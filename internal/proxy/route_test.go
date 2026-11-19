package proxy

import (
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"keyferry/internal/admin"
	"keyferry/internal/store"
)

func TestRoutesStayParallelAndFailClosed(t *testing.T) {
	var started atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	newUp := func(marker string) *http.Server {
		return &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if started.Add(1) == 2 {
				once.Do(func() { close(release) })
			}
			select {
			case <-release:
			case <-time.After(2 * time.Second):
				t.Errorf("requests were serialized")
			}
			w.Header().Set("X-Marker", marker)
			_, _ = io.WriteString(w, marker)
		})}
	}
	aLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go newUp("alpha").Serve(aLn)
	go newUp("beta").Serve(bLn)
	defer aLn.Close()
	defer bLn.Close()

	st := newStore(t)
	if err := st.PutUpstream(store.Upstream{Name: "alpha", Provider: store.ProviderOpenAI, BaseURL: "http://" + aLn.Addr().String(), Key: "sk-alpha-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutUpstream(store.Upstream{Name: "beta", Provider: store.ProviderOpenAI, BaseURL: "http://" + bLn.Addr().String(), Key: "sk-beta-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "work", Keys: []string{"beta"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "side", Keys: []string{"alpha"}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := chmod700(dir); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "relay.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := chmod600(sock); err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	relay := &http.Server{Handler: NewHandler(st, io.Discard, io.Discard, ModeUnix, ""), ErrorLog: discardLog()}
	go relay.Serve(ln)
	defer relay.Close()

	client := unixClient(sock)
	var wg sync.WaitGroup
	got := make([]string, 2)
	paths := []string{"/g/work/v1/chat", "/g/side/v1/chat"}
	for i, path := range paths {
		wg.Add(1)
		go func(i int, path string) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, "http://relay"+path, nil)
			req.Header.Set("Authorization", "Bearer "+store.PlaceholderKey)
			res, err := client.Do(req)
			if err != nil {
				got[i] = err.Error()
				return
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			got[i] = string(body)
		}(i, path)
	}
	wg.Wait()
	if got[0] != "beta" || got[1] != "alpha" || started.Load() < 2 {
		t.Fatalf("parallel routes got %q started %d", got, started.Load())
	}

	if err := st.SetKeyEnabled("beta", false); err != nil {
		t.Fatal(err)
	}
	if code := doUnixCode(t, client, "/g/work/v1/x"); code != http.StatusForbidden {
		t.Fatalf("disabled key status %d", code)
	}
	if err := st.SetKeyEnabled("beta", true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetGrantEnabled("work", false); err != nil {
		t.Fatal(err)
	}
	if code := doUnixCode(t, client, "/g/work/v1/x"); code != http.StatusForbidden {
		t.Fatalf("disabled grant status %d", code)
	}
	if err := st.DeleteGrant("side"); err != nil {
		t.Fatal(err)
	}
	if code := doUnixCode(t, client, "/g/side/v1/x"); code != http.StatusBadGateway && code != http.StatusForbidden {
		t.Fatalf("deleted grant status %d", code)
	}

	// TCP rejects the placeholder.
	tcp, tcpURL, stopTCP := startHTTP(NewHandler(st, io.Discard, io.Discard, ModeTCP, ""))
	defer stopTCP()
	_ = tcp
	req, _ := http.NewRequest(http.MethodGet, tcpURL+"/g/work/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+store.PlaceholderKey)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("placeholder on tcp %d", res.StatusCode)
	}

	// Admin routes on the relay socket do not toggle keys.
	before, err := st.GetUpstream("alpha")
	if err != nil {
		t.Fatal(err)
	}
	toggle, _ := http.NewRequest(http.MethodPost, "http://relay/keys/toggle", nil)
	toggle.Header.Set("Authorization", "Bearer "+store.PlaceholderKey)
	tres, err := client.Do(toggle)
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := io.ReadAll(tres.Body)
	tres.Body.Close()
	if tres.StatusCode == http.StatusOK || string(tb) == "saved" {
		t.Fatal("relay socket served admin")
	}
	after, err := st.GetUpstream("alpha")
	if err != nil || after.IsEnabled() != before.IsEnabled() {
		t.Fatal("relay toggle changed a key", err)
	}
	page, _ := http.NewRequest(http.MethodGet, "http://relay/", nil)
	page.Header.Set("Authorization", "Bearer "+store.PlaceholderKey)
	pres, err := client.Do(page)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := io.ReadAll(pres.Body)
	pres.Body.Close()
	if stringContains(pb, "Add key") || stringContains(pb, "sk-alpha-secret") {
		t.Fatal("relay returned the admin page or a key")
	}
}

func TestFixedGrantSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-beta-secret" {
			t.Errorf("auth leaked or wrong")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	st := newStore(t)
	if err := st.PutUpstream(store.Upstream{Name: "beta", Provider: store.ProviderOpenAI, BaseURL: "http://" + ln.Addr().String(), Key: "sk-beta-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutUpstream(store.Upstream{Name: "alpha", Provider: store.ProviderOpenAI, BaseURL: "http://127.0.0.1:1", Key: "sk-alpha-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "work", Keys: []string{"beta"}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := chmod700(dir); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "work.sock")
	uln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := chmod600(sock); err != nil {
		t.Fatal(err)
	}
	defer uln.Close()
	srv := &http.Server{Handler: NewHandler(st, io.Discard, io.Discard, ModeUnix, "work"), ErrorLog: discardLog()}
	go srv.Serve(uln)
	defer srv.Close()
	res := doUnixRes(t, unixClient(sock), "/v1/models")
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", res.StatusCode)
	}
	// A different grant on this socket is rejected.
	if code := doUnixCode(t, unixClient(sock), "/g/other/v1/models"); code != http.StatusBadRequest {
		t.Fatalf("cross grant %d", code)
	}
}

func TestAdminHidesKeys(t *testing.T) {
	st := newStore(t)
	secret := "sk-admin-should-not-echo"
	if err := st.PutUpstream(store.Upstream{Name: "main", Provider: store.ProviderOpenAI, Key: secret}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "desk", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	h := admin.New(st)
	_, adminURL, stop := startHTTP(h)
	defer stop()
	res, err := http.Get(adminURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if stringContains(body, secret) {
		t.Fatal("admin page contains the full key")
	}
	if !stringContains(body, "Bind") || !stringContains(body, "desk") {
		t.Fatal("admin page missing binding controls")
	}
	// List info has no key.
	info, err := st.ListUpstreams()
	if err != nil || len(info) != 1 || info[0].Last4 == "" && len(secret) >= 12 {
		t.Fatal(info, err)
	}
	fp := info[0].KeyFP
	if !stringContains(body, fp) {
		t.Fatal("fingerprint missing")
	}
}

func doUnix(t *testing.T, client *http.Client, path string) string {
	t.Helper()
	res := doUnixRes(t, client, path)
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s -> %d %s", path, res.StatusCode, b)
	}
	return string(b)
}

func doUnixCode(t *testing.T, client *http.Client, path string) int {
	t.Helper()
	res := doUnixRes(t, client, path)
	res.Body.Close()
	return res.StatusCode
}

func doUnixRes(t *testing.T, client *http.Client, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://relay"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+store.PlaceholderKey)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func unixClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Dial: func(_, _ string) (net.Conn, error) {
			return net.Dial("unix", sock)
		},
	}}
}

func stringContains(b []byte, s string) bool {
	return len(s) > 0 && (len(b) >= len(s)) && (func() bool {
		return bytesIndex(b, []byte(s)) >= 0
	})()
}

func bytesIndex(b, sub []byte) int {
	return indexBytes(b, sub)
}
