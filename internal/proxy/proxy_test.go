package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"keyferry/internal/store"
)

func TestProxySwapsKeyAndRequiresToken(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-from-env")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("http_proxy", "http://127.0.0.1:9")

	var saw sync.Mutex
	var gotAuth, gotBody, gotForward, gotCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		saw.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotBody = string(body)
		gotForward = r.Header.Get("X-Forwarded-For")
		gotCookie = r.Header.Get("Cookie")
		saw.Unlock()
		w.Header().Set("X-Api-Key", "sk-real-provider")
		w.Header().Set("X-Echo", "sk-real-provider")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: hello\n"))
	}))
	defer upstream.Close()

	st := newStore(t)
	if err := st.PutUpstream(store.Upstream{
		Name:     "main",
		Provider: store.ProviderOpenAI,
		BaseURL:  upstream.URL,
		Key:      "sk-real-provider",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.IssueToken("main", "desk", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	var verbose, alerts bytes.Buffer
	h := NewHandler(st, &verbose, &alerts, ModeTCP, "")
	relay := httptest.NewServer(h)
	defer relay.Close()

	req, err := http.NewRequest(http.MethodPost, relay.URL+"/v1/chat/completions", strings.NewReader(`{"prompt":"secret-prompt"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Cookie", "session=secret-cookie")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	respBody, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", res.StatusCode, respBody)
	}
	if strings.Contains(string(respBody), "sk-real-provider") || res.Header.Get("X-Api-Key") != "" || res.Header.Get("X-Echo") != "" {
		t.Fatalf("provider key reflected to client: body %q header %q", respBody, res.Header)
	}
	saw.Lock()
	defer saw.Unlock()
	if gotAuth != "Bearer sk-real-provider" {
		t.Fatalf("upstream auth %q", gotAuth)
	}
	if strings.Contains(gotAuth, raw) || gotBody != `{"prompt":"secret-prompt"}` {
		t.Fatalf("upstream saw token or wrong body: %q %q", gotAuth, gotBody)
	}
	if gotForward != "" || gotCookie != "" {
		t.Fatalf("forwarded client metadata: %q %q", gotForward, gotCookie)
	}
	logText := verbose.String() + alerts.String()
	for _, secret := range []string{raw, "sk-real-provider", "secret-prompt", "sk-from-env", "secret-cookie"} {
		if strings.Contains(logText, secret) {
			t.Fatalf("log contains %q: %s", secret, logText)
		}
	}

	bare, err := http.Post(relay.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"prompt":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	bare.Body.Close()
	if bare.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token status %d", bare.StatusCode)
	}

	q, err := http.NewRequest(http.MethodGet, relay.URL+"/v1/models?api_key="+raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	qres, err := http.DefaultClient.Do(q)
	if err != nil {
		t.Fatal(err)
	}
	qres.Body.Close()
	if qres.StatusCode != http.StatusBadRequest {
		t.Fatalf("query token status %d", qres.StatusCode)
	}
	if strings.Contains(verbose.String()+alerts.String(), raw) {
		t.Fatal("query token was logged")
	}
}

func TestAnthropicHeaderAndDownUpstream(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Api-Key")
		if r.Header.Get("Authorization") != "" {
			t.Errorf("relay token forwarded: %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	st := newStore(t)
	if err := st.PutUpstream(store.Upstream{Name: "ant", Provider: store.ProviderAnthropic, BaseURL: upstream.URL, Key: "ant-real"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "ant", Keys: []string{"ant"}}); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.IssueToken("ant", "", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(st, nil, io.Discard, ModeTCP, "")
	relay := httptest.NewServer(h)
	defer relay.Close()
	req, _ := http.NewRequest(http.MethodPost, relay.URL+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("X-Api-Key", raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got != "ant-real" {
		t.Fatalf("upstream key %q", got)
	}

	down := newStore(t)
	if err := down.PutUpstream(store.Upstream{Name: "main", Provider: store.ProviderOpenAI, BaseURL: "http://127.0.0.1:1", Key: "sk-real"}); err != nil {
		t.Fatal(err)
	}
	if err := down.PutGrant(store.Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	token, _, err := down.IssueToken("main", "", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	var alerts bytes.Buffer
	dh := NewHandler(down, nil, &alerts, ModeTCP, "")
	dsrv := httptest.NewServer(dh)
	defer dsrv.Close()
	dreq, _ := http.NewRequest(http.MethodGet, dsrv.URL+"/v1/models", nil)
	dreq.Header.Set("Authorization", "Bearer "+token)
	dres, err := http.DefaultClient.Do(dreq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(dres.Body)
	dres.Body.Close()
	if dres.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", dres.StatusCode)
	}
	if strings.Contains(string(body), "sk-real") || strings.Contains(alerts.String(), "sk-real") || strings.Contains(alerts.String(), token) {
		t.Fatalf("failure leaked secret: %q %s", body, alerts.String())
	}
}

func TestQuotaParallelAndStream(t *testing.T) {
	started := make(chan struct{})
	var startOnce sync.Once
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: one\n"))
		if fl != nil {
			fl.Flush()
		}
		startOnce.Do(func() { close(started) })
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("data: two\n"))
	}))
	defer upstream.Close()
	st := newStore(t)
	if err := st.PutUpstream(store.Upstream{Name: "main", Provider: store.ProviderGeneric, BaseURL: upstream.URL, AuthHeader: "X-Api-Key", Key: "sk-real"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.IssueToken("main", "", time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewServer(NewHandler(st, nil, io.Discard, ModeTCP, ""))
	defer relay.Close()

	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, relay.URL+"/v1/chat", strings.NewReader("body"))
			req.Header.Set("Authorization", "Bearer "+raw)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				codes[i] = 1
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			codes[i] = res.StatusCode
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, code := range codes {
		if code == http.StatusOK {
			ok++
		}
	}
	if ok != 1 || hits.Load() != 1 {
		t.Fatalf("successes %d hits %d codes %v", ok, hits.Load(), codes)
	}
	select {
	case <-started:
	default:
		t.Fatal("stream did not start")
	}
}

func TestProxyIgnoresAmbientProxy(t *testing.T) {
	var proxyHits atomic.Int32
	ambient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "proxy", http.StatusBadGateway)
	}))
	defer ambient.Close()
	t.Setenv("HTTP_PROXY", ambient.URL)
	t.Setenv("http_proxy", ambient.URL)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-real" {
			t.Errorf("auth %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	st := newStore(t)
	if err := st.PutUpstream(store.Upstream{Name: "main", Provider: store.ProviderOpenAI, BaseURL: upstream.URL, Key: "sk-real"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.IssueToken("main", "", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewServer(NewHandler(st, nil, io.Discard, ModeTCP, ""))
	defer relay.Close()
	req, _ := http.NewRequest(http.MethodGet, relay.URL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent || proxyHits.Load() != 0 {
		t.Fatalf("status %d proxy hits %d", res.StatusCode, proxyHits.Load())
	}
}

func TestSafeTransportIgnoresProxyEnv(t *testing.T) {
	var hits atomic.Int32
	ambient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer ambient.Close()
	t.Setenv("HTTP_PROXY", ambient.URL)
	t.Setenv("http_proxy", ambient.URL)
	client := &http.Client{Transport: safeTransport(), Timeout: 300 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, "http://203.0.113.5/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected the direct dial to fail")
	}
	if hits.Load() != 0 {
		t.Fatal("HTTP_PROXY received the request")
	}
}

func TestResponseStartsBeforeUpstreamFinishes(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
		_, _ = io.WriteString(w, "data: two\n")
	}))
	defer upstream.Close()
	st := newStore(t)
	if err := st.PutUpstream(store.Upstream{Name: "main", Provider: store.ProviderOpenAI, BaseURL: upstream.URL, Key: "sk-real"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(store.Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.IssueToken("main", "", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewServer(NewHandler(st, nil, io.Discard, ModeTCP, ""))
	defer relay.Close()
	req, _ := http.NewRequest(http.MethodPost, relay.URL+"/v1/chat", strings.NewReader("hi"))
	req.Header.Set("Authorization", "Bearer "+raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, len("data: one\n"))
		_, err := io.ReadFull(res.Body, buf)
		if err != nil {
			got <- err.Error()
			return
		}
		got <- string(buf)
	}()
	select {
	case s := <-got:
		if s != "data: one\n" {
			t.Fatal(s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response was buffered until the upstream finished")
	}
	close(release)
	_, _ = io.Copy(io.Discard, res.Body)
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	t.Setenv("KEYFERRY_STATE_DIR", "")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestDialUnixNotRequired(t *testing.T) {
	// The handler must fail closed when the upstream dial fails, including when
	// the only key material in the environment is a provider key.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	st := newStore(t)
	if err := st.PutUpstream(store.Upstream{Name: "main", Provider: store.ProviderOpenAI, BaseURL: "http://" + addr, Key: "sk-real"}); err != nil {
		t.Fatal(err)
	}
	os.Setenv("OPENAI_API_KEY", "sk-real")
	t.Cleanup(func() { os.Unsetenv("OPENAI_API_KEY") })
	if err := st.PutGrant(store.Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.IssueToken("main", "", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewServer(NewHandler(st, nil, io.Discard, ModeTCP, ""))
	defer relay.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, relay.URL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", res.StatusCode)
	}
}
