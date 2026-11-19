package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIssueAndAuthorize(t *testing.T) {
	st := openTest(t)
	if err := st.PutUpstream(Upstream{Name: "main", Provider: ProviderOpenAI, Key: "sk-real"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	raw, rec, err := st.IssueToken("main", "laptop", time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "sk-real") || !strings.HasPrefix(raw, "kf_") {
		t.Fatalf("unexpected token shape")
	}
	got, up, err := st.Authorize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != rec.ID || up.Key != "sk-real" || up.BaseURL != "https://api.openai.com" {
		t.Fatalf("got %+v base %s", got, up.BaseURL)
	}
	if _, _, err := st.Authorize("kf_nope"); err != ErrUnauthorized {
		t.Fatalf("bad token err %v", err)
	}
	if err := st.Revoke(rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Authorize(raw); err != ErrRevoked {
		t.Fatalf("revoke err %v", err)
	}
	list, err := st.ListUpstreams()
	if err != nil || len(list) != 1 || list[0].KeyFP == "" {
		t.Fatal(list, err)
	}
	entries, err := os.ReadDir(filepath.Join(st.Dir, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		b := mustRead(t, filepath.Join(st.Dir, "tokens", e.Name()))
		if strings.Contains(string(b), raw) || strings.Contains(string(b), "sk-real") {
			t.Fatal("token file contains a secret")
		}
		fi, err := os.Lstat(filepath.Join(st.Dir, "tokens", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("token mode %o", fi.Mode().Perm())
		}
	}
}

func TestQuotaExpiryAndCleartext(t *testing.T) {
	st := openTest(t)
	if err := st.PutUpstream(Upstream{Name: "main", Provider: ProviderOpenAI, BaseURL: "http://example.com", Key: "sk-real"}); err == nil {
		t.Fatal("accepted cleartext public upstream")
	}
	if err := st.PutUpstream(Upstream{Name: "main", Provider: ProviderOpenAI, BaseURL: "http://127.0.0.1:9", Key: "sk-real"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.IssueToken("main", "", time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Authorize(raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Authorize(raw); err != ErrQuota {
		t.Fatalf("quota err %v", err)
	}
	fresh, frec, err := st.IssueToken("main", "", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := findTokenFile(t, st, frec.ID)
	rewriteExpiry(t, file, time.Now().Add(-time.Hour).UTC())
	if _, _, err := st.Authorize(fresh); err != ErrExpired {
		t.Fatalf("expiry err %v", err)
	}
}

func TestLooseStateAndEnvIgnored(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-from-env")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-env")
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("opened a group-accessible state dir")
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		t.Fatal("Open chmod'd the loose directory")
	}
}

func TestTTLCap(t *testing.T) {
	st := openTest(t)
	if err := st.PutUpstream(Upstream{Name: "main", Provider: ProviderAnthropic, Key: "ant-real"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGrant(Grant{Name: "main", Keys: []string{"main"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.IssueToken("main", "", 200*time.Hour, 0); err == nil {
		t.Fatal("long ttl accepted")
	}
}

func openTest(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func rewriteExpiry(t *testing.T, path string, when time.Time) {
	t.Helper()
	var rec Token
	if err := json.Unmarshal(mustRead(t, path), &rec); err != nil {
		t.Fatal(err)
	}
	rec.Expires = when.UTC()
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findTokenFile(t *testing.T, st *Store, id string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(st.Dir, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		body := string(mustRead(t, filepath.Join(st.Dir, "tokens", e.Name())))
		if strings.Contains(body, id) {
			return filepath.Join(st.Dir, "tokens", e.Name())
		}
	}
	t.Fatal("token file not found")
	return ""
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
