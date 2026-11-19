package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpstreamAddKeepsKeyOffArgvAndOutput(t *testing.T) {
	if os.Getenv("KEYFERRY_ARGV_HELPER") == "1" {
		raw, err := os.ReadFile("/proc/self/cmdline")
		if err != nil {
			os.Exit(4)
		}
		if bytes.Contains(raw, []byte("sk-canary-secret")) {
			os.Stderr.WriteString("cmdline leaked\n")
			os.Exit(3)
		}
		os.Exit(Run(argsAfterDash(os.Args), os.Stdin, os.Stdout, os.Stderr))
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestUpstreamAddKeepsKeyOffArgvAndOutput$", "--",
		"upstream", "add", "main", "--provider", "openai", "--state-dir", dir)
	cmd.Env = append(os.Environ(), "KEYFERRY_ARGV_HELPER=1")
	cmd.Stdin = strings.NewReader("sk-canary-secret\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v\nstderr %s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), "sk-canary-secret") || strings.Contains(stderr.String(), "sk-canary-secret") {
		t.Fatalf("key leaked to output\nstdout %s\nstderr %s", stdout.String(), stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(dir, "upstreams", "main.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("sk-canary-secret")) {
		t.Fatal("key was not stored")
	}
	fi, err := os.Lstat(filepath.Join(dir, "upstreams", "main.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}

func TestTokenIssueListRevoke(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := Run([]string{"upstream", "add", "main", "--provider", "anthropic", "--state-dir", dir}, strings.NewReader("ant-real-key\n"), io.Discard, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if code := Run([]string{"grant", "add", "main", "--bind", "main", "--state-dir", dir}, nil, io.Discard, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	var stdout bytes.Buffer
	stderr.Reset()
	if code := Run([]string{"token", "issue", "--upstream", "main", "--ttl", "1h", "--quota", "3", "--label", "desk", "--state-dir", dir}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	text := stdout.String()
	if strings.Contains(text, "ant-real-key") || strings.Contains(stderr.String(), "ant-real-key") {
		t.Fatal("provider key leaked")
	}
	if strings.Contains(stderr.String(), "token=") || strings.Contains(stderr.String(), "kf_") {
		t.Fatal("token leaked to stderr")
	}
	id := field(t, text, "id")
	token := field(t, text, "token")
	if !strings.HasPrefix(token, "kf_") {
		t.Fatal(token)
	}
	stdout.Reset()
	if code := Run([]string{"token", "list", "--state-dir", dir}, nil, &stdout, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if strings.Contains(stdout.String(), token) || strings.Contains(stdout.String(), "ant-real-key") {
		t.Fatal("list leaked a secret")
	}
	if !strings.Contains(stdout.String(), id) {
		t.Fatal(stdout.String())
	}
	stdout.Reset()
	if code := Run([]string{"token", "revoke", id, "--state-dir", dir}, nil, &stdout, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if code := Run([]string{"serve", "--listen", "tcp:0.0.0.0:9", "--state-dir", dir}, nil, io.Discard, &stderr); code == 0 {
		t.Fatal("wildcard listen was accepted")
	}
	if code := Run([]string{"serve", "--listen", "tcp:203.0.113.5:9", "--state-dir", dir}, nil, io.Discard, io.Discard); code == 0 {
		t.Fatal("public listen was accepted")
	}
}

func TestTokenOutFileMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"upstream", "add", "main", "--provider", "openai", "--state-dir", dir}, strings.NewReader("sk-real\n"), io.Discard, io.Discard); code != 0 {
		t.Fatal("add")
	}
	if code := Run([]string{"grant", "add", "main", "--bind", "main", "--state-dir", dir}, nil, io.Discard, io.Discard); code != 0 {
		t.Fatal("grant")
	}
	out := filepath.Join(dir, "token")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"token", "issue", "--upstream", "main", "--out", out, "--state-dir", dir}, nil, &stdout, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if strings.Contains(stdout.String(), "kf_") || strings.Contains(stderr.String(), "sk-real") {
		t.Fatalf("secret in output %s %s", stdout.String(), stderr.String())
	}
	fi, err := os.Lstat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	body, err := os.ReadFile(out)
	if err != nil || !bytes.HasPrefix(body, []byte("kf_")) {
		t.Fatalf("file %q err %v", body, err)
	}
}

func TestLooseStateRefused(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "loose")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := Run([]string{"upstream", "add", "main", "--provider", "openai", "--state-dir", dir}, strings.NewReader("sk-real\n"), io.Discard, &stderr)
	if code == 0 {
		t.Fatal("loose state accepted")
	}
	if strings.Contains(stderr.String(), "sk-real") {
		t.Fatal("key in error")
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		t.Fatal("directory was chmod'd")
	}
}

func TestHelp(t *testing.T) {
	var stdout bytes.Buffer
	if code := Run([]string{"help"}, nil, &stdout, io.Discard); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(stdout.String(), "token issue") || !strings.Contains(stdout.String(), "unix:") {
		t.Fatal(stdout.String())
	}
}

func field(t *testing.T, text, name string) string {
	t.Helper()
	prefix := name + "="
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("missing %s in %s", name, text)
	return ""
}

func argsAfterDash(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	return nil
}
