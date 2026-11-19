package listen

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"keyferry/internal/perms"
)

func TestParseRejectsWildcardAndPublic(t *testing.T) {
	for _, spec := range []string{"tcp::80", "tcp:0.0.0.0:80", "tcp:1.2.3.4:80", "tcp:example.test:80", "socket"} {
		if _, _, err := Parse(spec); err == nil {
			t.Fatalf("accepted %s", spec)
		}
	}
	if _, _, err := Parse("tcp:127.0.0.1:80"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Parse("tcp:[::1]:80"); err != nil {
		t.Fatal(err)
	}
}

func TestUnixSocketMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "relay.sock")
	ln, cleanup, err := Listen("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := perms.AssertSocket(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	_ = ln
}

func TestRefuseLooseSocketDir(t *testing.T) {
	parent := t.TempDir()
	loose := filepath.Join(parent, "loose")
	if err := os.Mkdir(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	_, _, err := Listen("unix:" + filepath.Join(loose, "relay.sock"))
	if err == nil {
		t.Fatal("listened in a group/world accessible directory")
	}
	fi, statErr := os.Lstat(loose)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		t.Fatal("listen tightened the directory")
	}
	if _, statErr := os.Lstat(filepath.Join(loose, "relay.sock")); !os.IsNotExist(statErr) {
		t.Fatal("socket was created after a refused listen")
	}
}
