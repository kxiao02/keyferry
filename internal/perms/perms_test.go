package perms

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndReadOwnerFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret")
	if err := WriteOwnerFile(path, []byte("value")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	got, err := ReadOwnerFile(path, 32)
	if err != nil || string(got) != "value" {
		t.Fatalf("read %q err=%v", got, err)
	}
}

func TestRejectsSymlinkAndHardlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret")
	if err := WriteOwnerFile(path, []byte("value")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwnerFile(link, 32); err == nil {
		t.Fatal("symlink was followed")
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwnerFile(path, 32); err == nil {
		t.Fatal("hardlink was accepted")
	}
}

func TestLooseDirectoryIsNotChmodded(t *testing.T) {
	parent := t.TempDir()
	loose := filepath.Join(parent, "loose")
	if err := os.Mkdir(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	err := EnsureDir(loose)
	if err == nil {
		t.Fatal("loose directory was accepted")
	}
	fi, err := os.Lstat(loose)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		t.Fatal("EnsureDir tightened a directory it does not own exclusively")
	}
}
