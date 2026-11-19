// Package perms checks that secrets and sockets stay owner-only.
// A symlink or a hard link is refused: the other name is not covered by the check.
package perms

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// AssertOwnerOnly rejects symlinks, wrong ownership, and any group or world bit.
// wantDir selects a directory; otherwise the inode must be a regular file.
func AssertOwnerOnly(path string, wantDir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return assertInfo(path, fi, wantDir, false)
}

// AssertSocket rejects a unix socket that is not owner-only.
func AssertSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink: %s", path)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("not a socket: %s", path)
	}
	uid, err := uidOf(fi)
	if err != nil {
		return err
	}
	if uid != uint32(os.Getuid()) {
		return fmt.Errorf("not owned by current user: %s", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("group or world accessible: %s", path)
	}
	return nil
}

// EnsureDir creates missing directories as mode 0700 and checks path.
// An existing directory is left untouched. A loose mode is an error,
// so a shared directory such as /tmp is never chmod'd.
func EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return AssertOwnerOnly(path, true)
}

// WalkOwnerOnly visits root and everything under it.
// Symlinks, hard-linked files, and loose modes fail the walk.
func WalkOwnerOnly(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		wantDir := info.IsDir()
		return assertInfo(path, info, wantDir, true)
	})
}

// ReadOwnerFile reads a regular file without following links.
func ReadOwnerFile(path string, max int64) ([]byte, error) {
	if err := AssertOwnerOnly(path, false); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := assertInfo(path, fi, false, false); err != nil {
		return nil, err
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("file too large: %s", path)
	}
	buf, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > max {
		return nil, fmt.Errorf("file too large: %s", path)
	}
	return buf, nil
}

// WriteOwnerFile atomically replaces path with data, mode 0600.
// The parent directory must already be owner-only.
func WriteOwnerFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := AssertOwnerOnly(dir, true); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if err := AssertOwnerOnly(path, false); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func assertInfo(path string, fi os.FileInfo, wantDir bool, allowSocket bool) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink: %s", path)
	}
	if wantDir {
		if !fi.IsDir() {
			return fmt.Errorf("not a directory: %s", path)
		}
	} else if allowSocket && fi.Mode()&os.ModeSocket != 0 {
		// sockets under the runtime dir are not secret files
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}
	uid, err := uidOf(fi)
	if err != nil {
		return err
	}
	if uid != uint32(os.Getuid()) {
		return fmt.Errorf("not owned by current user: %s", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("group or world accessible: %s", path)
	}
	if !wantDir && fi.Mode().IsRegular() {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("unsupported file stat: %s", path)
		}
		if st.Nlink > 1 {
			return fmt.Errorf("refusing hardlinked file: %s", path)
		}
	}
	return nil
}

func uidOf(fi os.FileInfo) (uint32, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unsupported file stat")
	}
	return st.Uid, nil
}
