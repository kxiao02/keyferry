package store

import (
	"os"
	"sync"
	"syscall"

	"keyferry/internal/perms"
)

// gates serializes goroutines in this process. flock covers other processes.
// flock is not a thread mutex: a second descriptor in the same process can deadlock.
var (
	gatesMu sync.Mutex
	gates   = map[string]*sync.Mutex{}
)

func (s *Store) withLock(dir string, fn func() error) error {
	if err := perms.EnsureDir(dir); err != nil {
		return err
	}
	path := dir + "/.lock"
	g := gateFor(path)
	g.Lock()
	defer g.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	if err := perms.AssertOwnerOnly(path, false); err != nil {
		return err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func gateFor(path string) *sync.Mutex {
	gatesMu.Lock()
	defer gatesMu.Unlock()
	g, ok := gates[path]
	if !ok {
		g = &sync.Mutex{}
		gates[path] = g
	}
	return g
}
