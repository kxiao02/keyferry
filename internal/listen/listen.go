// Package listen binds the relay's owner-only socket.
// TCP is accepted only on a loopback address and only when asked for.
package listen

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"keyferry/internal/perms"
)

// Listen binds spec, which is "unix:/abs/path" or "tcp:127.0.0.1:port".
// The returned cleanup removes a unix socket this call created.
func Listen(spec string) (net.Listener, func(), error) {
	network, addr, err := Parse(spec)
	if err != nil {
		return nil, nil, err
	}
	if network == "unix" {
		return listenUnix(addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	return ln, func() {}, nil
}

// Parse checks a listen spec without binding.
func Parse(spec string) (network, addr string, err error) {
	switch {
	case strings.HasPrefix(spec, "unix:"):
		network, addr = "unix", strings.TrimPrefix(spec, "unix:")
	case strings.HasPrefix(spec, "tcp:"):
		network, addr = "tcp", strings.TrimPrefix(spec, "tcp:")
	default:
		return "", "", errors.New("listen spec must start with unix: or tcp:")
	}
	if network == "unix" {
		if addr == "" || !filepath.IsAbs(addr) {
			return "", "", errors.New("unix listen path must be absolute")
		}
		return network, addr, nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", errors.New("tcp listen must be host:port")
	}
	if err := requireLoopback(host); err != nil {
		return "", "", err
	}
	return network, addr, nil
}

// DefaultSocket is $XDG_RUNTIME_DIR/keyferry/relay.sock, or a socket under the state dir.
func DefaultSocket(stateDir string) (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "keyferry", "relay.sock"), nil
	}
	if stateDir == "" {
		return "", errors.New("no XDG_RUNTIME_DIR and no state directory")
	}
	return filepath.Join(stateDir, "run", "relay.sock"), nil
}

// DefaultAdminSocket is the management UI socket, never the relay socket.
func DefaultAdminSocket(stateDir string) (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "keyferry", "admin.sock"), nil
	}
	if stateDir == "" {
		return "", errors.New("no XDG_RUNTIME_DIR and no state directory")
	}
	return filepath.Join(stateDir, "run", "admin.sock"), nil
}

func requireLoopback(host string) error {
	if host == "" {
		return errors.New("refusing wildcard listen")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("refusing non-loopback listen")
	}
	return nil
}

func listenUnix(path string) (net.Listener, func(), error) {
	dir := filepath.Dir(path)
	if err := perms.EnsureDir(dir); err != nil {
		return nil, nil, err
	}
	if err := clearStaleSocket(path); err != nil {
		return nil, nil, err
	}
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, nil, err
	}
	if err := perms.AssertSocket(path); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, nil, err
	}
	cleanup := func() {
		ln.Close()
		os.Remove(path)
	}
	return ln, cleanup, nil
}

func clearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("listen path exists and is not a socket")
	}
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return errors.New("already running")
	}
	if err := perms.AssertSocket(path); err != nil {
		return err
	}
	return os.Remove(path)
}
