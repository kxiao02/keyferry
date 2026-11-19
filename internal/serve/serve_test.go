package serve

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketPermissionChangeStopsServer(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	run := filepath.Join(root, "run")
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(run, "relay.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- Serve(ctx, Options{
			StateDir: state,
			Listen:   "unix:" + sock,
			UI:       "unix:" + filepath.Join(run, "admin.sock"),
			Alerts:   io.Discard,
			Recheck:  20 * time.Millisecond,
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("server kept running after the socket became group/world accessible")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
	if _, err := net.Dial("unix", sock); err == nil {
		t.Fatal("socket still accepts connections")
	}
}
