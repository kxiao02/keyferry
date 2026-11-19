package expose

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestExposeRoundTripAndExit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := chmodSocket(path); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := &safeBuf{}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, path, "127.0.0.1:0", stdout)
	}()
	var line string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		text := stdout.String()
		if text != "" {
			line = text
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if line == "" {
		t.Fatal("no url printed", done)
	}
	addr := line[len("http://"):]
	addr = addr[:len(addr)-1]
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q err %v", buf, err)
	}
	conn.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expose did not exit")
	}
	if _, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		t.Fatal("tcp listener still open")
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expose left files: %v", entries)
	}
}

func TestExposeRefusesLooseSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := chmodSocket(path); err != nil {
		t.Fatal(err)
	}
	if err := chmodLoose(path); err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), path, "127.0.0.1:0", io.Discard)
	if err == nil {
		t.Fatal("accepted a group-accessible socket")
	}
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func chmodSocket(path string) error {
	return os.Chmod(path, 0o600)
}

func chmodLoose(path string) error {
	return os.Chmod(path, 0o666)
}
