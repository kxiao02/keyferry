// Package expose is the optional short-lived helper for HTTP clients.
// It proxies loopback TCP to a unix socket and stores no keys.
package expose

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"keyferry/internal/listen"
	"keyferry/internal/perms"
)

// Run listens on a loopback TCP address and splices each connection to unixPath.
// It writes one URL line to stdout. When ctx is cancelled the listener closes.
// Nothing is written to disk.
func Run(ctx context.Context, unixPath, tcpAddr string, stdout io.Writer) error {
	if err := perms.AssertSocket(unixPath); err != nil {
		return err
	}
	if tcpAddr == "" {
		tcpAddr = "127.0.0.1:0"
	}
	ln, _, err := listen.Listen("tcp:" + tcpAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	if _, err := fmt.Fprintf(stdout, "http://%s\n", ln.Addr().String()); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			remote, err := net.DialTimeout("unix", unixPath, 5*time.Second)
			if err != nil {
				return
			}
			splice(conn, remote)
		}()
	}
}

func splice(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}
