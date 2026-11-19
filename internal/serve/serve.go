// Package serve runs the foreground relay on the personal server.
package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"keyferry/internal/admin"
	"keyferry/internal/listen"
	"keyferry/internal/perms"
	"keyferry/internal/proxy"
	"keyferry/internal/store"
)

// Options configures one foreground server process.
type Options struct {
	StateDir string
	Listen   string
	// UI is empty for the default admin socket, "off" to skip it, or a listen spec.
	UI      string
	Verbose io.Writer
	Alerts  io.Writer
	Recheck time.Duration
}

type endpoint struct {
	ln      net.Listener
	cleanup func()
	path    string
	srv     *http.Server
	label   string
	spec    string
}

// Serve listens until ctx is cancelled. A socket that becomes group or world
// accessible stops the process instead of continuing.
// One process serves every grant. Requests are not serialized.
func Serve(ctx context.Context, opt Options) error {
	if opt.Alerts == nil {
		opt.Alerts = io.Discard
	}
	st, err := store.Open(opt.StateDir)
	if err != nil {
		return err
	}
	spec := opt.Listen
	if spec == "" {
		path, err := listen.DefaultSocket(opt.StateDir)
		if err != nil {
			return err
		}
		spec = "unix:" + path
	}
	mode := proxy.ModeUnix
	if network, _, err := listen.Parse(spec); err != nil {
		return err
	} else if network == "tcp" {
		mode = proxy.ModeTCP
	}

	var eps []endpoint
	closeAll := func() {
		for _, ep := range eps {
			if ep.srv != nil {
				_ = ep.srv.Close()
			}
			if ep.cleanup != nil {
				ep.cleanup()
			}
		}
	}
	add := func(label, listenSpec string, h http.Handler) error {
		ln, cleanup, err := listen.Listen(listenSpec)
		if err != nil {
			return err
		}
		ep := endpoint{
			ln: ln, cleanup: cleanup, label: label, spec: listenSpec,
			srv: &http.Server{
				Handler:           h,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       5 * time.Minute,
				MaxHeaderBytes:    1 << 20,
				ErrorLog:          log.New(io.Discard, "", 0),
			},
		}
		if path, ok := unixPath(listenSpec); ok {
			ep.path = path
		}
		eps = append(eps, ep)
		fmt.Fprintf(opt.Alerts, "keyferry: %s %s\n", label, describe(ln, listenSpec))
		return nil
	}

	if err := add("relay", spec, proxy.NewHandler(st, opt.Verbose, opt.Alerts, mode, "")); err != nil {
		closeAll()
		return err
	}
	uiSpec, err := adminSpec(opt)
	if err != nil {
		closeAll()
		return err
	}
	if uiSpec != "" {
		if sameSocket(spec, uiSpec) {
			closeAll()
			return errors.New("admin socket must not be the relay socket")
		}
		if err := add("ui", uiSpec, admin.New(st)); err != nil {
			closeAll()
			return err
		}
	}
	grants, err := st.ListGrants()
	if err != nil {
		closeAll()
		return err
	}
	used := map[string]bool{}
	for _, ep := range eps {
		if ep.path != "" {
			used[ep.path] = true
		}
	}
	for _, g := range grants {
		if g.Socket == "" {
			continue
		}
		if used[g.Socket] {
			closeAll()
			return fmt.Errorf("grant %s socket is already in use", g.Name)
		}
		used[g.Socket] = true
		h := proxy.NewHandler(st, opt.Verbose, opt.Alerts, proxy.ModeUnix, g.Name)
		if err := add("grant "+g.Name, "unix:"+g.Socket, h); err != nil {
			closeAll()
			return err
		}
	}

	serveErr := make(chan error, len(eps))
	for i := range eps {
		ep := &eps[i]
		go func(ep *endpoint) {
			err := ep.srv.Serve(ep.ln)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			serveErr <- err
		}(ep)
	}

	var paths []string
	for _, ep := range eps {
		if ep.path != "" {
			paths = append(paths, ep.path)
		}
	}
	permErr := make(chan error, 1)
	if len(paths) > 0 {
		every := opt.Recheck
		if every <= 0 {
			every = 2 * time.Second
		}
		go watchSockets(ctx, paths, every, permErr)
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-permErr:
		fmt.Fprintf(opt.Alerts, "keyferry: %s\n", err.Error())
		runErr = err
	case err := <-serveErr:
		runErr = err
	}
	for i := range eps {
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = eps[i].srv.Shutdown(shut)
		cancel()
		eps[i].cleanup()
	}
	return runErr
}

func adminSpec(opt Options) (string, error) {
	switch opt.UI {
	case "off":
		return "", nil
	case "":
		path, err := listen.DefaultAdminSocket(opt.StateDir)
		if err != nil {
			return "", err
		}
		return "unix:" + path, nil
	default:
		return opt.UI, nil
	}
}

func sameSocket(a, b string) bool {
	na, aa, ea := listen.Parse(a)
	nb, ab, eb := listen.Parse(b)
	return ea == nil && eb == nil && na == "unix" && nb == "unix" && aa == ab
}

func watchSockets(ctx context.Context, paths []string, every time.Duration, permErr chan<- error) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, path := range paths {
				if err := perms.AssertSocket(path); err != nil {
					select {
					case permErr <- err:
					default:
					}
					return
				}
			}
		}
	}
}

func unixPath(spec string) (string, bool) {
	network, addr, err := listen.Parse(spec)
	if err != nil || network != "unix" {
		return "", false
	}
	return addr, true
}

func describe(ln net.Listener, spec string) string {
	if network, _, err := listen.Parse(spec); err == nil && network == "tcp" {
		return "tcp:" + ln.Addr().String()
	}
	return spec
}
