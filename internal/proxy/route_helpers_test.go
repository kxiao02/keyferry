package proxy

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"keyferry/internal/perms"
)

func chmod700(path string) error { return os.Chmod(path, 0o700) }
func chmod600(path string) error { return os.Chmod(path, 0o600) }

func discardLog() *log.Logger { return log.New(io.Discard, "", 0) }

func indexBytes(b, sub []byte) int { return bytes.Index(b, sub) }

func init() {
	_ = perms.AssertOwnerOnly
}

// httptestServer starts a loopback TCP server for handler tests.
func startHTTP(h http.Handler) (*http.Server, string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	srv := &http.Server{Handler: h, ErrorLog: discardLog()}
	go srv.Serve(ln)
	return srv, "http://" + ln.Addr().String(), func() { srv.Close() }
}
