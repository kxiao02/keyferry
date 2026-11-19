// Package proxy forwards authorized requests to one configured upstream.
// Provider keys and relay tokens are not written to logs or to the client.
package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"keyferry/internal/store"
)

// Mode is how the listener authenticated the connection.
type Mode int

const (
	// ModeUnix accepts the placeholder api key. The socket is the authenticator.
	ModeUnix Mode = iota
	// ModeTCP requires a relay token. The placeholder is rejected.
	ModeTCP
)

// Handler is an HTTP reverse proxy. It does not serialize requests.
type Handler struct {
	Store      *store.Store
	Verbose    io.Writer
	Alerts     io.Writer
	Mode       Mode
	FixedGrant string
	upstream   http.RoundTripper
}

// NewHandler builds a handler whose transport ignores HTTP_PROXY.
// fixedGrant is set when the listener is a grant's own Unix socket.
func NewHandler(st *store.Store, verbose, alerts io.Writer, mode Mode, fixedGrant string) *Handler {
	return &Handler{
		Store:      st,
		Verbose:    verbose,
		Alerts:     alerts,
		Mode:       mode,
		FixedGrant: fixedGrant,
		upstream:   safeTransport(),
	}
}

func safeTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// ServeHTTP authenticates, then proxies. It never reads a provider key from the environment.
// Each call builds its own reverse proxy and does not wait on other requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rejectedQuery(r) {
		h.debug("auth=rejected-query")
		writeStatus(w, http.StatusBadRequest, "rejected")
		return
	}
	asked, path, err := grantFromRequest(r)
	if err != nil {
		writeStatus(w, http.StatusBadRequest, "grant")
		return
	}
	grantName, mismatch := chooseGrant(h.FixedGrant, asked)
	if mismatch {
		writeStatus(w, http.StatusBadRequest, "grant")
		return
	}
	req := r.Clone(r.Context())
	req.URL.Path = path
	req.URL.RawPath = ""
	req.Header.Del("X-Keyferry-Grant")

	token, ok := presentedToken(r)
	if !ok {
		h.debug("auth=nomatch")
		writeStatus(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if token == store.PlaceholderKey {
		if h.Mode != ModeUnix {
			h.debug("auth=placeholder-rejected")
			writeStatus(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		g, up, err := h.Store.ResolveGrant(grantName)
		if err != nil {
			h.grantError(grantName, err)
			writeGrantErr(w, err)
			return
		}
		h.forward(w, req, "-", g.Name, up)
		return
	}
	rec, up, err := h.Store.Authorize(token)
	if err != nil {
		h.authError(rec, err)
		writeGrantErr(w, err)
		return
	}
	if grantName != "" && grantName != rec.GrantName() {
		writeStatus(w, http.StatusBadRequest, "grant")
		return
	}
	h.forward(w, req, rec.ID, rec.GrantName(), up)
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, id, grant string, up store.Upstream) {
	switch up.Provider {
	case store.ProviderOpenAI, store.ProviderAnthropic, store.ProviderGeneric:
	default:
		h.alert("upstream=unavailable grant=%s", grant)
		writeStatus(w, http.StatusBadGateway, "unavailable")
		return
	}
	target, err := url.Parse(up.BaseURL)
	if err != nil {
		h.alert("upstream=unavailable grant=%s", grant)
		writeStatus(w, http.StatusBadGateway, "unavailable")
		return
	}
	if id == "" {
		id = "-"
	}
	h.debug("auth=ok id=%s grant=%s key=%s", id, grant, up.Name)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = r.URL.Path
			pr.Out.URL.RawPath = ""
			stripSensitive(pr.Out.Header)
			applyAuth(pr.Out.Header, up)
		},
		Transport:     h.upstream,
		FlushInterval: -1,
		ModifyResponse: func(res *http.Response) error {
			scrubResponse(res, up.Key)
			return nil
		},
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			h.debug("upstream=unavailable id=%s grant=%s key=%s", id, grant, up.Name)
			writeStatus(w, http.StatusBadGateway, "unavailable")
		},
	}
	rp.ServeHTTP(w, r)
}

func writeGrantErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrQuota):
		writeStatus(w, http.StatusTooManyRequests, "quota")
	case errors.Is(err, store.ErrUnauthorized), errors.Is(err, store.ErrRevoked), errors.Is(err, store.ErrExpired):
		writeStatus(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, store.ErrDisabled):
		writeStatus(w, http.StatusForbidden, "disabled")
	case errors.Is(err, store.ErrGrantRequired):
		writeStatus(w, http.StatusBadRequest, "grant")
	default:
		writeStatus(w, http.StatusBadGateway, "unavailable")
	}
}

func (h *Handler) grantError(grant string, err error) {
	switch {
	case errors.Is(err, store.ErrDisabled):
		h.debug("auth=disabled grant=%s", grant)
	case errors.Is(err, store.ErrGrantRequired):
		h.debug("auth=grant-required")
	default:
		h.debug("auth=unavailable grant=%s", grant)
	}
}

func (h *Handler) authError(rec store.Token, err error) {
	id := rec.ID
	if id == "" {
		id = "-"
	}
	switch {
	case errors.Is(err, store.ErrUnauthorized):
		h.debug("auth=nomatch")
	case errors.Is(err, store.ErrRevoked):
		h.debug("auth=revoked id=%s", id)
	case errors.Is(err, store.ErrExpired):
		h.debug("auth=expired id=%s", id)
	case errors.Is(err, store.ErrQuota):
		h.debug("auth=quota id=%s", id)
	default:
		h.alert("state=insecure id=%s err=%s", id, err.Error())
	}
}

func (h *Handler) debug(format string, args ...any) {
	if h.Verbose == nil {
		return
	}
	fmt.Fprintf(h.Verbose, "keyferry: "+format+"\n", args...)
}

func (h *Handler) alert(format string, args ...any) {
	if h.Alerts == nil {
		return
	}
	fmt.Fprintf(h.Alerts, "keyferry: "+format+"\n", args...)
}

func writeStatus(w http.ResponseWriter, code int, word string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, word)
	_, _ = io.WriteString(w, "\n")
}

func chooseGrant(fixed, asked string) (string, bool) {
	switch {
	case fixed != "" && asked != "" && fixed != asked:
		return "", true
	case fixed != "":
		return fixed, false
	default:
		return asked, false
	}
}

// grantFromRequest reads /g/{name}/... or X-Keyferry-Grant.
// The returned path is what the provider should see.
func grantFromRequest(r *http.Request) (name, path string, err error) {
	path = r.URL.Path
	if path == "" {
		path = "/"
	}
	header := strings.TrimSpace(r.Header.Get("X-Keyferry-Grant"))
	if strings.HasPrefix(path, "/g/") {
		rest := strings.TrimPrefix(path, "/g/")
		cut, suffix, _ := strings.Cut(rest, "/")
		if err := validateGrantName(cut); err != nil {
			return "", "", err
		}
		name = cut
		if suffix == "" {
			path = "/"
		} else {
			path = "/" + suffix
		}
	}
	if header != "" {
		if err := validateGrantName(header); err != nil {
			return "", "", err
		}
		if name != "" && name != header {
			return "", "", errors.New("grant mismatch")
		}
		name = header
	}
	return name, path, nil
}

func validateGrantName(name string) error {
	if name == "" || len(name) > 32 {
		return errors.New("bad grant")
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0:
		default:
			return errors.New("bad grant")
		}
	}
	return nil
}

func rejectedQuery(r *http.Request) bool {
	q := r.URL.Query()
	for _, name := range []string{"api_key", "api-key", "key", "token", "access_token"} {
		if _, ok := q[name]; ok {
			return true
		}
	}
	return false
}

func presentedToken(r *http.Request) (string, bool) {
	var found []string
	if h := r.Header.Get("Authorization"); h != "" {
		token, ok := bearer(h)
		if !ok {
			return "", false
		}
		found = append(found, token)
	}
	if v := strings.TrimSpace(r.Header.Get("X-Api-Key")); v != "" {
		found = append(found, v)
	}
	if v := strings.TrimSpace(r.Header.Get("X-Keyferry-Token")); v != "" {
		found = append(found, v)
	}
	if len(found) == 0 {
		return "", false
	}
	for _, other := range found[1:] {
		if other != found[0] {
			return "", false
		}
	}
	return found[0], true
}

func bearer(h string) (string, bool) {
	h = strings.TrimSpace(h)
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

func stripSensitive(h http.Header) {
	for _, name := range []string{
		"Authorization",
		"Proxy-Authorization",
		"X-Api-Key",
		"X-Keyferry-Token",
		"Cookie",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Real-Ip",
		"Forwarded",
	} {
		h.Del(name)
	}
}

func scrubResponse(res *http.Response, key string) {
	res.Header.Del("Authorization")
	res.Header.Del("X-Api-Key")
	res.Header.Del("Set-Cookie")
	if key == "" {
		return
	}
	for name, vals := range res.Header {
		for _, v := range vals {
			if strings.Contains(v, key) {
				res.Header.Del(name)
				break
			}
		}
	}
}

func applyAuth(h http.Header, up store.Upstream) {
	switch up.Provider {
	case store.ProviderOpenAI:
		h.Set("Authorization", "Bearer "+up.Key)
	case store.ProviderAnthropic:
		h.Set("X-Api-Key", up.Key)
	case store.ProviderGeneric:
		value := up.Key
		if up.AuthScheme != "" {
			value = up.AuthScheme + " " + up.Key
		}
		h.Set(up.AuthHeader, value)
	default:
		// Unknown providers never receive a key. The request fails upstream
		// without the stored secret attached.
	}
}
