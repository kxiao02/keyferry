// Package admin is the local management UI. It is served on its own listener,
// never on the relay socket shared machines use.
package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"

	"keyferry/internal/store"
)

// Handler serves one page for keys, grants, and bindings.
type Handler struct {
	Store *store.Store
	csrf  string
}

// New returns a handler with an in-memory form token.
func New(st *store.Store) *Handler {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return &Handler{Store: st, csrf: base64.RawURLEncoding.EncodeToString(buf)}
}

type keyView struct {
	store.UpstreamInfo
	Bound bool
}

type grantView struct {
	store.GrantInfo
	KeyViews []keyView
}

type page struct {
	CSRF   string
	Notice string
	Keys   []store.UpstreamInfo
	Grants []grantView
}

// ServeHTTP handles the management page and its form posts.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.URL.Query()["key"]; ok {
		http.Error(w, "rejected\n", http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == ""):
		h.render(w, r.URL.Query().Get("notice"))
	case r.Method == http.MethodPost:
		h.post(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) post(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "rejected\n", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(h.csrf)) != 1 {
		http.Error(w, "rejected\n", http.StatusForbidden)
		return
	}
	notice := "saved"
	var err error
	switch r.URL.Path {
	case "/keys/add":
		err = h.Store.PutUpstream(store.Upstream{
			Name:       r.PostForm.Get("name"),
			Provider:   r.PostForm.Get("provider"),
			BaseURL:    r.PostForm.Get("base_url"),
			AuthHeader: r.PostForm.Get("auth_header"),
			AuthScheme: r.PostForm.Get("auth_scheme"),
			Key:        r.PostForm.Get("key"),
			Enabled:    boolPtr(r.PostForm.Get("enabled") == "1"),
		})
	case "/keys/edit":
		err = h.Store.EditKey(
			r.PostForm.Get("name"),
			r.PostForm.Get("provider"),
			r.PostForm.Get("base_url"),
			r.PostForm.Get("auth_header"),
			r.PostForm.Get("auth_scheme"),
			r.PostForm.Get("key"),
		)
	case "/keys/toggle":
		err = h.Store.SetKeyEnabled(r.PostForm.Get("name"), r.PostForm.Get("enabled") == "1")
	case "/keys/delete":
		err = h.Store.DeleteUpstream(r.PostForm.Get("name"))
	case "/grants/add":
		err = h.Store.PutGrant(store.Grant{
			Name:    r.PostForm.Get("name"),
			Enabled: boolPtr(r.PostForm.Get("enabled") == "1"),
			Keys:    r.PostForm["keys"],
			Socket:  strings.TrimSpace(r.PostForm.Get("socket")),
		})
	case "/grants/save":
		err = h.saveGrant(r)
	case "/grants/toggle":
		err = h.Store.SetGrantEnabled(r.PostForm.Get("name"), r.PostForm.Get("enabled") == "1")
	case "/grants/delete":
		err = h.Store.DeleteGrant(r.PostForm.Get("name"))
	case "/grants/bind":
		err = h.Store.Bind(r.PostForm.Get("name"), r.PostForm.Get("bind_key"))
	case "/grants/unbind":
		err = h.Store.Unbind(r.PostForm.Get("name"), r.PostForm.Get("bind_key"))
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		notice = "error"
	}
	http.Redirect(w, r, "/?notice="+notice, http.StatusSeeOther)
}

func (h *Handler) saveGrant(r *http.Request) error {
	name := r.PostForm.Get("name")
	g, err := h.Store.GetGrant(name)
	if err != nil {
		return err
	}
	g.Keys = append([]string(nil), r.PostForm["keys"]...)
	g.Socket = strings.TrimSpace(r.PostForm.Get("socket"))
	g.Enabled = boolPtr(r.PostForm.Get("enabled") == "1")
	return h.Store.PutGrant(g)
}

func (h *Handler) render(w http.ResponseWriter, notice string) {
	keys, err := h.Store.ListUpstreams()
	if err != nil {
		http.Error(w, "unavailable\n", http.StatusBadGateway)
		return
	}
	grants, err := h.Store.ListGrants()
	if err != nil {
		http.Error(w, "unavailable\n", http.StatusBadGateway)
		return
	}
	view := page{CSRF: h.csrf, Notice: notice, Keys: keys}
	for _, g := range grants {
		gv := grantView{GrantInfo: g}
		bound := map[string]bool{}
		for _, name := range g.Keys {
			bound[name] = true
		}
		for _, k := range keys {
			gv.KeyViews = append(gv.KeyViews, keyView{UpstreamInfo: k, Bound: bound[k.Name]})
		}
		view.Grants = append(view.Grants, gv)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = pageTmpl.Execute(w, view)
}

func boolPtr(on bool) *bool { return &on }

var pageTmpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>keyferry</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.45 ui-sans-serif, system-ui, sans-serif; margin: 0; }
  main { max-width: 46rem; margin: 0 auto; padding: 1.25rem; }
  h1 { font-size: 1.3rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.05rem; margin: 1.5rem 0 .4rem; }
  p { margin: .3rem 0 .8rem; }
  form, .card { border: 1px solid #8884; border-radius: 8px; padding: .8rem; margin: .6rem 0; }
  label { display: block; margin: .35rem 0; }
  input, select, button { font: inherit; }
  input[type="text"], input[type="password"], select { width: 100%; max-width: 28rem; }
  .row { display: flex; flex-wrap: wrap; gap: .4rem; align-items: center; }
  .muted { opacity: .75; }
  .off { opacity: .6; }
  code { font-family: ui-monospace, monospace; }
</style>
</head>
<body>
<main>
<h1>keyferry</h1>
<p class="muted">Keys and grants on this machine. Shared clients never open this page.</p>
{{if eq .Notice "saved"}}<p>Saved.</p>{{end}}
{{if eq .Notice "error"}}<p>That change was rejected.</p>{{end}}

<h2>Keys</h2>
<form method="post" action="/keys/add" autocomplete="off">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <label>Name <input name="name" required pattern="[a-z][a-z0-9-]{0,31}"></label>
  <label>Provider
    <select name="provider">
      <option value="openai">openai</option>
      <option value="anthropic">anthropic</option>
      <option value="generic">generic</option>
    </select>
  </label>
  <label>Base URL <input name="base_url" placeholder="https://api.example"></label>
  <label>Auth header <input name="auth_header" placeholder="generic only"></label>
  <label>Auth scheme <input name="auth_scheme" placeholder="Bearer or blank"></label>
  <label>Key <input type="password" name="key" required autocomplete="off"></label>
  <label><input type="checkbox" name="enabled" value="1" checked> Enabled</label>
  <button type="submit">Add key</button>
</form>
{{range .Keys}}
<div class="card{{if not .Enabled}} off{{end}}">
  <strong>{{.Name}}</strong>
  <span class="muted">{{.Provider}} {{.BaseURL}}</span>
  <div class="muted">fp <code>{{.KeyFP}}</code>{{if .Last4}} last4 <code>{{.Last4}}</code>{{end}} {{if .Enabled}}on{{else}}off{{end}}</div>
  <div class="row">
    <form method="post" action="/keys/toggle">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="name" value="{{.Name}}">
      <input type="hidden" name="enabled" value="{{if .Enabled}}0{{else}}1{{end}}">
      <button type="submit">{{if .Enabled}}Turn off{{else}}Turn on{{end}}</button>
    </form>
    <form method="post" action="/keys/delete">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="name" value="{{.Name}}">
      <button type="submit">Delete</button>
    </form>
  </div>
  <form method="post" action="/keys/edit" autocomplete="off">
    <input type="hidden" name="csrf" value="{{$.CSRF}}">
    <input type="hidden" name="name" value="{{.Name}}">
    <label>Provider
      <select name="provider">
        <option value="openai" {{if eq .Provider "openai"}}selected{{end}}>openai</option>
        <option value="anthropic" {{if eq .Provider "anthropic"}}selected{{end}}>anthropic</option>
        <option value="generic" {{if eq .Provider "generic"}}selected{{end}}>generic</option>
      </select>
    </label>
    <label>Base URL <input name="base_url" value="{{.BaseURL}}"></label>
    <label>Auth header <input name="auth_header" value="{{.AuthHeader}}"></label>
    <label>Auth scheme <input name="auth_scheme" value="{{.AuthScheme}}"></label>
    <label>Replace key <input type="password" name="key" autocomplete="off" placeholder="blank keeps the current key"></label>
    <button type="submit">Save key</button>
  </form>
</div>
{{end}}

<h2>Grants</h2>
<p class="muted">A grant is a route. Bind one or more keys. One key can sit on several grants. Clients select a grant with <code>/g/name/...</code> or their own socket.</p>
<form method="post" action="/grants/add">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <label>Name <input name="name" required pattern="[a-z][a-z0-9-]{0,31}"></label>
  <label>Extra Unix socket <input name="socket" placeholder="optional absolute path"></label>
  <label><input type="checkbox" name="enabled" value="1" checked> Enabled</label>
  <fieldset>
    <legend>Bind keys</legend>
    {{range .Keys}}<label><input type="checkbox" name="keys" value="{{.Name}}"> {{.Name}}{{if .Last4}} ···{{.Last4}}{{end}}</label>{{end}}
  </fieldset>
  <button type="submit">Add grant</button>
</form>
{{range $g := .Grants}}
<div class="card{{if not $g.Enabled}} off{{end}}">
  <strong>{{$g.Name}}</strong>
  <span class="muted">{{if $g.Enabled}}on{{else}}off{{end}}{{if $g.Socket}} socket {{$g.Socket}}{{end}}</span>
  <div class="row">
    <form method="post" action="/grants/toggle">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="name" value="{{$g.Name}}">
      <input type="hidden" name="enabled" value="{{if $g.Enabled}}0{{else}}1{{end}}">
      <button type="submit">{{if $g.Enabled}}Turn off{{else}}Turn on{{end}}</button>
    </form>
    <form method="post" action="/grants/delete">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="name" value="{{$g.Name}}">
      <button type="submit">Delete</button>
    </form>
  </div>
  {{range $g.KeyViews}}
  <div class="row">
    <span>{{.Name}} {{if .Enabled}}on{{else}}off{{end}} <code>{{.KeyFP}}</code>{{if .Last4}} ···{{.Last4}}{{end}}</span>
    {{if .Bound}}
    <form method="post" action="/grants/unbind">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="name" value="{{$g.Name}}">
      <input type="hidden" name="bind_key" value="{{.Name}}">
      <button type="submit">Unbind</button>
    </form>
    {{else}}
    <form method="post" action="/grants/bind">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="name" value="{{$g.Name}}">
      <input type="hidden" name="bind_key" value="{{.Name}}">
      <button type="submit">Bind</button>
    </form>
    {{end}}
  </div>
  {{end}}
  <form method="post" action="/grants/save">
    <input type="hidden" name="csrf" value="{{$.CSRF}}">
    <input type="hidden" name="name" value="{{$g.Name}}">
    <label>Extra Unix socket <input name="socket" value="{{$g.Socket}}"></label>
    <label><input type="checkbox" name="enabled" value="1" {{if $g.Enabled}}checked{{end}}> Enabled</label>
    <fieldset>
      <legend>Bound keys</legend>
      {{range $g.KeyViews}}<label><input type="checkbox" name="keys" value="{{.Name}}" {{if .Bound}}checked{{end}}> {{.Name}}</label>{{end}}
    </fieldset>
    <button type="submit">Save bindings</button>
  </form>
</div>
{{else}}
<p class="muted">No grants yet. Add one and bind a key.</p>
{{end}}
</main>
</body>
</html>
`))
