// Package store keeps provider keys and relay tokens on the personal server.
// Tokens are stored as hashes. Provider keys are never read from the environment.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"keyferry/internal/perms"
)

const (
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
	ProviderGeneric   = "generic"

	maxFile     = 16 << 10
	maxLabelLen = 64
	maxTTL      = 168 * time.Hour
	defaultTTL  = 4 * time.Hour

	// PlaceholderKey is the fixed client api_key for Unix-socket access.
	// It is not a secret and is never a provider key.
	PlaceholderKey = "keyferry"
)

var (
	ErrUnauthorized  = errors.New("unauthorized")
	ErrRevoked       = errors.New("revoked")
	ErrExpired       = errors.New("expired")
	ErrQuota         = errors.New("quota")
	ErrUnavailable   = errors.New("unavailable")
	ErrDisabled      = errors.New("disabled")
	ErrGrantRequired = errors.New("grant required")
)

// Upstream is one provider account. Key is the real provider secret.
type Upstream struct {
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	BaseURL    string `json:"base_url"`
	AuthHeader string `json:"auth_header,omitempty"`
	AuthScheme string `json:"auth_scheme,omitempty"`
	Key        string `json:"key"`
	// Enabled is nil for records written before the switch existed; those stay on.
	Enabled *bool `json:"enabled,omitempty"`
}

// IsEnabled reports whether the key may be selected for a grant.
func (u Upstream) IsEnabled() bool {
	return u.Enabled == nil || *u.Enabled
}

// UpstreamInfo is safe to print. It does not contain the provider key.
type UpstreamInfo struct {
	Name       string
	Provider   string
	BaseURL    string
	KeyFP      string
	Last4      string
	Enabled    bool
	AuthHeader string
	AuthScheme string
}

// Token is the on-disk record. The bearer string is not stored.
type Token struct {
	ID             string    `json:"id"`
	Grant          string    `json:"grant,omitempty"`
	Upstream       string    `json:"upstream,omitempty"`
	Expires        time.Time `json:"expires"`
	Revoked        bool      `json:"revoked"`
	Label          string    `json:"label,omitempty"`
	Created        time.Time `json:"created"`
	QuotaRemaining *int      `json:"quota_remaining,omitempty"`
}

// Store is a directory of mode-0700 files.
type Store struct {
	Dir string
}

// DefaultDir is $XDG_STATE_HOME/keyferry or ~/.local/state/keyferry.
func DefaultDir() (string, error) {
	if v := os.Getenv("KEYFERRY_STATE_DIR"); v != "" {
		return v, nil
	}
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "keyferry"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "keyferry"), nil
}

// Open creates the directory layout and refuses loose permissions.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("state directory is empty")
	}
	if err := perms.EnsureDir(dir); err != nil {
		return nil, err
	}
	for _, sub := range []string{"upstreams", "grants", "tokens"} {
		if err := perms.EnsureDir(filepath.Join(dir, sub)); err != nil {
			return nil, err
		}
	}
	if err := perms.WalkOwnerOnly(dir); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

// PutUpstream validates and stores a provider key, replacing any previous key of the same name.
func (s *Store) PutUpstream(u Upstream) error {
	if err := validateName(u.Name); err != nil {
		return err
	}
	if u.Enabled == nil {
		if prev, err := s.GetUpstream(u.Name); err == nil && prev.Enabled != nil {
			u.Enabled = prev.Enabled
		} else {
			on := true
			u.Enabled = &on
		}
	}
	norm, err := normalizeUpstream(u)
	if err != nil {
		return err
	}
	norm.Enabled = u.Enabled
	body, err := json.MarshalIndent(norm, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return s.withLock(filepath.Join(s.Dir, "upstreams"), func() error {
		return perms.WriteOwnerFile(filepath.Join(s.Dir, "upstreams", norm.Name+".json"), body)
	})
}

// GetUpstream loads a key. Callers must not log the Key field.
func (s *Store) GetUpstream(name string) (Upstream, error) {
	if err := validateName(name); err != nil {
		return Upstream{}, err
	}
	body, err := perms.ReadOwnerFile(filepath.Join(s.Dir, "upstreams", name+".json"), maxFile)
	if err != nil {
		if os.IsNotExist(err) {
			return Upstream{}, fmt.Errorf("%w: upstream %s", ErrUnavailable, name)
		}
		return Upstream{}, err
	}
	var u Upstream
	if err := json.Unmarshal(body, &u); err != nil {
		return Upstream{}, fmt.Errorf("%w: upstream record", ErrUnavailable)
	}
	if _, err := normalizeUpstream(u); err != nil {
		return Upstream{}, err
	}
	return u, nil
}

// ListUpstreams returns descriptions without keys.
func (s *Store) ListUpstreams() ([]UpstreamInfo, error) {
	dir := filepath.Join(s.Dir, "upstreams")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []UpstreamInfo
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		u, err := s.GetUpstream(strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, UpstreamInfo{
			Name:       u.Name,
			Provider:   u.Provider,
			BaseURL:    u.BaseURL,
			KeyFP:      KeyFingerprint(u.Key),
			Last4:      KeyLast4(u.Key),
			Enabled:    u.IsEnabled(),
			AuthHeader: u.AuthHeader,
			AuthScheme: u.AuthScheme,
		})
	}
	return out, nil
}

// DeleteUpstream removes a provider record. Existing tokens then fail closed.
func (s *Store) DeleteUpstream(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := s.withLock(s.grantDir(), func() error {
		return s.stripKeyLocked(name)
	}); err != nil {
		return err
	}
	return s.withLock(s.upstreamDir(), func() error {
		path := filepath.Join(s.upstreamDir(), name+".json")
		if err := perms.AssertOwnerOnly(path, false); err != nil {
			if os.IsNotExist(err) {
				return errors.New("upstream not found")
			}
			return err
		}
		return os.Remove(path)
	})
}

// GrantName is the serving-side grant this token selects.
func (t Token) GrantName() string {
	if t.Grant != "" {
		return t.Grant
	}
	return t.Upstream
}

// IssueToken creates a short-lived bearer token bound to one grant.
// The returned string is the only copy of the secret.
func (s *Store) IssueToken(grant, label string, ttl time.Duration, quota int) (string, Token, error) {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if ttl > maxTTL {
		return "", Token{}, fmt.Errorf("ttl exceeds %s", maxTTL)
	}
	if quota < 0 {
		return "", Token{}, errors.New("quota must be >= 0")
	}
	if err := validateLabel(label); err != nil {
		return "", Token{}, err
	}
	if _, err := s.GetGrant(grant); err != nil {
		return "", Token{}, err
	}
	raw, err := randomToken()
	if err != nil {
		return "", Token{}, err
	}
	id, err := randomID()
	if err != nil {
		return "", Token{}, err
	}
	now := time.Now().UTC()
	rec := Token{
		ID:       id,
		Grant:    grant,
		Upstream: grant,
		Expires:  now.Add(ttl),
		Label:    label,
		Created:  now,
	}
	if quota > 0 {
		q := quota
		rec.QuotaRemaining = &q
	}
	if err := s.writeToken(raw, rec); err != nil {
		return "", Token{}, err
	}
	return raw, rec, nil
}

// ListTokens returns records. Bearer secrets are not recoverable.
func (s *Store) ListTokens() ([]Token, error) {
	var out []Token
	err := s.withLock(filepath.Join(s.Dir, "tokens"), func() error {
		var err error
		out, err = s.listTokensLocked()
		return err
	})
	return out, err
}

// Revoke marks a token so later requests fail.
func (s *Store) Revoke(id string) error {
	if !validID(id) {
		return errors.New("invalid token id")
	}
	return s.withLock(filepath.Join(s.Dir, "tokens"), func() error {
		found, err := s.pathsByIDLocked(id)
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return errors.New("token not found")
		}
		for _, item := range found {
			item.rec.Revoked = true
			body, err := json.MarshalIndent(item.rec, "", "  ")
			if err != nil {
				return err
			}
			if err := perms.WriteOwnerFile(item.path, append(body, '\n')); err != nil {
				return err
			}
		}
		return nil
	})
}

// Authorize checks the bearer token, spends one request of quota, and returns
// the bound upstream. It does not consult the process environment.
func (s *Store) Authorize(token string) (Token, Upstream, error) {
	if !acceptableToken(token) {
		return Token{}, Upstream{}, ErrUnauthorized
	}
	sum := hashToken(token)
	path := filepath.Join(s.Dir, "tokens", sum+".json")
	var (
		rec Token
		up  Upstream
	)
	err := s.withLock(filepath.Join(s.Dir, "tokens"), func() error {
		body, err := perms.ReadOwnerFile(path, maxFile)
		if err != nil {
			if os.IsNotExist(err) {
				return ErrUnauthorized
			}
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		if err := json.Unmarshal(body, &rec); err != nil {
			return ErrUnauthorized
		}
		if rec.Revoked {
			return ErrRevoked
		}
		if !rec.Expires.After(time.Now()) {
			return ErrExpired
		}
		_, loaded, err := s.ResolveGrant(rec.GrantName())
		if err != nil {
			return err
		}
		if rec.QuotaRemaining != nil {
			if *rec.QuotaRemaining <= 0 {
				return ErrQuota
			}
			left := *rec.QuotaRemaining - 1
			rec.QuotaRemaining = &left
			out, err := json.MarshalIndent(rec, "", "  ")
			if err != nil {
				return err
			}
			if err := perms.WriteOwnerFile(path, append(out, '\n')); err != nil {
				return err
			}
		}
		up = loaded
		return nil
	})
	if err != nil {
		return rec, Upstream{}, err
	}
	return rec, up, nil
}

// KeyFingerprint is a short hash prefix so operators can tell keys apart.
func KeyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:4])
}

// KeyLast4 is a short suffix for the UI. Short secrets return nothing.
func KeyLast4(key string) string {
	if len(key) < 12 {
		return ""
	}
	return key[len(key)-4:]
}

func (s *Store) writeToken(raw string, rec Token) error {
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return s.withLock(filepath.Join(s.Dir, "tokens"), func() error {
		return perms.WriteOwnerFile(filepath.Join(s.Dir, "tokens", hashToken(raw)+".json"), append(body, '\n'))
	})
}

type tokenPath struct {
	path string
	rec  Token
}

func (s *Store) listTokensLocked() ([]Token, error) {
	entries, err := os.ReadDir(filepath.Join(s.Dir, "tokens"))
	if err != nil {
		return nil, err
	}
	var out []Token
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		base := strings.TrimSuffix(name, ".json")
		if len(base) != 64 || strings.Trim(base, "0123456789abcdef") != "" {
			return nil, fmt.Errorf("%w: unexpected token file", ErrUnavailable)
		}
		body, err := perms.ReadOwnerFile(filepath.Join(s.Dir, "tokens", name), maxFile)
		if err != nil {
			return nil, err
		}
		var rec Token
		if err := json.Unmarshal(body, &rec); err != nil {
			return nil, fmt.Errorf("%w: token record", ErrUnavailable)
		}
		out = append(out, rec)
	}
	return out, nil
}

func (s *Store) pathsByIDLocked(id string) ([]tokenPath, error) {
	entries, err := os.ReadDir(filepath.Join(s.Dir, "tokens"))
	if err != nil {
		return nil, err
	}
	var out []tokenPath
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		body, err := perms.ReadOwnerFile(filepath.Join(s.Dir, "tokens", name), maxFile)
		if err != nil {
			return nil, err
		}
		var rec Token
		if err := json.Unmarshal(body, &rec); err != nil {
			return nil, err
		}
		if rec.ID == id {
			out = append(out, tokenPath{path: filepath.Join(s.Dir, "tokens", name), rec: rec})
		}
	}
	return out, nil
}

func normalizeUpstream(u Upstream) (Upstream, error) {
	if err := validateName(u.Name); err != nil {
		return Upstream{}, err
	}
	if err := validateSecret(u.Key); err != nil {
		return Upstream{}, fmt.Errorf("provider key: %w", err)
	}
	if u.Key == PlaceholderKey {
		return Upstream{}, errors.New("provider key must not be the placeholder")
	}
	base, err := ValidateBaseURL(u.BaseURL)
	if err != nil {
		return Upstream{}, err
	}
	switch u.Provider {
	case ProviderOpenAI:
		if u.BaseURL == "" {
			base = "https://api.openai.com"
		}
		u.AuthHeader = ""
		u.AuthScheme = ""
	case ProviderAnthropic:
		if u.BaseURL == "" {
			base = "https://api.anthropic.com"
		}
		u.AuthHeader = ""
		u.AuthScheme = ""
	case ProviderGeneric:
		if u.BaseURL == "" {
			return Upstream{}, errors.New("generic provider requires --base-url")
		}
		if err := validateHeaderName(u.AuthHeader); err != nil {
			return Upstream{}, err
		}
		if err := validateScheme(u.AuthScheme); err != nil {
			return Upstream{}, err
		}
	default:
		return Upstream{}, errors.New("provider must be openai, anthropic, or generic")
	}
	u.BaseURL = base
	return u, nil
}

// ValidateBaseURL allows https, and http only to a loopback host.
// Credentials, queries, and non-root paths are rejected.
func ValidateBaseURL(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid base url")
	}
	if u.User != nil {
		return "", errors.New("base url must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("base url must not contain a query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("base url must be an origin without a path")
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		if !loopbackHost(host) {
			return "", errors.New("refusing cleartext upstream")
		}
	default:
		return "", errors.New("base url scheme must be https")
	}
	if u.Hostname() == "" {
		return "", errors.New("base url is missing a host")
	}
	u.Path = ""
	u.RawPath = ""
	return u.String(), nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateName(name string) error {
	if len(name) == 0 || len(name) > 32 {
		return errors.New("invalid upstream name")
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0:
		default:
			return errors.New("invalid upstream name")
		}
	}
	return nil
}

func validateLabel(label string) error {
	if len(label) > maxLabelLen {
		return errors.New("label is too long")
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			return errors.New("label contains control characters")
		}
	}
	return nil
}

func validateSecret(s string) error {
	if s == "" || len(s) > 4096 {
		return errors.New("empty or too long")
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return errors.New("contains whitespace or control characters")
		}
	}
	return nil
}

func validateHeaderName(h string) error {
	if h == "" || len(h) > 64 {
		return errors.New("auth header is required for a generic provider")
	}
	for _, r := range h {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return errors.New("invalid auth header name")
		}
	}
	return nil
}

func validateScheme(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > 32 {
		return errors.New("auth scheme is too long")
	}
	for i, r := range s {
		ok := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if i > 0 && (r == '.' || r == '_' || r == '+' || r == '-') {
			ok = true
		}
		if !ok {
			return errors.New("invalid auth scheme")
		}
	}
	return nil
}

func acceptableToken(token string) bool {
	if len(token) < 8 || len(token) > 256 {
		return false
	}
	return validateSecret(token) == nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "kf_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func validID(id string) bool {
	if len(id) != 16 {
		return false
	}
	return strings.Trim(id, "0123456789abcdef") == ""
}
