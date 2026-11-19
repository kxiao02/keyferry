package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"keyferry/internal/perms"
)

// Grant is one serving route. It can bind many keys, and a key can appear on many grants.
type Grant struct {
	Name    string   `json:"name"`
	Enabled *bool    `json:"enabled,omitempty"`
	Keys    []string `json:"keys,omitempty"`
	// Socket is an optional extra Unix socket for this grant alone.
	// Empty means the grant is reached on the shared socket by path or header.
	Socket string `json:"socket,omitempty"`
}

// IsEnabled reports whether requests for this grant may proceed.
func (g Grant) IsEnabled() bool {
	return g.Enabled == nil || *g.Enabled
}

// GrantInfo is safe to show. It has no provider secrets.
type GrantInfo struct {
	Name    string
	Enabled bool
	Keys    []string
	Socket  string
}

func (s *Store) grantDir() string    { return filepath.Join(s.Dir, "grants") }
func (s *Store) upstreamDir() string { return filepath.Join(s.Dir, "upstreams") }

// PutGrant creates or replaces a grant. Keys must already exist.
func (s *Store) PutGrant(g Grant) error {
	norm, err := s.normalizeGrant(g)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(norm, "", "  ")
	if err != nil {
		return err
	}
	return s.withLock(s.grantDir(), func() error {
		return perms.WriteOwnerFile(filepath.Join(s.grantDir(), norm.Name+".json"), append(body, '\n'))
	})
}

// GetGrant loads one grant.
func (s *Store) GetGrant(name string) (Grant, error) {
	if err := validateName(name); err != nil {
		return Grant{}, err
	}
	body, err := perms.ReadOwnerFile(filepath.Join(s.grantDir(), name+".json"), maxFile)
	if err != nil {
		if os.IsNotExist(err) {
			return Grant{}, errors.New("grant not found")
		}
		return Grant{}, err
	}
	var g Grant
	if err := json.Unmarshal(body, &g); err != nil {
		return Grant{}, ErrUnavailable
	}
	if _, err := s.normalizeGrant(g); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// ListGrants returns grants without secrets.
func (s *Store) ListGrants() ([]GrantInfo, error) {
	entries, err := os.ReadDir(s.grantDir())
	if err != nil {
		return nil, err
	}
	var out []GrantInfo
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		g, err := s.GetGrant(strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		keys := append([]string(nil), g.Keys...)
		sort.Strings(keys)
		out = append(out, GrantInfo{Name: g.Name, Enabled: g.IsEnabled(), Keys: keys, Socket: g.Socket})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteGrant removes a grant. Tokens for it then fail closed.
func (s *Store) DeleteGrant(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return s.withLock(s.grantDir(), func() error {
		path := filepath.Join(s.grantDir(), name+".json")
		if err := perms.AssertOwnerOnly(path, false); err != nil {
			if os.IsNotExist(err) {
				return errors.New("grant not found")
			}
			return err
		}
		return os.Remove(path)
	})
}

// Bind attaches a key to a grant.
func (s *Store) Bind(grant, key string) error {
	if _, err := s.GetUpstream(key); err != nil {
		return err
	}
	return s.withLock(s.grantDir(), func() error {
		g, err := s.readGrantLocked(grant)
		if err != nil {
			return err
		}
		if !containsName(g.Keys, key) {
			g.Keys = append(g.Keys, key)
		}
		return s.writeGrantLocked(g)
	})
}

// Unbind removes one key from a grant.
func (s *Store) Unbind(grant, key string) error {
	return s.withLock(s.grantDir(), func() error {
		g, err := s.readGrantLocked(grant)
		if err != nil {
			return err
		}
		g.Keys = removeName(g.Keys, key)
		return s.writeGrantLocked(g)
	})
}

// SetGrantEnabled turns a grant on or off.
func (s *Store) SetGrantEnabled(name string, on bool) error {
	return s.updateGrant(name, func(g *Grant) error {
		g.Enabled = boolPtr(on)
		return nil
	})
}

// SetGrantSocket sets or clears the optional extra Unix socket.
func (s *Store) SetGrantSocket(name, socket string) error {
	return s.updateGrant(name, func(g *Grant) error {
		g.Socket = socket
		return nil
	})
}

// SetKeyEnabled turns a provider key on or off.
func (s *Store) SetKeyEnabled(name string, on bool) error {
	return s.updateKey(name, func(u *Upstream) error {
		u.Enabled = boolPtr(on)
		return nil
	})
}

// EditKey updates metadata. newKey empty keeps the stored secret.
func (s *Store) EditKey(name, provider, baseURL, authHeader, authScheme, newKey string) error {
	return s.updateKey(name, func(u *Upstream) error {
		if provider != "" {
			u.Provider = provider
		}
		if baseURL != "" || provider == ProviderGeneric {
			if baseURL != "" {
				u.BaseURL = baseURL
			}
		}
		if provider == ProviderGeneric || authHeader != "" {
			if authHeader != "" {
				u.AuthHeader = authHeader
			}
		}
		if authScheme != "" {
			u.AuthScheme = authScheme
		}
		if newKey != "" {
			u.Key = newKey
		}
		return nil
	})
}

// ResolveGrant selects one enabled key bound to an enabled grant.
// An empty name uses the sole enabled grant. The caller must not hold the grant lock.
func (s *Store) ResolveGrant(name string) (Grant, Upstream, error) {
	var (
		g  Grant
		up Upstream
	)
	err := s.withLock(s.grantDir(), func() error {
		return s.withLock(s.upstreamDir(), func() error {
			picked, err := s.pickGrantLocked(name)
			if err != nil {
				return err
			}
			chosen, err := s.pickKeyLocked(picked.Keys)
			if err != nil {
				return err
			}
			g = picked
			up = chosen
			return nil
		})
	})
	return g, up, err
}

func (s *Store) updateGrant(name string, fn func(*Grant) error) error {
	if err := validateName(name); err != nil {
		return err
	}
	return s.withLock(s.grantDir(), func() error {
		g, err := s.readGrantLocked(name)
		if err != nil {
			return err
		}
		if err := fn(&g); err != nil {
			return err
		}
		norm, err := s.normalizeGrant(g)
		if err != nil {
			return err
		}
		return s.writeGrantLocked(norm)
	})
}

func (s *Store) updateKey(name string, fn func(*Upstream) error) error {
	if err := validateName(name); err != nil {
		return err
	}
	return s.withLock(s.upstreamDir(), func() error {
		u, err := s.GetUpstream(name)
		if err != nil {
			return err
		}
		if err := fn(&u); err != nil {
			return err
		}
		norm, err := normalizeUpstream(u)
		if err != nil {
			return err
		}
		norm.Enabled = u.Enabled
		if norm.Enabled == nil {
			norm.Enabled = boolPtr(true)
		}
		body, err := json.MarshalIndent(norm, "", "  ")
		if err != nil {
			return err
		}
		return perms.WriteOwnerFile(filepath.Join(s.upstreamDir(), name+".json"), append(body, '\n'))
	})
}

func (s *Store) normalizeGrant(g Grant) (Grant, error) {
	if err := validateName(g.Name); err != nil {
		return Grant{}, err
	}
	if g.Socket != "" {
		if !filepath.IsAbs(g.Socket) || strings.ContainsAny(g.Socket, "\r\n") {
			return Grant{}, errors.New("grant socket must be an absolute path")
		}
	}
	seen := map[string]bool{}
	var keys []string
	for _, name := range g.Keys {
		if err := validateName(name); err != nil {
			return Grant{}, err
		}
		if seen[name] {
			continue
		}
		if _, err := s.GetUpstream(name); err != nil {
			return Grant{}, err
		}
		seen[name] = true
		keys = append(keys, name)
	}
	sort.Strings(keys)
	g.Keys = keys
	if g.Enabled == nil {
		g.Enabled = boolPtr(true)
	}
	return g, nil
}

func (s *Store) pickGrantLocked(name string) (Grant, error) {
	if name != "" {
		g, err := s.readGrantLocked(name)
		if err != nil {
			return Grant{}, err
		}
		if !g.IsEnabled() {
			return Grant{}, ErrDisabled
		}
		return g, nil
	}
	entries, err := os.ReadDir(s.grantDir())
	if err != nil {
		return Grant{}, err
	}
	var enabled []Grant
	var any bool
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
			continue
		}
		g, err := s.readGrantLocked(strings.TrimSuffix(n, ".json"))
		if err != nil {
			return Grant{}, err
		}
		any = true
		if g.IsEnabled() {
			enabled = append(enabled, g)
		}
	}
	if len(enabled) == 1 {
		return enabled[0], nil
	}
	if len(enabled) == 0 && any {
		return Grant{}, ErrDisabled
	}
	if len(enabled) == 0 {
		return Grant{}, ErrUnavailable
	}
	return Grant{}, ErrGrantRequired
}

func (s *Store) pickKeyLocked(names []string) (Upstream, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	saw := false
	for _, name := range sorted {
		u, err := s.GetUpstream(name)
		if err != nil {
			continue
		}
		saw = true
		if u.IsEnabled() {
			return u, nil
		}
	}
	if !saw {
		return Upstream{}, ErrDisabled
	}
	return Upstream{}, ErrDisabled
}

func (s *Store) readGrantLocked(name string) (Grant, error) {
	if err := validateName(name); err != nil {
		return Grant{}, err
	}
	body, err := perms.ReadOwnerFile(filepath.Join(s.grantDir(), name+".json"), maxFile)
	if err != nil {
		if os.IsNotExist(err) {
			return Grant{}, errors.New("grant not found")
		}
		return Grant{}, err
	}
	var g Grant
	if err := json.Unmarshal(body, &g); err != nil {
		return Grant{}, ErrUnavailable
	}
	return g, nil
}

func (s *Store) writeGrantLocked(g Grant) error {
	body, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return perms.WriteOwnerFile(filepath.Join(s.grantDir(), g.Name+".json"), append(body, '\n'))
}

func (s *Store) stripKeyLocked(key string) error {
	entries, err := os.ReadDir(s.grantDir())
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		g, err := s.readGrantLocked(strings.TrimSuffix(name, ".json"))
		if err != nil {
			return err
		}
		next := removeName(g.Keys, key)
		if len(next) == len(g.Keys) {
			continue
		}
		g.Keys = next
		if err := s.writeGrantLocked(g); err != nil {
			return err
		}
	}
	return nil
}

func containsName(list []string, name string) bool {
	for _, item := range list {
		if item == name {
			return true
		}
	}
	return false
}

func removeName(list []string, name string) []string {
	var out []string
	for _, item := range list {
		if item != name {
			out = append(out, item)
		}
	}
	return out
}

func boolPtr(on bool) *bool {
	return &on
}
