// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 6) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
//
// Package scope implements scope profiles (spec D7/D10, section 6):
// built-in, per-platform knowledge of which concrete scope set an access
// level ("read-only"/"read-write") implies, plus the env var a scope
// profile says exec should inject a secret under. Built-in profiles are
// embedded in the binary; a user file at
// ~/.config/credroute/profiles/<platform>.yaml overrides or extends them.
// An unknown platform is never an error: it resolves as generic
// passthrough (enforcement "advisory", no scopes), per spec 6.3.
package scope

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hasandenizuk/credroute/internal/config"
)

//go:embed profiles/*.yaml
var builtinFS embed.FS

// Profile is one platform's scope profile document (spec 6.1).
type Profile struct {
	Platform        string                 `yaml:"platform" json:"platform"`
	Aliases         []string               `yaml:"aliases,omitempty" json:"aliases,omitempty"`
	CredentialTypes []string               `yaml:"credential_types,omitempty" json:"credential_types,omitempty"`
	IdentityProbe   IdentityProbe          `yaml:"identity_probe,omitempty" json:"identity_probe,omitempty"`
	AccessLevels    map[string]AccessLevel `yaml:"access_levels,omitempty" json:"access_levels,omitempty"`
	Login           LoginInfo              `yaml:"login,omitempty" json:"login,omitempty"`
	// ExecEnv is the env var name `credroute exec` injects the decrypted
	// secret under for this platform (spec 6.1 example: GOOGLE_OAUTH_TOKEN_JSON,
	// GH_TOKEN).
	ExecEnv string `yaml:"exec_env,omitempty" json:"exec_env,omitempty"`
}

// IdentityProbe describes how spec 5.3's live probe confirms "who is
// really in this credential" for this platform. Milestone 3 only loads
// and exposes this data (profiles show); internal/verify's own prober
// registry (milestone 2) is the thing that actually calls out over the
// network and is not touched here.
type IdentityProbe struct {
	Method        string `yaml:"method,omitempty" json:"method,omitempty"`
	Endpoint      string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	AuthHeader    string `yaml:"auth_header,omitempty" json:"auth_header,omitempty"`
	IdentityField string `yaml:"identity_field,omitempty" json:"identity_field,omitempty"`
	ScopesHeader  string `yaml:"scopes_header,omitempty" json:"scopes_header,omitempty"`
}

// AccessLevel is one access-levels.<level> entry. Exactly one of Scopes
// (task/alias-keyed, google-style) or PATScopes (flat, github-style) is
// populated by a well-formed profile.
type AccessLevel struct {
	Scopes    map[string][]string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	PATScopes []string            `yaml:"pat_scopes,omitempty" json:"pat_scopes,omitempty"`
}

// LoginInfo is the login{} block: the re-login helper command spec 5.4's
// remediation hint points the operator at.
type LoginInfo struct {
	Helper string `yaml:"helper,omitempty" json:"helper,omitempty"`
}

// ScopesFor returns the concrete scope set access+task implies (spec
// 6.1/6.2). For a github-style profile (flat pat_scopes), task is
// ignored. For a google-style profile (scopes keyed by task/alias), an
// exact task match returns that alias's set; an empty or unrecognized
// task falls back to the union of every alias's scopes for the access
// level, so a caller that has not narrowed by task still gets an honest,
// non-empty scope-derived answer instead of silently reporting nothing.
// Returns nil if the profile has no entry for access at all.
func (p *Profile) ScopesFor(access, task string) []string {
	lvl, ok := p.AccessLevels[access]
	if !ok {
		return nil
	}
	if len(lvl.PATScopes) > 0 {
		return append([]string(nil), lvl.PATScopes...)
	}
	if len(lvl.Scopes) == 0 {
		return nil
	}
	if task != "" {
		if s, ok := lvl.Scopes[task]; ok {
			return append([]string(nil), s...)
		}
	}
	return unionScopes(lvl.Scopes)
}

func unionScopes(byTask map[string][]string) []string {
	seen := map[string]bool{}
	var out []string
	keys := make([]string, 0, len(byTask))
	for k := range byTask {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, s := range byTask[k] {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Result is the outcome of resolving platform+access(+task) against a
// Registry: the concrete scope set, and whether that set is scope-derived
// (a profile exists) or advisory (spec 6.3 generic passthrough).
type Result struct {
	Platform    string   `json:"platform"`
	AccessLevel string   `json:"access_level"`
	Scopes      []string `json:"scopes"`
	Enforcement string   `json:"enforcement"` // scope-derived | advisory
	ExecEnv     string   `json:"exec_env,omitempty"`
}

// Registry holds every loaded profile (built-in plus any user overrides),
// keyed by platform name.
type Registry struct {
	profiles map[string]*Profile
	sources  map[string]string // platform -> "builtin" | "user"
}

// NewRegistry loads the built-in profiles and, if userDir is non-empty and
// exists, merges in every *.yaml file found there. A user profile with the
// same `platform:` value as a built-in overrides it entirely (spec 6.1:
// "overrides or extends"); a user profile for a new platform extends the
// set. userDir not existing is not an error (nothing to merge).
func NewRegistry(userDir string) (*Registry, error) {
	builtin, err := loadBuiltin()
	if err != nil {
		return nil, err
	}
	user, err := loadUserDir(userDir)
	if err != nil {
		return nil, err
	}

	reg := &Registry{profiles: map[string]*Profile{}, sources: map[string]string{}}
	for name, p := range builtin {
		reg.profiles[name] = p
		reg.sources[name] = "builtin"
	}
	for name, p := range user {
		reg.profiles[name] = p
		reg.sources[name] = "user"
	}
	return reg, nil
}

// LoadDefaultRegistry builds a Registry from the built-in profiles plus
// the default user profile directory (UserProfilesDir).
func LoadDefaultRegistry() (*Registry, error) {
	dir, err := UserProfilesDir()
	if err != nil {
		return nil, err
	}
	return NewRegistry(dir)
}

// UserProfilesDir returns ~/.config/credroute/profiles, the location spec
// 6.1 designates for user-supplied profile overrides. Set
// CREDROUTE_PROFILES_DIR to override (used by tests so they never touch a
// real home directory).
func UserProfilesDir() (string, error) {
	if v := os.Getenv("CREDROUTE_PROFILES_DIR"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("scope: determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "credroute", "profiles"), nil
}

func loadBuiltin() (map[string]*Profile, error) {
	entries, err := builtinFS.ReadDir("profiles")
	if err != nil {
		return nil, fmt.Errorf("scope: read embedded profiles: %w", err)
	}
	out := map[string]*Profile{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := builtinFS.ReadFile("profiles/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("scope: read embedded profile %s: %w", e.Name(), err)
		}
		p, err := parseProfile(b)
		if err != nil {
			return nil, fmt.Errorf("scope: parse embedded profile %s: %w", e.Name(), err)
		}
		out[p.Platform] = p
	}
	return out, nil
}

func loadUserDir(dir string) (map[string]*Profile, error) {
	if dir == "" {
		return nil, nil
	}
	expanded, err := config.ExpandHome(dir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(expanded)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("scope: read user profiles dir %s: %w", expanded, err)
	}
	out := map[string]*Profile{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(expanded, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("scope: read user profile %s: %w", path, err)
		}
		p, err := parseProfile(b)
		if err != nil {
			return nil, fmt.Errorf("scope: parse user profile %s: %w", path, err)
		}
		if p.Platform == "" {
			return nil, fmt.Errorf("scope: user profile %s has no platform: field", path)
		}
		out[p.Platform] = p
	}
	return out, nil
}

func parseProfile(b []byte) (*Profile, error) {
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Get returns the profile for platform, if one is loaded (built-in or
// user).
func (r *Registry) Get(platform string) (*Profile, bool) {
	p, ok := r.profiles[platform]
	return p, ok
}

// Source reports whether platform's loaded profile came from the built-in
// set or a user override, empty if platform is not loaded at all.
func (r *Registry) Source(platform string) string {
	return r.sources[platform]
}

// List returns every loaded profile, sorted by platform name.
func (r *Registry) List() []*Profile {
	out := make([]*Profile, 0, len(r.profiles))
	for _, p := range r.profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Platform < out[j].Platform })
	return out
}

// Resolve is the D7/D10 seam: given a platform and access level (plus an
// optional task/alias tag), return the concrete scope set and whether it
// is scope-derived or advisory. An unknown platform never errors: it
// resolves as generic passthrough (spec 6.3), reporting the requested
// access level with no scopes and enforcement "advisory".
func (r *Registry) Resolve(platform, access, task string) Result {
	res := Result{Platform: platform, AccessLevel: access, Enforcement: "advisory"}
	p, ok := r.Get(platform)
	if !ok {
		return res
	}
	res.Enforcement = "scope-derived"
	res.Scopes = p.ScopesFor(access, task)
	res.ExecEnv = p.ExecEnv
	return res
}
