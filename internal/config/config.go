// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md) for this exact
// multi-file build; mechanical translation of spec to Go, low ambiguity.
//
// Package config loads and represents the credroute YAML configuration:
// clients, identities, credentials, rules, and vault settings.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the top-level credroute configuration document.
type Config struct {
	Version    int                 `yaml:"version"`
	Defaults   Defaults            `yaml:"defaults"`
	Clients    map[string]Client   `yaml:"clients"`
	Identities map[string]Identity `yaml:"identities"`
	Rules      []Rule              `yaml:"rules"`
	Vault      VaultConfig         `yaml:"vault"`
	Store      *StoreConfig        `yaml:"store,omitempty"`

	// Path is the absolute path the config was loaded from. Not part of
	// the YAML document; set by Load for error messages and doctor checks.
	Path string `yaml:"-"`
}

// Defaults holds the defaults{} block.
type Defaults struct {
	// OnNoMatch controls behavior when no rule matches. v1 only supports
	// "refuse" (fail closed); the field is kept as a string so a future
	// value can be added without a schema break.
	OnNoMatch string `yaml:"on_no_match"`
	// Verify is one of "required", "advisory", "off".
	Verify string `yaml:"verify"`
	// SidecarMaxAge is a Go duration string, e.g. "24h". Milestone 2
	// (verify-in-slot) consumes this; milestone 1 only validates it parses.
	SidecarMaxAge string `yaml:"sidecar_max_age"`
}

// Client is one entry under clients{}: a named set of root globs.
type Client struct {
	Roots []string `yaml:"roots"`
}

// Identity is one entry under identities{}: a real account, keyed by its
// map key (usually an email) in the parent Config.Identities map.
type Identity struct {
	Label     string              `yaml:"label"`
	Platforms map[string]Platform `yaml:"platforms"`
}

// Platform is one entry under identities.<id>.platforms{}.
type Platform struct {
	Credentials map[string]Credential `yaml:"credentials"`
}

// Credential is one entry under platforms.<name>.credentials{}, keyed by
// access level ("read-only" / "read-write") in the parent Platform map.
type Credential struct {
	Type  string `yaml:"type"`  // oauth | api_key | bearer_token | pat
	Vault string `yaml:"vault"` // vault handle URI, e.g. age://github/me/pat.age
	Slot  string `yaml:"slot,omitempty"`
}

// Rule is one ordered entry under rules[].
type Rule struct {
	ID    string    `yaml:"id"`
	Match RuleMatch `yaml:"match"`
	Use   RuleUse   `yaml:"use"`
}

// RuleMatch is the match{} block of a rule. All present fields must hold
// (AND). An omitted field is a wildcard.
type RuleMatch struct {
	Client   string       `yaml:"client,omitempty"`
	Dir      string       `yaml:"dir,omitempty"`
	Platform StringOrList `yaml:"platform,omitempty"`
	Task     StringOrList `yaml:"task,omitempty"`
}

// IsEmpty reports whether this match block has no conditions at all
// (a catch-all rule).
func (m RuleMatch) IsEmpty() bool {
	return m.Client == "" && m.Dir == "" && len(m.Platform) == 0 && len(m.Task) == 0
}

// RuleUse is the use{} block of a rule: which identity, at which access
// level.
type RuleUse struct {
	Identity string `yaml:"identity"`
	Access   string `yaml:"access"` // read-only | read-write
}

// VaultConfig is the vault{} block.
type VaultConfig struct {
	Backend string    `yaml:"backend"` // only "age" is implemented in v1
	Age     AgeConfig `yaml:"age"`
}

// AgeConfig is the vault.age{} block.
type AgeConfig struct {
	StoreDir     string `yaml:"store_dir"`
	IdentityFile string `yaml:"identity_file"`
}

// StoreConfig is the optional store{} block (thin secret store). Milestone
// 1 loads and validates it but the age backend never writes.
type StoreConfig struct {
	Enabled bool   `yaml:"enabled"`
	Dir     string `yaml:"dir"`
}

// StringOrList unmarshals a YAML scalar or a YAML sequence of scalars into
// a []string. Used for match.platform and match.task, which the spec
// allows to be a single string or a list.
type StringOrList []string

// UnmarshalYAML implements custom decoding for StringOrList.
func (s *StringOrList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var single string
		if err := value.Decode(&single); err != nil {
			return err
		}
		if single == "" {
			*s = nil
			return nil
		}
		*s = []string{single}
		return nil
	case yaml.SequenceNode:
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		*s = list
		return nil
	case 0:
		*s = nil
		return nil
	default:
		return fmt.Errorf("expected a string or a list of strings, got %v", value.Kind)
	}
}

// MarshalYAML implements custom encoding for StringOrList so a
// single-element list round-trips as a scalar.
func (s StringOrList) MarshalYAML() (interface{}, error) {
	if len(s) == 1 {
		return s[0], nil
	}
	return []string(s), nil
}

// DefaultPath returns the default config path: ~/.config/credroute/config.yaml.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "credroute", "config.yaml"), nil
}

// Load reads and strictly parses the config at path. An empty path uses
// DefaultPath(). Unknown YAML fields are a hard error (KnownFields).
// Load does not run semantic validation (see Validate); it only parses.
func Load(path string) (*Config, error) {
	resolved := path
	if resolved == "" {
		p, err := DefaultPath()
		if err != nil {
			return nil, err
		}
		resolved = p
	}
	expanded, err := ExpandHome(resolved)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(expanded)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", expanded, err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", expanded, err)
	}
	cfg.Path = expanded
	return &cfg, nil
}

// ExpandHome expands a leading "~" or "~/" in p to the current user's home
// directory. Paths without a leading "~" are returned unchanged (after
// filepath.Clean is left to the caller, since globs must not be cleaned
// the same way as plain paths).
func ExpandHome(p string) (string, error) {
	if p == "" {
		return p, nil
	}
	if p != "~" && !hasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	if p == "~" {
		return home, nil
	}
	return filepath.Join(home, p[2:]), nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
