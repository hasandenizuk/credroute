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
	// Include lists additional config files to merge into this one
	// (F11). Paths are relative to this file's own directory unless
	// absolute or "~"-prefixed. Processed by Load; see mergeInclude for
	// the merge policy. Nested includes (an included file that itself
	// sets include:) are not supported and are a load error.
	Include []string `yaml:"include,omitempty"`

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
	// SidecarMaxAge is a Go duration string, e.g. "24h". Consumed by
	// resolve/exec (internal/verify.ClassifyForResolve) to decide when a
	// verified sidecar is too old to substitute for a live probe.
	SidecarMaxAge string `yaml:"sidecar_max_age"`
}

// Client is one entry under clients{}: a named set of root globs.
type Client struct {
	Roots []string `yaml:"roots"`
}

// Identity is one entry under identities{}: a real account, keyed by its
// map key (usually an email) in the parent Config.Identities map.
type Identity struct {
	Label string `yaml:"label"`
	// Platforms is omitempty so `identity add` can create an identity with
	// no platforms yet (added afterwards via `identity edit
	// --add-credential`) without rendering a stray "platforms: {}".
	Platforms map[string]Platform `yaml:"platforms,omitempty"`
}

// Platform is one entry under identities.<id>.platforms{}.
type Platform struct {
	// Credentials is omitempty for the same reason as Identity.Platforms.
	Credentials map[string]Credential `yaml:"credentials,omitempty"`
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
	// Verify overrides defaults.verify for this rule only: "required",
	// "advisory", or "off" (milestone 2, spec 5.2/5.4). Empty inherits
	// defaults.verify. The CLI --verify flag layered on top of whichever
	// of these applies can only tighten further, never loosen (spec 4.1).
	Verify string `yaml:"verify,omitempty"`
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

// resolvedPath applies the F10 precedence (--config flag > CREDROUTE_CONFIG
// env > default) for an explicit path argument that may be empty.
func resolvedPath(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	if env := os.Getenv("CREDROUTE_CONFIG"); env != "" {
		return env, nil
	}
	return DefaultPath()
}

// ResolvedPath is the exported form of resolvedPath: it applies the exact
// same precedence (--config flag > CREDROUTE_CONFIG env > DefaultPath())
// that Load and OpenDocument use internally, for callers that need the
// resolved location before the file necessarily exists (H1, Fable 5
// review v2: `credroute init` used to resolve an empty path via
// DefaultPath() alone, skipping CREDROUTE_CONFIG, which let it scaffold
// or --force-overwrite the wrong file relative to every other command).
func ResolvedPath(path string) (string, error) {
	return resolvedPath(path)
}

// Load reads and strictly parses the config at path (see resolvedPath for
// how an empty path is resolved), merging any include: files it names
// (F11). Unknown YAML fields are a hard error (KnownFields). Load does not
// run semantic validation (see Validate); it only parses.
func Load(path string) (*Config, error) {
	resolved, err := resolvedPath(path)
	if err != nil {
		return nil, err
	}

	cfg, err := loadOne(resolved)
	if err != nil {
		return nil, err
	}
	if len(cfg.Include) == 0 {
		return cfg, nil
	}

	baseDir := filepath.Dir(cfg.Path)
	seen := map[string]bool{cfg.Path: true}
	for _, inc := range cfg.Include {
		incPath, err := resolveIncludePath(baseDir, inc)
		if err != nil {
			return nil, fmt.Errorf("config %s: include %q: %w", cfg.Path, inc, err)
		}
		if seen[incPath] {
			return nil, fmt.Errorf("config %s: include %q resolves to %s, which is already included (circular or duplicate include)", cfg.Path, inc, incPath)
		}
		seen[incPath] = true

		incCfg, err := loadOne(incPath)
		if err != nil {
			return nil, fmt.Errorf("config %s: include %q: %w", cfg.Path, inc, err)
		}
		if len(incCfg.Include) > 0 {
			return nil, fmt.Errorf("config %s: include %q (%s): nested include: is not supported", cfg.Path, inc, incPath)
		}
		if err := mergeInclude(cfg, incCfg, incPath); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// loadOne parses exactly one config file at an already-resolved absolute
// (or relative-to-cwd) path, without following its include: list.
func loadOne(path string) (*Config, error) {
	expanded, err := ExpandHome(path)
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

// resolveIncludePath resolves one include: entry relative to baseDir
// (the including file's own directory), honoring "~" and absolute paths.
func resolveIncludePath(baseDir, inc string) (string, error) {
	expanded, err := ExpandHome(inc)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(expanded) {
		return expanded, nil
	}
	return filepath.Join(baseDir, expanded), nil
}

// mergeInclude folds src (a loaded include: file) into dst (the config
// that named it). Policy, deliberately simple and fail-closed rather than
// silently shadowing: clients/identities are unioned by key, and a key
// defined in both dst and src is a hard error rather than a silent
// overwrite in either direction. Rules from src are appended after dst's
// own rules, so the including file's rules always take precedence under
// first-match-wins, and an include only ever adds fallback/extra rules.
// defaults/vault/store are never merged: they belong to the top-level
// file only.
func mergeInclude(dst, src *Config, srcPath string) error {
	for name, c := range src.Clients {
		if _, exists := dst.Clients[name]; exists {
			return fmt.Errorf("include %s: client %q is already defined in %s", srcPath, name, dst.Path)
		}
		if dst.Clients == nil {
			dst.Clients = map[string]Client{}
		}
		dst.Clients[name] = c
	}
	for id, identity := range src.Identities {
		if _, exists := dst.Identities[id]; exists {
			return fmt.Errorf("include %s: identity %q is already defined in %s", srcPath, id, dst.Path)
		}
		if dst.Identities == nil {
			dst.Identities = map[string]Identity{}
		}
		dst.Identities[id] = identity
	}
	dst.Rules = append(dst.Rules, src.Rules...)
	return nil
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
