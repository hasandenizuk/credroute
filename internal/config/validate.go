// allow-claude-code: see config.go header.
package config

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ValidationError is one problem found by Validate. Errors are hard
// failures (non-zero exit); Warnings are reported but do not fail
// `config validate` unless strict mode is requested by the caller.
type ValidationError struct {
	Path    string // dotted path into the config, e.g. "rules[2].use.identity"
	Message string
}

func (e ValidationError) String() string {
	if e.Path == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

// ValidationResult is the outcome of Validate.
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

// OK reports whether there are no hard errors.
func (r ValidationResult) OK() bool {
	return len(r.Errors) == 0
}

var validAccessLevels = map[string]bool{
	"read-only":  true,
	"read-write": true,
}

var validCredentialTypes = map[string]bool{
	"oauth":        true,
	"api_key":      true,
	"bearer_token": true,
	"pat":          true,
}

var validVerifyModes = map[string]bool{
	"required": true,
	"advisory": true,
	"off":      true,
}

var validOnNoMatch = map[string]bool{
	"refuse": true,
}

var validVaultBackends = map[string]bool{
	"age": true,
}

// Validate runs the full strict schema + semantic check described in the
// technical spec: known-field schema (already enforced by Load's strict
// decode), enum checks, dangling references (a rule using an identity,
// platform, or access level that is not defined), and shadowed-rule
// detection (a later rule whose match set can never be reached because an
// earlier rule already covers it).
func Validate(cfg *Config) ValidationResult {
	var res ValidationResult
	addErr := func(path, format string, args ...interface{}) {
		res.Errors = append(res.Errors, ValidationError{Path: path, Message: fmt.Sprintf(format, args...)})
	}
	addWarn := func(path, format string, args ...interface{}) {
		res.Warnings = append(res.Warnings, ValidationError{Path: path, Message: fmt.Sprintf(format, args...)})
	}

	if cfg.Version != 1 {
		addErr("version", "unsupported version %d (only 1 is supported)", cfg.Version)
	}

	// defaults
	onNoMatch := cfg.Defaults.OnNoMatch
	if onNoMatch == "" {
		onNoMatch = "refuse"
	}
	if !validOnNoMatch[onNoMatch] {
		addErr("defaults.on_no_match", "unknown value %q (expected: refuse)", onNoMatch)
	}
	verify := cfg.Defaults.Verify
	if verify == "" {
		verify = "required"
	}
	if !validVerifyModes[verify] {
		addErr("defaults.verify", "unknown value %q (expected: required, advisory, off)", cfg.Defaults.Verify)
	}
	if cfg.Defaults.SidecarMaxAge != "" {
		if _, err := time.ParseDuration(cfg.Defaults.SidecarMaxAge); err != nil {
			addErr("defaults.sidecar_max_age", "invalid duration %q: %v", cfg.Defaults.SidecarMaxAge, err)
		}
	}

	// clients
	for name, c := range cfg.Clients {
		path := fmt.Sprintf("clients.%s.roots", name)
		if len(c.Roots) == 0 {
			addErr(path, "client %q defines no roots", name)
		}
		for i, root := range c.Roots {
			if strings.TrimSpace(root) == "" {
				addErr(fmt.Sprintf("%s[%d]", path, i), "empty root glob")
			}
		}
	}

	// identities
	for id, identity := range cfg.Identities {
		for platName, plat := range identity.Platforms {
			for access, cred := range plat.Credentials {
				path := fmt.Sprintf("identities.%s.platforms.%s.credentials.%s", id, platName, access)
				if !validAccessLevels[access] {
					addErr(path, "unknown access level %q (expected: read-only, read-write)", access)
				}
				if !validCredentialTypes[cred.Type] {
					addErr(path+".type", "unknown credential type %q (expected: oauth, api_key, bearer_token, pat)", cred.Type)
				}
				if strings.TrimSpace(cred.Vault) == "" {
					addErr(path+".vault", "vault handle is required")
				} else if !strings.Contains(cred.Vault, "://") {
					addErr(path+".vault", "vault handle %q is not a URI (expected scheme://path)", cred.Vault)
				}
			}
		}
	}

	// vault
	if !validVaultBackends[cfg.Vault.Backend] {
		addErr("vault.backend", "unknown backend %q (expected: age)", cfg.Vault.Backend)
	}
	if cfg.Vault.Backend == "age" {
		if strings.TrimSpace(cfg.Vault.Age.StoreDir) == "" {
			addErr("vault.age.store_dir", "required when vault.backend is age")
		}
		if strings.TrimSpace(cfg.Vault.Age.IdentityFile) == "" {
			addErr("vault.age.identity_file", "required when vault.backend is age")
		}
	}

	// store (optional)
	if cfg.Store != nil && cfg.Store.Enabled {
		if strings.TrimSpace(cfg.Store.Dir) == "" {
			addErr("store.dir", "required when store.enabled is true")
		}
	}

	// rules: ids, dangling refs, catch-all placement
	seenIDs := map[string]int{}
	for i, rule := range cfg.Rules {
		path := fmt.Sprintf("rules[%d]", i)
		if strings.TrimSpace(rule.ID) == "" {
			addErr(path+".id", "rule id is required")
		} else if prev, ok := seenIDs[rule.ID]; ok {
			addErr(path+".id", "duplicate rule id %q (first defined at rules[%d])", rule.ID, prev)
		} else {
			seenIDs[rule.ID] = i
		}

		if rule.Match.IsEmpty() && i != len(cfg.Rules)-1 {
			addErr(path+".match", "empty match block (catch-all) is only legal as the final rule")
		}

		if rule.Match.Client != "" {
			if _, ok := cfg.Clients[rule.Match.Client]; !ok {
				addErr(path+".match.client", "references undefined client %q", rule.Match.Client)
			}
		}

		if strings.TrimSpace(rule.Use.Identity) == "" {
			addErr(path+".use.identity", "identity is required")
		}
		identity, identityOK := cfg.Identities[rule.Use.Identity]
		if rule.Use.Identity != "" && !identityOK {
			addErr(path+".use.identity", "references undefined identity %q", rule.Use.Identity)
		}

		if rule.Use.Access != "" && !validAccessLevels[rule.Use.Access] {
			addErr(path+".use.access", "unknown access level %q (expected: read-only, read-write)", rule.Use.Access)
		}

		if rule.Use.Verify != "" && !validVerifyModes[rule.Use.Verify] {
			addErr(path+".use.verify", "unknown value %q (expected: required, advisory, off)", rule.Use.Verify)
		}

		// Cross-check identity has a matching platform/access-level
		// credential. Only possible when the rule names exactly one
		// platform; a wildcard or multi-platform match can't be checked
		// without knowing which platform a caller will ask for.
		if identityOK && rule.Use.Access != "" && len(rule.Match.Platform) == 1 {
			platName := rule.Match.Platform[0]
			plat, hasPlat := identity.Platforms[platName]
			if !hasPlat {
				addErr(path, "identity %q has no platform %q, but the rule targets it", rule.Use.Identity, platName)
			} else if _, hasCred := plat.Credentials[rule.Use.Access]; !hasCred {
				addErr(path, "identity %q has no %q credential for platform %q", rule.Use.Identity, rule.Use.Access, platName)
			}
		}
	}

	// shadowed-rule detection
	for j := 1; j < len(cfg.Rules); j++ {
		for i := 0; i < j; i++ {
			if ruleShadows(cfg.Rules[i], cfg.Rules[j]) {
				addWarn(fmt.Sprintf("rules[%d]", j), "rule %q is shadowed by earlier rule %q (rules[%d]) and can never match", cfg.Rules[j].ID, cfg.Rules[i].ID, i)
				break
			}
		}
	}

	sort.Slice(res.Errors, func(a, b int) bool { return res.Errors[a].Path < res.Errors[b].Path })

	return res
}

// ruleShadows reports whether every request matching rule b would already
// have matched rule a, making b unreachable when a precedes it.
//
// This is a conservative, equality-based heuristic, not full glob
// subsumption: for each condition rule a sets, rule b must set the exact
// same condition (same client, same dir pattern string, same platform
// set, same task set). A condition rule a omits is a wildcard and imposes
// no requirement on b. This catches exact duplicates and "later rule adds
// nothing new" cases; it does NOT prove subsumption between two
// different-but-overlapping globs (e.g. client sugar vs. an equivalent
// dir glob), which is left as a known limitation.
func ruleShadows(a, b Rule) bool {
	if a.Match.Client != "" && a.Match.Client != b.Match.Client {
		return false
	}
	if a.Match.Dir != "" && a.Match.Dir != b.Match.Dir {
		return false
	}
	if len(a.Match.Platform) > 0 && !sameStringSet(a.Match.Platform, b.Match.Platform) {
		return false
	}
	if len(a.Match.Task) > 0 && !sameStringSet(a.Match.Task, b.Match.Task) {
		return false
	}
	// a matches everything b would match. If a's action differs from b's,
	// b is still unreachable (dead), which is exactly what we want to flag.
	return true
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
