// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md sections 4/5) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
//
// This file holds the verification decision shared by every path that
// hands over or dereferences a secret (resolve, exec, handle get), so
// they cannot drift out of sync with one another (F1): the founding bug
// this review exists to close was exactly that drift, resolve refusing
// correctly while exec sailed a mismatched credential straight through.
package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/scope"
	"github.com/hasandenizuk/credroute/internal/verify"
)

// verifyPrecheck is the resolve-shared verification decision: the
// effective verify mode for one credential, and what its attestation
// sidecar currently says, computed WITHOUT ever touching the vault. Every
// hand-off path calls this before decrypting anything, so a mismatched or
// unconfirmed slot is refused before the secret is ever in memory.
type verifyPrecheck struct {
	Mode   string
	Status string
}

// Refuse reports whether this precheck alone is grounds to fail closed.
func (p verifyPrecheck) Refuse() bool { return verify.ShouldRefuse(p.Mode, p.Status) }

func scopeExcessDetail(platform, access, task string, observed []string) string {
	if len(observed) == 0 {
		return ""
	}
	reg, err := scope.LoadDefaultRegistry()
	if err != nil {
		return ""
	}
	expected := reg.Resolve(platform, access, task)
	if expected.Enforcement != "scope-derived" || len(expected.Scopes) == 0 {
		return ""
	}
	allowed := map[string]bool{}
	for _, s := range expected.Scopes {
		allowed[s] = true
	}
	var excess []string
	for _, s := range observed {
		if !allowed[s] {
			excess = append(excess, s)
		}
	}
	if len(excess) == 0 {
		return ""
	}
	sort.Strings(excess)
	return fmt.Sprintf("observed credential scopes exceed %s access for platform %q: %s", access, platform, strings.Join(excess, ", "))
}

// runVerifyPrecheck computes the effective verify mode from cliFlag, the
// rule's own verify override (pass "" when there is no rule in play, e.g.
// handle get), and defaults.verify, then classifies whatever the
// attestation sidecar currently says about slot/vaultHandle (KeyFor
// prefers slot; see internal/attest).
func runVerifyPrecheck(cliFlag, ruleVerify, defaultsVerify, sidecarMaxAge, slot, vaultHandle, identity, platform, access string) verifyPrecheck {
	mode := verify.EffectiveVerifyMode(cliFlag, ruleVerify, defaultsVerify)
	var maxAge time.Duration
	if sidecarMaxAge != "" {
		if parsed, err := time.ParseDuration(sidecarMaxAge); err == nil {
			maxAge = parsed
		}
	}
	rec, readErr := attest.Read(slot, vaultHandle)
	status := verify.ClassifyForResolve(rec, readErr, maxAge, time.Now().UTC(), vaultHandle, identity, platform, access)
	return verifyPrecheck{Mode: mode, Status: status}
}

// expandSlot expands "~" in a configured slot path, falling back to the
// raw value if expansion fails (matching the pattern used throughout
// resolve/exec/explain).
func expandSlot(rawSlot string) string {
	if rawSlot == "" {
		return ""
	}
	if expanded, err := rules.ExpandHome(rawSlot); err == nil {
		return expanded
	}
	return rawSlot
}

// credMatch is one identity/platform/access-level credential found by
// findCredentialMatches.
type credMatch struct {
	id, platform, access string
	cred                 config.Credential
}

var (
	errCredentialNoMatch   = fmt.Errorf("no matching credential")
	errCredentialAmbiguous = fmt.Errorf("ambiguous credential")
)

// findCredentialMatches walks every identity/platform/credential in cfg
// and collects every one for which match returns true, sorted
// deterministically by (identity, platform, access) so callers never
// depend on Go's randomized map iteration order (F3).
func findCredentialMatches(cfg *config.Config, match func(config.Credential) bool) []credMatch {
	var out []credMatch
	for id, identity := range cfg.Identities {
		for platName, plat := range identity.Platforms {
			for acc, c := range plat.Credentials {
				if match(c) {
					out = append(out, credMatch{id: id, platform: platName, access: acc, cred: c})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].id != out[j].id {
			return out[i].id < out[j].id
		}
		if out[i].platform != out[j].platform {
			return out[i].platform < out[j].platform
		}
		return out[i].access < out[j].access
	})
	return out
}

// resolveUniqueIdentity turns a set of credential matches into exactly one
// identity, or a clear error: no matches at all, or matches that span more
// than one distinct identity (F3's ambiguity case - a shared slot or
// handle claimed by two different accounts must never be resolved by
// picking one at random).
func resolveUniqueIdentity(matches []credMatch, subject string) (id, platform, access string, cred config.Credential, err error) {
	if len(matches) == 0 {
		return "", "", "", config.Credential{}, fmt.Errorf("%w: no credential in config has %s", errCredentialNoMatch, subject)
	}
	distinct := map[string]bool{}
	for _, m := range matches {
		distinct[m.id] = true
	}
	if len(distinct) > 1 {
		ids := make([]string, 0, len(distinct))
		for id := range distinct {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return "", "", "", config.Credential{}, fmt.Errorf("%w: %s is claimed by multiple identities (%s); disambiguate with --platform", errCredentialAmbiguous, subject, strings.Join(ids, ", "))
	}
	m := matches[0]
	return m.id, m.platform, m.access, m.cred, nil
}

// findCredentialBySlot searches every identity/platform/credential in cfg
// for the one(s) whose expanded slot matches expandedSlot. Used by
// `credroute verify --slot`, which (per spec 5.3's login-guard use case)
// verifies a specific slot right after a login, without needing a
// dir/platform/task context for the rule engine. F3: deterministic, and
// refuses (rather than picking arbitrarily) when the slot is legitimately
// shared by more than one identity.
func findCredentialBySlot(cfg *config.Config, expandedSlot string) (identityID, platform, access string, cred config.Credential, err error) {
	matches := findCredentialMatches(cfg, func(c config.Credential) bool {
		if c.Slot == "" {
			return false
		}
		candidate, expErr := rules.ExpandHome(c.Slot)
		return expErr == nil && candidate == expandedSlot
	})
	return resolveUniqueIdentity(matches, fmt.Sprintf("slot %q", expandedSlot))
}

// findCredentialByVaultHandle is findCredentialBySlot's counterpart for
// `credroute handle get`, which only carries a bare vault handle and no
// dir/platform/task context. Not finding a match is not necessarily an
// error at the call site: some handles are legitimately used outside the
// identities modeled in config (e.g. ad hoc/debug use), so callers decide
// whether an unmatched handle skips verification or refuses.
func findCredentialByVaultHandle(cfg *config.Config, handle string) (identityID, platform, access string, cred config.Credential, err error) {
	matches := findCredentialMatches(cfg, func(c config.Credential) bool {
		return c.Vault == handle
	})
	return resolveUniqueIdentity(matches, fmt.Sprintf("vault handle %q", handle))
}
