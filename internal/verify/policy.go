// allow-claude-code: see prober.go header.
package verify

import (
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
)

// verifyRank orders the verify modes from loosest to strictest so
// "tighten only, cannot loosen" (spec 4.1) can be computed as a max.
func verifyRank(mode string) int {
	switch mode {
	case "off":
		return 0
	case "on":
		return 2
	default:
		return 2
	}
}

// EffectiveVerifyMode combines the rule-level override, the config
// default, and the CLI --verify flag into the mode that actually governs
// one resolve/exec call. ruleVerify wins over defaultsVerify when set;
// cliFlag can only tighten the result further, never loosen it (spec 4.1:
// "--verify=on|off ... tighten only, cannot loosen config").
func EffectiveVerifyMode(cliFlag, ruleVerify, defaultsVerify string) string {
	base := ruleVerify
	if base == "" {
		base = defaultsVerify
	}
	if base == "" {
		base = "on"
	}
	if cliFlag == "" {
		return base
	}
	if verifyRank(cliFlag) > verifyRank(base) {
		return cliFlag
	}
	return base
}

// Resolve-facing verification statuses (spec 4.2's "verification.status").
// ResolveUnconfirmed (F2) reports a fingerprint-only baseline honestly,
// distinct from ResolveVerified (a prober actually confirmed the
// identity) and from ResolveUnverified (no usable sidecar at all); it is
// treated exactly like ResolveUnverified by ShouldRefuse.
const (
	ResolveVerified         = "verified"
	ResolveAcceptedBaseline = "accepted_baseline"
	ResolveUnconfirmed      = "unconfirmed"
	ResolveStale            = "stale"
	ResolveMismatch         = "mismatch"
	ResolveUnverified       = "unverified"
)

// ClassifyForResolve turns a sidecar read (rec, readErr) into the status
// resolve reports and enforces against: verified (fresh, prober-confirmed
// and matching), unconfirmed (fresh fingerprint-only baseline, identity
// never independently confirmed), stale (verified but older than maxAge),
// mismatch, or unverified (no sidecar, or one that failed its integrity
// check). maxAge <= 0 disables staleness (a verified sidecar never
// expires). currentVaultHandle is the vault handle the credential being
// resolved ACTUALLY carries right now; if the sidecar was written for a
// different handle (H2, Fable 5 review v2: sidecars for slot-carrying
// credentials are keyed by slot only, so re-pointing a slot's vault
// handle via `identity edit --add-credential` leaves the OLD handle's
// "verified" attestation readable under the same key), that is treated
// exactly like no sidecar at all rather than letting a verification
// earned by one handle silently endorse a different one. Pass "" to skip
// this check (e.g. from a caller with no current handle in hand).
func ClassifyForResolve(rec *attest.Record, readErr error, maxAge time.Duration, now time.Time, currentVaultHandle, currentIdentity, currentPlatform, currentAccess string) string {
	if readErr != nil || rec == nil {
		// Covers attest.ErrNotFound and attest.ErrTampered alike: neither
		// leaves anything a caller can trust. Spec 5.4: a tampered sidecar
		// "is treated as unreadable, forcing a live probe" - resolve
		// itself never performs that probe (see cmd/credroute/resolve.go),
		// so the safest equivalent here is to report it exactly like "no
		// sidecar at all" and let `credroute verify` supply the probe.
		return ResolveUnverified
	}
	if currentVaultHandle != "" && rec.VaultHandle != currentVaultHandle {
		return ResolveUnverified
	}
	if currentIdentity != "" && rec.ExpectedIdentity != currentIdentity {
		return ResolveUnverified
	}
	if currentPlatform != "" && rec.Platform != currentPlatform {
		return ResolveUnverified
	}
	if currentAccess != "" && rec.AccessLevel != currentAccess {
		return ResolveUnverified
	}

	switch rec.Status {
	case attest.StatusMismatch:
		return ResolveMismatch
	case attest.StatusUnreadable:
		return ResolveUnverified
	case attest.StatusAcceptedBaseline:
		return ResolveAcceptedBaseline
	case attest.StatusUnconfirmed:
		return ResolveUnconfirmed
	case attest.StatusVerified:
		if maxAge > 0 && now.Sub(rec.CheckedAt) > maxAge {
			return ResolveStale
		}
		return ResolveVerified
	default:
		return ResolveUnverified
	}
}

// ResolveStatusForAttest maps a freshly-observed attest.Status (e.g. from
// a live verify.Run just performed, as `credroute exec` does per F1/spec
// 5.2 "record reality on every path") to the resolve-facing status
// string, without needing a fresh sidecar read: the observation IS fresh
// (CheckedAt == now), so staleness never applies.
func ResolveStatusForAttest(status attest.Status) string {
	switch status {
	case attest.StatusVerified:
		return ResolveVerified
	case attest.StatusAcceptedBaseline:
		return ResolveAcceptedBaseline
	case attest.StatusUnconfirmed:
		return ResolveUnconfirmed
	case attest.StatusMismatch:
		return ResolveMismatch
	default:
		return ResolveUnverified
	}
}

// ShouldRefuse reports whether resolve/exec must fail closed given the
// effective verify mode and a resolve-facing status from
// ClassifyForResolve/ResolveStatusForAttest. "off" ignores verification.
// Under "on", a stale, mismatched, absent, or unconfirmed sidecar refuses
// until `credroute verify` clears it.
func ShouldRefuse(mode, status string) bool {
	if mode == "off" {
		return false
	}
	switch status {
	case ResolveVerified, ResolveAcceptedBaseline:
		return false
	default:
		return true
	}
}
