// allow-claude-code: see prober.go header.
package verify

import (
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
)

// verifyRank orders the three verify modes from loosest to strictest so
// "tighten only, cannot loosen" (spec 4.1) can be computed as a max.
func verifyRank(mode string) int {
	switch mode {
	case "off":
		return 0
	case "advisory":
		return 1
	case "required":
		return 2
	default:
		// Empty or unrecognized: treat as the middle ground rather than
		// silently granting either extreme. Validated config never
		// reaches here with an unrecognized non-empty value; config.Validate
		// rejects that upstream.
		return 1
	}
}

// EffectiveVerifyMode combines the rule-level override, the config
// default, and the CLI --verify flag into the mode that actually governs
// one resolve/exec call. ruleVerify wins over defaultsVerify when set;
// cliFlag can only tighten the result further, never loosen it (spec 4.1:
// "--verify=required|advisory|off ... tighten only, cannot loosen config").
func EffectiveVerifyMode(cliFlag, ruleVerify, defaultsVerify string) string {
	base := ruleVerify
	if base == "" {
		base = defaultsVerify
	}
	if base == "" {
		base = "required"
	}
	if cliFlag == "" {
		return base
	}
	if verifyRank(cliFlag) > verifyRank(base) {
		return cliFlag
	}
	return base
}

// Resolve-facing verification statuses (spec 4.2's "verification.status",
// milestone 2 scope: verified, stale, mismatch, unverified).
const (
	ResolveVerified   = "verified"
	ResolveStale      = "stale"
	ResolveMismatch   = "mismatch"
	ResolveUnverified = "unverified"
)

// ClassifyForResolve turns a sidecar read (rec, readErr) into the status
// resolve reports and enforces against: verified (fresh and matching),
// stale (verified but older than maxAge), mismatch, or unverified (no
// sidecar, or one that failed its integrity check). maxAge <= 0 disables
// staleness (a verified sidecar never expires).
func ClassifyForResolve(rec *attest.Record, readErr error, maxAge time.Duration, now time.Time) string {
	if readErr != nil || rec == nil {
		// Covers attest.ErrNotFound and attest.ErrTampered alike: neither
		// leaves anything a caller can trust. Spec 5.4: a tampered sidecar
		// "is treated as unreadable, forcing a live probe" - resolve
		// itself never performs that probe (see cmd/credroute/resolve.go),
		// so the safest equivalent here is to report it exactly like "no
		// sidecar at all" and let `credroute verify` supply the probe.
		return ResolveUnverified
	}

	switch rec.Status {
	case attest.StatusMismatch:
		return ResolveMismatch
	case attest.StatusUnreadable:
		return ResolveUnverified
	case attest.StatusVerified:
		if maxAge > 0 && now.Sub(rec.CheckedAt) > maxAge {
			return ResolveStale
		}
		return ResolveVerified
	default:
		return ResolveUnverified
	}
}

// ShouldRefuse reports whether resolve/exec must fail closed (spec exit
// code 3) given the effective verify mode and a resolve-facing status from
// ClassifyForResolve. Only "required" ever refuses; "advisory" reports the
// status but proceeds, and "off" ignores verification entirely (spec
// 5.4/4.3). Under "required", a stale sidecar no longer substitutes for a
// live probe (spec: "sidecar_max_age bounds how long a verified sidecar
// substitutes for a live probe"), so it refuses exactly like mismatch or
// unverified until a fresh `credroute verify` clears it.
func ShouldRefuse(mode, status string) bool {
	if mode != "required" {
		return false
	}
	switch status {
	case ResolveMismatch, ResolveUnverified, ResolveStale:
		return true
	default:
		return false
	}
}
