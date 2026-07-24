// allow-claude-code: see prober.go header.
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/vault"
)

// Request bundles everything Run needs to attest one credential's slot.
type Request struct {
	Platform         string
	CredentialType   string // oauth | api_key | bearer_token | pat
	ExpectedIdentity string
	VaultHandle      string
	Slot             string // may be empty for slotless credentials
	Secret           *vault.Secret
	CheckedBy        string
}

// allow-claude-code: see prober.go header.
// Outcome is the human/JSON-facing result of one Run call.
type Outcome struct {
	Status attest.Status
	// IdentityConfirmed mirrors attest.Record.IdentityConfirmed (F2): true
	// only when a prober actually named the identity and it matched.
	IdentityConfirmed bool
	ObservedIdentity  string
	Method            string
	Fingerprint       string
	ObservedScopes    []string
	Detail            string
	// PriorStatus is the status recorded before this run, empty if there
	// was no usable prior sidecar (none written yet, or it failed its
	// integrity check).
	PriorStatus attest.Status
}

// Run probes req's secret, compares the observation to req.ExpectedIdentity
// (or, when the chosen prober cannot name an identity, to the fingerprint
// recorded by the prior attestation), and writes the result to the
// attestation sidecar unconditionally, on every path: verified,
// unconfirmed, mismatch, or unreadable (spec 5.2). A probe failure is
// recorded as unreadable and is never treated as success (closes the
// fail-open audit finding). F2: a fingerprint-only observation (no
// identity-naming prober available) is never recorded as "verified" -
// that status is reserved for a prober that actually confirmed the
// account; an unchanged or first-time fingerprint records "unconfirmed"
// instead, and only a *changed* fingerprint escalates to "mismatch" (the
// fingerprint change-detection guard stays on top of the honest status).
func Run(ctx context.Context, req Request, reg *Registry) (Outcome, error) {
	if req.Secret == nil {
		return Outcome{}, fmt.Errorf("verify: request has no secret to probe")
	}

	var fingerprint string
	if err := req.Secret.WithBytes(func(b []byte) error {
		fingerprint = fingerprintForCredential(req.CredentialType, b)
		return nil
	}); err != nil {
		return Outcome{}, fmt.Errorf("verify: fingerprint secret: %w", err)
	}

	prior, priorErr := attest.Read(req.Slot, req.VaultHandle)
	var priorStatus attest.Status
	priorDetail := ""
	if priorErr == nil && prior != nil {
		priorStatus = prior.Status
	} else if attest.IsTampered(priorErr) {
		// Spec 5.4: a sidecar that fails HMAC is treated as unreadable and
		// forces re-verification from scratch, never as evidence either
		// way. prior stays nil so the comparison below runs as if this
		// were the first attestation.
		priorDetail = "prior sidecar failed integrity check (edited or foreign-machine); ignored, re-establishing baseline"
		prior = nil
	}
	// attest.ErrNotFound (or any other read error) also leaves prior nil,
	// which is handled the same way: nothing trustworthy to compare
	// against yet.

	prober := reg.Best(req.Platform)
	observedIdentity, scopes, probeErr := prober.Probe(ctx, req.Secret, req.Platform)
	method := prober.Method()

	rec := &attest.Record{
		Slot:             req.Slot,
		VaultHandle:      req.VaultHandle,
		ExpectedIdentity: req.ExpectedIdentity,
		Method:           method,
		Fingerprint:      fingerprint,
		CheckedAt:        time.Now().UTC(),
		CheckedBy:        req.CheckedBy,
	}

	outcome := Outcome{
		Method:      method,
		Fingerprint: fingerprint,
		PriorStatus: priorStatus,
	}

	switch {
	case probeErr != nil:
		// A live probe that errors is an unreadable observation, not a
		// pass: the credential's real state is unknown, so it must not be
		// allowed to satisfy "required" verification.
		rec.Status = attest.StatusUnreadable
		outcome.Status = attest.StatusUnreadable
		outcome.Detail = probeErr.Error()

	case observedIdentity != "":
		// The prober named a real identity: compare directly. This is the
		// only branch that can ever produce StatusVerified (F2).
		rec.ObservedIdentity = observedIdentity
		rec.ObservedScopes = scopes
		outcome.ObservedIdentity = observedIdentity
		outcome.ObservedScopes = scopes
		if observedIdentity == req.ExpectedIdentity {
			rec.Status = attest.StatusVerified
			rec.IdentityConfirmed = true
			outcome.Status = attest.StatusVerified
			outcome.IdentityConfirmed = true
		} else {
			rec.Status = attest.StatusMismatch
			outcome.Status = attest.StatusMismatch
			outcome.Detail = fmt.Sprintf("expected identity %q, observed %q", req.ExpectedIdentity, observedIdentity)
		}

	default:
		// Fingerprint-only method: the prober cannot name an account, so
		// the only evidence is whether the secret bytes changed since the
		// last attestation. Identity itself is never confirmed here
		// (F2): the honest status caps at "unconfirmed", never
		// "verified", regardless of whether the fingerprint matched.
		switch {
		case prior != nil && prior.Fingerprint != "" && prior.Fingerprint != fingerprint:
			rec.Status = attest.StatusMismatch
			outcome.Status = attest.StatusMismatch
			outcome.Detail = "secret fingerprint changed since the last attestation (identity not independently confirmed: fingerprint-only method)"
		default:
			rec.Status = attest.StatusUnconfirmed
			outcome.Status = attest.StatusUnconfirmed
			outcome.Detail = "identity not confirmed: fingerprint-only method, no identity-naming prober available for this platform"
			if priorDetail != "" {
				outcome.Detail = priorDetail + "; " + outcome.Detail
			}
		}
	}

	if writeErr := attest.Write(rec); writeErr != nil {
		return outcome, fmt.Errorf("verify: record attestation: %w", writeErr)
	}
	return outcome, nil
}

// oauthStableFields is the subset of an OAuth credential's JSON blob that
// stays constant across a normal token refresh (F7): refresh_token is the
// account-scoped, long-lived field every gws/Google-style credential
// carries, so it is tried first. A blob with no refresh_token (e.g. an
// access-token-only credential, which cannot itself detect a swap this
// way) falls back to whatever stable account identifier is present.
type oauthStableFields struct {
	RefreshToken string `json:"refresh_token"`
	Email        string `json:"email"`
	Account      string `json:"account"`
	Sub          string `json:"sub"`
}

// fingerprintForCredential computes the attestation fingerprint for raw
// secret bytes. For credential type "oauth" it fingerprints only the
// stable, identity-bearing fields of the credential JSON (F7:
// refresh_token, falling back to email/account/sub) rather than the whole
// blob, so a normal access-token refresh - which rotates access_token and
// expiry on every use - is never mistaken for the secret having been
// swapped out from under the slot. Every other credential type, and any
// oauth blob that fails to parse or carries none of those fields,
// fingerprints the raw bytes unchanged (the original, and still correct,
// behavior for non-rotating secrets like a PAT or API key).
func fingerprintForCredential(credentialType string, raw []byte) string {
	if credentialType == "oauth" {
		var f oauthStableFields
		if err := json.Unmarshal(raw, &f); err == nil {
			switch {
			case f.RefreshToken != "":
				return vault.FingerprintBytes([]byte("refresh_token:" + f.RefreshToken))
			case f.Email != "":
				return vault.FingerprintBytes([]byte("email:" + f.Email))
			case f.Account != "":
				return vault.FingerprintBytes([]byte("account:" + f.Account))
			case f.Sub != "":
				return vault.FingerprintBytes([]byte("sub:" + f.Sub))
			}
		}
	}
	return vault.FingerprintBytes(raw)
}
