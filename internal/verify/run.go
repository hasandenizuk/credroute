// allow-claude-code: see prober.go header.
package verify

import (
	"context"
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

// Outcome is the human/JSON-facing result of one Run call.
type Outcome struct {
	Status           attest.Status
	ObservedIdentity string
	Method           string
	Fingerprint      string
	ObservedScopes   []string
	Detail           string
	// PriorStatus is the status recorded before this run, empty if there
	// was no usable prior sidecar (none written yet, or it failed its
	// integrity check).
	PriorStatus attest.Status
}

// Run probes req's secret, compares the observation to req.ExpectedIdentity
// (or, when the chosen prober cannot name an identity, to the fingerprint
// recorded by the prior attestation), and writes the result to the
// attestation sidecar unconditionally, on every path: verified, mismatch,
// or unreadable (spec 5.2). A probe failure is recorded as unreadable and
// is never treated as success (closes the fail-open audit finding).
func Run(ctx context.Context, req Request, reg *Registry) (Outcome, error) {
	if req.Secret == nil {
		return Outcome{}, fmt.Errorf("verify: request has no secret to probe")
	}

	var fingerprint string
	if err := req.Secret.WithBytes(func(b []byte) error {
		fingerprint = vault.FingerprintBytes(b)
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
		// The prober named a real identity: compare directly.
		rec.ObservedIdentity = observedIdentity
		rec.ObservedScopes = scopes
		outcome.ObservedIdentity = observedIdentity
		outcome.ObservedScopes = scopes
		if observedIdentity == req.ExpectedIdentity {
			rec.Status = attest.StatusVerified
			outcome.Status = attest.StatusVerified
		} else {
			rec.Status = attest.StatusMismatch
			outcome.Status = attest.StatusMismatch
			outcome.Detail = fmt.Sprintf("expected identity %q, observed %q", req.ExpectedIdentity, observedIdentity)
		}

	default:
		// Fingerprint-only method: the prober cannot name an account, so
		// the only evidence is whether the secret bytes changed since the
		// last attestation.
		switch {
		case prior != nil && prior.Fingerprint != "":
			if prior.Fingerprint == fingerprint {
				rec.Status = attest.StatusVerified
				outcome.Status = attest.StatusVerified
			} else {
				rec.Status = attest.StatusMismatch
				outcome.Status = attest.StatusMismatch
				outcome.Detail = "secret fingerprint changed since the last attestation (identity not independently confirmed: fingerprint-only method)"
			}
		default:
			// No usable prior fingerprint: this is the first observation,
			// so it establishes the trusted baseline. It is honestly
			// weaker than an identity-naming probe (recorded method stays
			// "fingerprint"), but there is no contradiction to report.
			rec.Status = attest.StatusVerified
			outcome.Status = attest.StatusVerified
			if priorDetail != "" {
				outcome.Detail = priorDetail
			}
		}
	}

	if writeErr := attest.Write(rec); writeErr != nil {
		return outcome, fmt.Errorf("verify: record attestation: %w", writeErr)
	}
	return outcome, nil
}
