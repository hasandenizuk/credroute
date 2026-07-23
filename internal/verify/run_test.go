// allow-claude-code: see prober.go header.
package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/vault"
)

func TestRun_FirstAttestation_FingerprintOnly_EstablishesBaseline(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	req := Request{
		Platform:         "github",
		CredentialType:   "pat",
		ExpectedIdentity: "alex@example.com",
		VaultHandle:      "age://github/alex/pat.age",
		Secret:           vault.NewSecret([]byte("initial-pat-value")),
	}
	out, err := Run(context.Background(), req, NewRegistry(false))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Status != attest.StatusVerified {
		t.Fatalf("Status = %q, want verified for a first-time fingerprint baseline", out.Status)
	}
	if out.Method != "fingerprint" {
		t.Fatalf("Method = %q, want fingerprint", out.Method)
	}

	rec, err := attest.Read("", req.VaultHandle)
	if err != nil {
		t.Fatalf("attest.Read after Run: %v", err)
	}
	if rec.Status != attest.StatusVerified {
		t.Fatalf("recorded status = %q, want verified", rec.Status)
	}
	if rec.Fingerprint == "" {
		t.Fatal("recorded fingerprint is empty")
	}
}

func TestRun_FingerprintChange_IsMismatch(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	handle := "age://google/reports-acme-corp-com/gsc-ro.json.age"
	slot := t.TempDir() // an existing directory, exercising the mirror path too

	first := Request{
		Platform:         "google",
		CredentialType:   "oauth",
		ExpectedIdentity: "reports@acme-corp.com",
		VaultHandle:      handle,
		Slot:             slot,
		Secret:           vault.NewSecret([]byte("original-oauth-json-blob")),
	}
	out1, err := Run(context.Background(), first, NewRegistry(false))
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if out1.Status != attest.StatusVerified {
		t.Fatalf("first Run status = %q, want verified (establishes baseline)", out1.Status)
	}

	// Simulate exactly the origin bug: the slot's secret silently changes
	// (an expired client login overwritten by a different login).
	second := Request{
		Platform:         "google",
		CredentialType:   "oauth",
		ExpectedIdentity: "reports@acme-corp.com",
		VaultHandle:      handle,
		Slot:             slot,
		Secret:           vault.NewSecret([]byte("a-completely-different-oauth-json-blob")),
	}
	out2, err := Run(context.Background(), second, NewRegistry(false))
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if out2.Status != attest.StatusMismatch {
		t.Fatalf("second Run status = %q, want mismatch after the secret changed", out2.Status)
	}
	if out2.PriorStatus != attest.StatusVerified {
		t.Fatalf("PriorStatus = %q, want verified (the prior baseline)", out2.PriorStatus)
	}

	// Reality must be recorded, not the old label: read the sidecar back
	// and confirm it now says mismatch, not a stale "verified".
	rec, err := attest.Read(slot, handle)
	if err != nil {
		t.Fatalf("attest.Read after second Run: %v", err)
	}
	if rec.Status != attest.StatusMismatch {
		t.Fatalf("sidecar status after mismatch = %q, want mismatch (a stale label must not survive)", rec.Status)
	}

	// The mirror copy next to the slot must also reflect reality.
	mirrored := filepath.Join(slot, ".credroute-attest.json")
	if _, statErr := os.Stat(mirrored); statErr != nil {
		t.Fatalf("expected mirrored sidecar: %v", statErr)
	}
}

func TestRun_ProbeFailure_IsUnreadable_NeverSuccess(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	reg := NewRegistry(false)
	reg.Register("google", failingProber{})

	req := Request{
		Platform:         "google",
		ExpectedIdentity: "alex@example.com",
		VaultHandle:      "age://google/x.age",
		Secret:           vault.NewSecret([]byte("some-oauth-blob")),
	}
	out, err := Run(context.Background(), req, reg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Status != attest.StatusUnreadable {
		t.Fatalf("Status = %q, want unreadable when the probe itself errors", out.Status)
	}
	if out.Detail == "" {
		t.Fatal("expected a detail message explaining the probe failure")
	}

	rec, err := attest.Read("", req.VaultHandle)
	if err != nil {
		t.Fatalf("attest.Read: %v", err)
	}
	if rec.Status != attest.StatusUnreadable {
		t.Fatalf("recorded status = %q, want unreadable", rec.Status)
	}
}

func TestRun_IdentityMatch_Verified(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	reg := NewRegistry(false)
	reg.Register("google", namingProber{identity: "reports@acme-corp.com", scopes: []string{"scope-a"}})

	req := Request{
		Platform:         "google",
		ExpectedIdentity: "reports@acme-corp.com",
		VaultHandle:      "age://google/y.age",
		Secret:           vault.NewSecret([]byte("blob")),
	}
	out, err := Run(context.Background(), req, reg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Status != attest.StatusVerified {
		t.Fatalf("Status = %q, want verified", out.Status)
	}
	if out.ObservedIdentity != "reports@acme-corp.com" {
		t.Fatalf("ObservedIdentity = %q", out.ObservedIdentity)
	}
}

func TestRun_IdentityMismatch(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	reg := NewRegistry(false)
	reg.Register("google", namingProber{identity: "wrong-person@example.com"})

	req := Request{
		Platform:         "google",
		ExpectedIdentity: "reports@acme-corp.com",
		VaultHandle:      "age://google/z.age",
		Secret:           vault.NewSecret([]byte("blob")),
	}
	out, err := Run(context.Background(), req, reg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Status != attest.StatusMismatch {
		t.Fatalf("Status = %q, want mismatch", out.Status)
	}
}

func TestRun_TamperedPriorSidecar_ReestablishesBaseline(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	handle := "age://github/bot/pat.age"
	req := Request{
		Platform:         "github",
		ExpectedIdentity: "bot@bluesky.io",
		VaultHandle:      handle,
		Secret:           vault.NewSecret([]byte("pat-value")),
	}
	if _, err := Run(context.Background(), req, NewRegistry(false)); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	// Hand-tamper the sidecar without recomputing its HMAC: flip an actual
	// field's value (appending an unknown JSON key would be silently
	// dropped by json.Unmarshal and would not change the record at all).
	path, err := attest.SidecarPath(attest.KeyFor("", handle))
	if err != nil {
		t.Fatalf("SidecarPath: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	var onDisk map[string]interface{}
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatalf("unmarshal sidecar: %v", err)
	}
	onDisk["expected_identity"] = "someone-else@example.com"
	tampered, err := json.Marshal(onDisk)
	if err != nil {
		t.Fatalf("marshal tampered sidecar: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered sidecar: %v", err)
	}

	req2 := Request{
		Platform:         "github",
		ExpectedIdentity: "bot@bluesky.io",
		VaultHandle:      handle,
		Secret:           vault.NewSecret([]byte("pat-value")), // unchanged
	}
	out, err := Run(context.Background(), req2, NewRegistry(false))
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	// A tampered prior must never be trusted as evidence of anything; Run
	// re-establishes a fresh baseline rather than either silently passing
	// or blaming the (unrelated) current secret.
	if out.Status != attest.StatusVerified {
		t.Fatalf("Status after tampered-prior recovery = %q, want verified (fresh baseline)", out.Status)
	}
	if out.Detail == "" {
		t.Fatal("expected Detail to note the tampered prior was ignored")
	}
}

type failingProber struct{}

func (failingProber) Method() string { return "oauth_probe" }
func (failingProber) Probe(_ context.Context, _ *vault.Secret, _ string) (string, []string, error) {
	return "", nil, errTestProbeFailed
}

type namingProber struct {
	identity string
	scopes   []string
}

func (namingProber) Method() string { return "oauth_probe" }
func (p namingProber) Probe(_ context.Context, _ *vault.Secret, _ string) (string, []string, error) {
	return p.identity, p.scopes, nil
}

var errTestProbeFailed = &testError{"simulated live probe failure"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
