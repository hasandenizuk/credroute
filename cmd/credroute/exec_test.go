// allow-claude-code: see exec.go header.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/vault"
	"github.com/hasandenizuk/credroute/internal/verify"
)

const execTestConfigTemplate = `
version: 1
defaults:
  on_no_match: refuse
  verify: required
identities:
  alex@example.com:
    label: "Alex"
    platforms:
      github:
        credentials:
          read-write:
            type: pat
            vault: age://github/alex/pat.age
            slot: %s
rules:
  - id: r1
    match: { platform: github }
    use: { identity: alex@example.com, access: read-write }
vault:
  backend: age
  age:
    store_dir: %s
    identity_file: %s
`

// TestCmdExec_RefusesOnMismatchedSlot is F1: exec must run the same
// verify+policy decision resolve does and refuse (exit 3) BEFORE ever
// decrypting or injecting the secret, when the attestation sidecar says
// mismatch under verify:required. Proven two ways: the exit code is 3,
// and the child command (which would create a marker file) never ran.
func TestCmdExec_RefusesOnMismatchedSlot(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	stateDir := t.TempDir()
	t.Setenv("CREDROUTE_STATE_DIR", stateDir)

	v := newTestVault(t)
	v.Encrypt(t, "github/alex/pat.age", []byte("ghp_the_real_token"))

	slot := filepath.Join(t.TempDir(), "gh-slot")
	vaultHandle := "age://github/alex/pat.age"

	// Pre-record a mismatch (the founding bug: a wrong-but-decryptable
	// secret sitting in the slot). exec must consult this before ever
	// calling backend.Retrieve.
	if err := attest.Write(&attest.Record{
		Slot:             slot,
		VaultHandle:      vaultHandle,
		ExpectedIdentity: "alex@example.com",
		ObservedIdentity: "someone-else",
		Status:           attest.StatusMismatch,
		Method:           "http_whoami",
	}); err != nil {
		t.Fatalf("attest.Write: %v", err)
	}

	cfgYAML := fmt.Sprintf(execTestConfigTemplate, slot, v.StoreDir, v.IdentityFile)
	cfgPath := writeTestConfig(t, cfgYAML)

	marker := filepath.Join(t.TempDir(), "child-ran.marker")
	args := []string{"--config", cfgPath, "--platform", "github", "--", "touch", marker}

	code := cmdExec(args)
	if code != 3 {
		t.Fatalf("cmdExec exit code = %d, want 3 (refuse)", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("child command ran despite a mismatched slot; exec must refuse before hand-off")
	}
}

// TestCmdExec_ProceedsWhenUnconfirmedUnderAdvisory is a control: the same
// mismatched-precondition setup, but with a rule that opts down to
// verify:advisory, must NOT refuse (advisory reports, never blocks).
func TestCmdExec_ProceedsUnderAdvisory(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	stateDir := t.TempDir()
	t.Setenv("CREDROUTE_STATE_DIR", stateDir)

	v := newTestVault(t)
	v.Encrypt(t, "github/alex/pat.age", []byte("ghp_the_real_token"))

	slot := filepath.Join(t.TempDir(), "gh-slot")

	advisoryYAML := fmt.Sprintf(`
version: 1
defaults:
  on_no_match: refuse
  verify: required
identities:
  alex@example.com:
    label: "Alex"
    platforms:
      github:
        credentials:
          read-write:
            type: pat
            vault: age://github/alex/pat.age
            slot: %s
rules:
  - id: r1
    match: { platform: github }
    use: { identity: alex@example.com, access: read-write, verify: advisory }
vault:
  backend: age
  age:
    store_dir: %s
    identity_file: %s
`, slot, v.StoreDir, v.IdentityFile)
	cfgPath := writeTestConfig(t, advisoryYAML)

	marker := filepath.Join(t.TempDir(), "child-ran.marker")
	args := []string{"--config", cfgPath, "--platform", "github", "--", "touch", marker}

	// No prior sidecar at all: fingerprint-only first observation is
	// "unconfirmed" (F2), which advisory must allow through.
	code := cmdExec(args)
	if code != 0 {
		t.Fatalf("cmdExec exit code = %d, want 0 (advisory proceeds)", code)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("child command did not run under advisory verify: %v", err)
	}
}

func TestCmdExec_MismatchWithUnrecordableObservationRefuses(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	stateDir := t.TempDir()
	t.Setenv("CREDROUTE_STATE_DIR", stateDir)

	v := newTestVault(t)
	handle := "age://github/alex/pat.age"
	v.Encrypt(t, "github/alex/pat.age", []byte("ghp_initial_token"))

	slot := filepath.Join(t.TempDir(), "gh-slot")
	if _, err := verify.Run(t.Context(), verify.Request{
		Platform:         "github",
		CredentialType:   "pat",
		ExpectedIdentity: "alex@example.com",
		AccessLevel:      "read-write",
		VaultHandle:      handle,
		Slot:             slot,
		Secret:           vault.NewSecret([]byte("ghp_initial_token")),
		CheckedBy:        attest.DefaultCheckedBy(buildVersion),
		AcceptBaseline:   true,
	}, verify.NewRegistry(false)); err != nil {
		t.Fatalf("seed accepted baseline: %v", err)
	}

	v.Encrypt(t, "github/alex/pat.age", []byte("ghp_changed_token"))
	attestDir, err := attest.AttestDir()
	if err != nil {
		t.Fatalf("attest dir: %v", err)
	}
	if err := os.Chmod(attestDir, 0o500); err != nil {
		t.Fatalf("make attest dir read-only: %v", err)
	}
	defer os.Chmod(attestDir, 0o700)

	cfgPath := writeTestConfig(t, fmt.Sprintf(execTestConfigTemplate, slot, v.StoreDir, v.IdentityFile))
	marker := filepath.Join(t.TempDir(), "child-ran.marker")
	code, stderr := captureStderr(t, func() int {
		return cmdExec([]string{"--config", cfgPath, "--platform", "github", "--", "sh", "-c", "printf ran > " + marker})
	})
	if code != 3 {
		t.Fatalf("cmdExec exit code = %d, want 3; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "refused after re-attestation") {
		t.Fatalf("stderr = %q, want refusal reason without -v", stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("child command ran despite mismatched fresh observation")
	}
	entries, err := audit.ReadAll()
	if err != nil {
		t.Fatalf("audit.ReadAll: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected an audit entry")
	}
	last := entries[len(entries)-1]
	if last.Verification != verify.ResolveMismatch || last.Decision != "refuse" {
		t.Fatalf("last audit verification/decision = (%q, %q), want (mismatch, refuse)", last.Verification, last.Decision)
	}
}

func captureStderr(t *testing.T, f func() int) (int, string) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = w
	code := f()
	_ = w.Close()
	os.Stderr = old
	var buf strings.Builder
	tmp := make([]byte, 1024)
	for {
		n, readErr := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			break
		}
	}
	return code, buf.String()
}
