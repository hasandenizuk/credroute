// allow-claude-code: see exec.go header.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hasandenizuk/credroute/internal/attest"
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
