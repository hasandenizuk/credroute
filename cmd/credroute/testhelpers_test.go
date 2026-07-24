// allow-claude-code: see resolve.go/exec.go headers.
//
// Shared test fixtures for cmd/credroute: a minimal age vault plus a
// minimal credroute config, used by the F1/F3/F6/F13 regression tests.
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testVault holds a temp age identity + store dir, and a helper to
// encrypt a plaintext secret into it. Skips the calling test if age/
// age-keygen are not on PATH (matches internal/vault's own live-round-trip
// test pattern).
type testVault struct {
	StoreDir     string
	IdentityFile string
}

func newTestVault(t *testing.T) *testVault {
	t.Helper()
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age binary not on PATH, skipping")
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen binary not on PATH, skipping")
	}

	dir := t.TempDir()
	identityFile := filepath.Join(dir, "identity.txt")
	storeDir := filepath.Join(dir, "store")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("age-keygen", "-o", identityFile).CombinedOutput(); err != nil {
		t.Fatalf("age-keygen -o failed: %v: %s", err, out)
	}
	return &testVault{StoreDir: storeDir, IdentityFile: identityFile}
}

// Encrypt writes plaintext to relPath under the vault store, encrypted to
// this vault's own identity (so the same identity_file can decrypt it).
func (v *testVault) Encrypt(t *testing.T, relPath string, plaintext []byte) {
	t.Helper()
	pubOut, err := exec.Command("age-keygen", "-y", v.IdentityFile).Output()
	if err != nil {
		t.Fatalf("age-keygen -y failed: %v", err)
	}
	recipient := strings.TrimSpace(string(pubOut))

	full := filepath.Join(v.StoreDir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("age", "-r", recipient, "-o", full)
	cmd.Stdin = bytes.NewReader(plaintext)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("age encrypt failed: %v: %s", err, out)
	}
}

// writeTestConfig writes yaml to a fresh temp config.yaml and returns its
// path.
func writeTestConfig(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return path
}
