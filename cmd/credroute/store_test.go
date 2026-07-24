// allow-claude-code: see store.go header.
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/hasandenizuk/credroute/internal/vault"
)

// storeCmdTestConfig writes a config.yaml with the thin store enabled
// against a fresh temp age identity, and returns the config path plus
// the store dir. Skips if age/age-keygen are not on PATH (same pattern
// as testhelpers_test.go's newTestVault).
func storeCmdTestConfig(t *testing.T) (configPath, storeDir string) {
	t.Helper()
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age binary not on PATH, skipping")
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen binary not on PATH, skipping")
	}

	dir := t.TempDir()
	identityFile := filepath.Join(dir, "identity.txt")
	if out, err := exec.Command("age-keygen", "-o", identityFile).CombinedOutput(); err != nil {
		t.Fatalf("age-keygen -o failed: %v: %s", err, out)
	}
	storeDir = filepath.Join(dir, "store")
	yaml := `version: 1
defaults:
  on_no_match: refuse
  verify: required
  sidecar_max_age: 24h
vault:
  backend: age
  age:
    store_dir: ` + filepath.Join(dir, "vault") + `
    identity_file: ` + identityFile + `
store:
  enabled: true
  dir: ` + storeDir + `
`
	return writeTestConfig(t, yaml), storeDir
}

func TestCmdStoreAdd_LsRemove(t *testing.T) {
	path, _ := storeCmdTestConfig(t)

	secretFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secretFile, []byte("ghp_test_secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	code := cmdStoreAdd([]string{"--config", path, "--from-file", secretFile, "github/me/pat"})
	if code != 0 {
		t.Fatalf("store add exit = %d, want 0", code)
	}

	code = cmdStoreLs([]string{"--config", path, "--json"})
	if code != 0 {
		t.Fatalf("store ls exit = %d, want 0", code)
	}

	// Adding again without --force must fail.
	if code := cmdStoreAdd([]string{"--config", path, "--from-file", secretFile, "github/me/pat"}); code == 0 {
		t.Error("store add over an existing secret without --force should fail, got exit 0")
	}
	// With --force it succeeds.
	if code := cmdStoreAdd([]string{"--config", path, "--from-file", secretFile, "--force", "github/me/pat"}); code != 0 {
		t.Errorf("store add --force exit = %d, want 0", code)
	}

	code = cmdStoreRemove([]string{"--config", path, "github/me/pat"})
	if code != 0 {
		t.Fatalf("store remove exit = %d, want 0", code)
	}

	// Removing again (now missing) without --force should fail.
	if code := cmdStoreRemove([]string{"--config", path, "github/me/pat"}); code == 0 {
		t.Error("store remove of a missing secret without --force should fail, got exit 0")
	}
	// With --force it is a no-op success.
	if code := cmdStoreRemove([]string{"--config", path, "--force", "github/me/pat"}); code != 0 {
		t.Errorf("store remove --force on a missing secret exit = %d, want 0", code)
	}
}

func TestCmdStoreAdd_ReadsSecretFromStdinPipe(t *testing.T) {
	path, storeDir := storeCmdTestConfig(t)

	// Simulate a piped stdin by pointing a real os.Pipe at os.Stdin, since
	// readSecretInput checks isTerminal(os.Stdin) to decide whether to
	// treat stdin as piped content.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	go func() {
		_, _ = w.Write([]byte("piped-secret-value\n"))
		w.Close()
	}()

	code := cmdStoreAdd([]string{"--config", path, "github/me/pat"})
	if code != 0 {
		t.Fatalf("store add (stdin pipe) exit = %d, want 0", code)
	}

	// Confirm the stored plaintext matches (trailing newline trimmed).
	cfg, err := loadAndValidate(path)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := buildStoreBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := backend.Retrieve(context.Background(), vault.Handle("store://github/me/pat"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Zero()
	_ = secret.WithBytes(func(b []byte) error {
		if string(b) != "piped-secret-value" {
			t.Errorf("stored secret = %q, want %q", b, "piped-secret-value")
		}
		return nil
	})
	_ = storeDir
}

func TestBuildStoreBackend_NotEnabled(t *testing.T) {
	path := writeTestConfig(t, `version: 1
defaults:
  on_no_match: refuse
  verify: required
  sidecar_max_age: 24h
vault:
  backend: age
  age:
    store_dir: /tmp/vault
    identity_file: /tmp/id.txt
`)
	cfg, err := loadAndValidate(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildStoreBackend(cfg); err == nil {
		t.Error("expected an error when store.enabled is not set, got nil")
	}
}

func TestReadSecretInput_FromFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(f, []byte("value-with-trailing-newline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := readSecretInput(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "value-with-trailing-newline" {
		t.Errorf("readSecretInput(--from-file) = %q, want trailing newline trimmed", b)
	}
}

func TestTrimTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"abc\n":   "abc",
		"abc\r\n": "abc",
		"abc":     "abc",
		"":        "",
	}
	for in, want := range cases {
		if got := string(trimTrailingNewline([]byte(in))); got != want {
			t.Errorf("trimTrailingNewline(%q) = %q, want %q", in, got, want)
		}
	}
}
