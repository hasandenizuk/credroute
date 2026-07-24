// allow-claude-code: see store.go header.
package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	// M2 (Fable 5 review v2): store add/remove now append an audit entry
	// on success, so every caller of this helper must sandbox the state
	// dir rather than writing to the real machine's audit.jsonl.
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

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

// TestValidateStorePath_RejectsReservedCharacters guards L2 (Fable 5
// review v2): "#", "?", and "%" are all meaningful to url.Parse (used by
// resolvePath), so a path containing one could make the stored/retrieved
// path disagree with the handle credroute reports back.
func TestValidateStorePath_RejectsReservedCharacters(t *testing.T) {
	for _, bad := range []string{"github/me/pat#frag", "github/me?query", "github/me%2e"} {
		if err := validateStorePath(bad); err == nil {
			t.Errorf("validateStorePath(%q) = nil, want an error", bad)
		}
	}
	if err := validateStorePath("github/me/pat"); err != nil {
		t.Errorf("validateStorePath(plain path) = %v, want nil", err)
	}
}

func TestCmdStoreAdd_RejectsReservedPathCharacters(t *testing.T) {
	path, _ := storeCmdTestConfig(t)
	if code := cmdStoreAdd([]string{"--config", path, "--from-file", os.DevNull, "github/me/pat#frag"}); code == 0 {
		t.Error("store add with a '#' in the path should be refused, got exit 0")
	}
}

func TestCmdStoreRemove_RejectsReservedPathCharacters(t *testing.T) {
	path, _ := storeCmdTestConfig(t)
	if code := cmdStoreRemove([]string{"--config", path, "github/me/pat#frag"}); code == 0 {
		t.Error("store remove with a '#' in the path should be refused, got exit 0")
	}
}

// TestCmdStoreRemove_RefusesToRemoveADirectory guards L7 (Fable 5 review
// v2): `store remove` must never delete a directory inside the store
// dir, even one that happens to sit at the resolved path for a handle.
func TestCmdStoreRemove_RefusesToRemoveADirectory(t *testing.T) {
	path, storeDir := storeCmdTestConfig(t)
	if err := os.MkdirAll(filepath.Join(storeDir, "github", "me"), 0o755); err != nil {
		t.Fatal(err)
	}

	code := cmdStoreRemove([]string{"--config", path, "github/me"})
	if code == 0 {
		t.Fatal("store remove of a directory should be refused, got exit 0")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "github", "me")); err != nil {
		t.Errorf("directory was removed despite the refusal: %v", err)
	}
}

// TestReadPromptedSecret_SingleLineIsAccepted is the control case for
// TestReadPromptedSecret_RejectsBufferedMultilineInput below.
func TestReadPromptedSecret_SingleLineIsAccepted(t *testing.T) {
	b, err := readPromptedSecret(bufio.NewReader(strings.NewReader("just-one-line\n")))
	if err != nil {
		t.Fatalf("readPromptedSecret: %v", err)
	}
	if string(b) != "just-one-line" {
		t.Errorf("readPromptedSecret = %q, want %q", b, "just-one-line")
	}
}

// TestReadPromptedSecret_RejectsBufferedMultilineInput guards L1 (Fable 5
// review v2): the interactive prompt used to silently truncate a pasted
// multiline secret (e.g. a PEM key) at the first newline and store it
// truncated with exit 0. When more than one line arrives in the same
// read, it must now be rejected instead.
func TestReadPromptedSecret_RejectsBufferedMultilineInput(t *testing.T) {
	_, err := readPromptedSecret(bufio.NewReader(strings.NewReader("line-one\nline-two\n")))
	if err == nil {
		t.Error("readPromptedSecret with buffered multiline input should return an error, got nil")
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
