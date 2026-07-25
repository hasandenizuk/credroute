// allow-claude-code: see handle.go header.
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

func TestHandleRevealAllowed(t *testing.T) {
	cases := []struct {
		name        string
		forceReveal bool
		isTTY       bool
		want        bool
	}{
		{"neither flag nor tty", false, false, false},
		{"tty but no flag", false, true, false},
		{"flag but no tty (piped/redirected)", true, false, false},
		{"flag and tty", true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := handleRevealAllowed(c.forceReveal, c.isTTY)
			if got != c.want {
				t.Fatalf("handleRevealAllowed(%v, %v) = %v, want %v", c.forceReveal, c.isTTY, got, c.want)
			}
			if !got && reason == "" {
				t.Fatal("a refusal must always explain why")
			}
			if got && reason != "" {
				t.Fatalf("an allowed reveal should carry no refusal reason, got %q", reason)
			}
		})
	}
}

func TestCmdHandleGet_UnmodeledRefusesUnlessBreakGlass(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	v := newTestVault(t)
	v.Encrypt(t, "misc/token.age", []byte("secret"))
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
version: 1
defaults: { verify: required, on_no_match: refuse }
identities: {}
rules: []
vault:
  backend: age
  age:
    store_dir: %s
    identity_file: %s
`, v.StoreDir, v.IdentityFile))

	out := filepath.Join(t.TempDir(), "secret.txt")
	code, stderr := captureStderr(t, func() int {
		return cmdHandleGet([]string{"--config", cfgPath, "age://misc/token.age", "--to-file", out})
	})
	if code != 3 {
		t.Fatalf("cmdHandleGet exit code = %d, want 3; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "not modeled in config") {
		t.Fatalf("stderr = %q, want unmodeled refusal", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("unmodeled handle wrote a secret without break-glass")
	}

	code, stderr = captureStderr(t, func() int {
		return cmdHandleGet([]string{"--config", cfgPath, "age://misc/token.age", "--allow-unmodeled-handle", "--to-file", out})
	})
	if code != 0 {
		t.Fatalf("break-glass exit code = %d, want 0; stderr=%s", code, stderr)
	}
	entries, err := audit.ReadAll()
	if err != nil {
		t.Fatalf("audit.ReadAll: %v", err)
	}
	last := entries[len(entries)-1]
	if last.Verification != "bypass_unmodeled_handle" || last.Decision != "allow" {
		t.Fatalf("audit verification/decision = (%q, %q), want bypass_unmodeled_handle/allow", last.Verification, last.Decision)
	}
}

func TestCmdHandleGet_BreakGlassFailsWhenAuditCannotBeWritten(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state-file")
	if err := os.WriteFile(stateFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write state file: %v", err)
	}
	t.Setenv("CREDROUTE_STATE_DIR", stateFile)

	cfgPath := writeTestConfig(t, `
version: 1
defaults: { verify: required, on_no_match: refuse }
identities: {}
rules: []
vault:
  backend: age
  age:
    store_dir: /tmp/store
    identity_file: /tmp/id.txt
`)

	out := filepath.Join(t.TempDir(), "secret.txt")
	code, stderr := captureStderr(t, func() int {
		return cmdHandleGet([]string{"--config", cfgPath, "age://misc/token.age", "--allow-unmodeled-handle", "--to-file", out})
	})
	if code == 0 {
		t.Fatalf("cmdHandleGet exit code = 0, want refusal when break-glass audit cannot be written; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "break-glass audit entry could not be written") {
		t.Fatalf("stderr = %q, want audit failure detail", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("secret output file was created even though break-glass audit failed")
	}
}

func TestCmdHandleGet_AmbiguousHandleRefuses(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	v := newTestVault(t)
	v.Encrypt(t, "shared/token.age", []byte("secret"))
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
version: 1
defaults: { verify: required, on_no_match: refuse }
identities:
  a@example.com:
    platforms:
      github:
        credentials:
          read-only: { type: pat, vault: age://shared/token.age }
  b@example.com:
    platforms:
      github:
        credentials:
          read-only: { type: pat, vault: age://shared/token.age }
rules: []
vault:
  backend: age
  age:
    store_dir: %s
    identity_file: %s
`, v.StoreDir, v.IdentityFile))

	out := filepath.Join(t.TempDir(), "secret.txt")
	code, stderr := captureStderr(t, func() int {
		return cmdHandleGet([]string{"--config", cfgPath, "age://shared/token.age", "--to-file", out})
	})
	if code != 3 {
		t.Fatalf("cmdHandleGet exit code = %d, want 3; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "multiple identities") {
		t.Fatalf("stderr = %q, want ambiguity message", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("ambiguous handle wrote a secret")
	}
}

func TestCmdHandleGet_ChangedCiphertextRefuses(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	v := newTestVault(t)
	handle := "age://github/alex/pat.age"
	v.Encrypt(t, "github/alex/pat.age", []byte("initial"))
	if _, err := verify.Run(t.Context(), verify.Request{
		Platform:         "github",
		CredentialType:   "pat",
		ExpectedIdentity: "alex@example.com",
		AccessLevel:      "read-only",
		VaultHandle:      handle,
		Secret:           vault.NewSecret([]byte("initial")),
		CheckedBy:        attest.DefaultCheckedBy(buildVersion),
		AcceptBaseline:   true,
	}, verify.NewRegistry(false)); err != nil {
		t.Fatalf("seed accepted baseline: %v", err)
	}
	v.Encrypt(t, "github/alex/pat.age", []byte("changed"))
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
version: 1
defaults: { verify: required, on_no_match: refuse }
identities:
  alex@example.com:
    platforms:
      github:
        credentials:
          read-only: { type: pat, vault: %s }
rules: []
vault:
  backend: age
  age:
    store_dir: %s
    identity_file: %s
`, handle, v.StoreDir, v.IdentityFile))

	out := filepath.Join(t.TempDir(), "secret.txt")
	code, stderr := captureStderr(t, func() int {
		return cmdHandleGet([]string{"--config", cfgPath, handle, "--to-file", out})
	})
	if code != 3 {
		t.Fatalf("cmdHandleGet exit code = %d, want 3; stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "refused after re-attestation") {
		t.Fatalf("stderr = %q, want fresh verification refusal", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("changed handle wrote a secret")
	}
}
