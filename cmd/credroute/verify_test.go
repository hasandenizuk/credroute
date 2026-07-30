// allow-claude-code: see verify.go header.
package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/config"
)

// TestFindCredentialBySlot_Deterministic is F3: a slot claimed by exactly
// one identity resolves to that identity every time (no reliance on Go's
// randomized map iteration order), checked across many repeated calls to
// catch any residual nondeterminism.
func TestFindCredentialBySlot_Deterministic(t *testing.T) {
	cfg := &config.Config{
		Identities: map[string]config.Identity{
			"alex@example.com": {
				Platforms: map[string]config.Platform{
					"github": {
						Credentials: map[string]config.Credential{
							"read-write": {Type: "pat", Vault: "age://github/alex/pat.age", Slot: "/home/h/.config/gws/p1"},
						},
					},
				},
			},
		},
	}

	for i := 0; i < 20; i++ {
		id, platform, access, _, err := findCredentialBySlot(cfg, "/home/h/.config/gws/p1")
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if id != "alex@example.com" || platform != "github" || access != "read-write" {
			t.Fatalf("iteration %d: got (%s, %s, %s), want (alex@example.com, github, read-write)", i, id, platform, access)
		}
	}
}

// TestFindCredentialBySlot_SharedByTwoIdentities_IsAmbiguityError is F3's
// core fix: two identities legitimately pointing at the same slot must
// error out and name --platform as the way to disambiguate, never pick
// one at random.
func TestFindCredentialBySlot_SharedByTwoIdentities_IsAmbiguityError(t *testing.T) {
	cfg := &config.Config{
		Identities: map[string]config.Identity{
			"a@x.com": {
				Platforms: map[string]config.Platform{
					"google": {Credentials: map[string]config.Credential{
						"read-only": {Type: "oauth", Vault: "age://google/a/ro.age", Slot: "/shared/slot"},
					}},
				},
			},
			"b@y.com": {
				Platforms: map[string]config.Platform{
					"google": {Credentials: map[string]config.Credential{
						"read-only": {Type: "oauth", Vault: "age://google/b/ro.age", Slot: "/shared/slot"},
					}},
				},
			},
		},
	}

	_, _, _, _, err := findCredentialBySlot(cfg, "/shared/slot")
	if err == nil {
		t.Fatal("expected an ambiguity error for a slot shared by two identities, got nil")
	}
	if !strings.Contains(err.Error(), "multiple identities") || !strings.Contains(err.Error(), "--platform") {
		t.Fatalf("error = %q, want it to name the ambiguity and suggest --platform", err.Error())
	}
}

// TestFindCredentialBySlot_NoMatch is the plain not-found case.
func TestFindCredentialBySlot_NoMatch(t *testing.T) {
	cfg := &config.Config{Identities: map[string]config.Identity{}}
	if _, _, _, _, err := findCredentialBySlot(cfg, "/nowhere"); err == nil {
		t.Fatal("expected an error for a slot with no matching credential")
	}
}

func TestCmdVerify_UnconfirmedNeedsAcceptBaseline(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	v := newTestVault(t)
	v.Encrypt(t, "stripe/ops/key.age", []byte("stripe-secret"))
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
version: 1
defaults: { verify: required, on_no_match: refuse }
identities:
  ops@example.com:
    platforms:
      stripe:
        credentials:
          read-only: { type: api_key, vault: age://stripe/ops/key.age }
rules:
  - id: stripe
    match: { platform: stripe }
    use: { identity: ops@example.com, access: read-only }
vault:
  backend: age
  age:
    store_dir: %s
    identity_file: %s
`, v.StoreDir, v.IdentityFile))

	code, stdout := captureStdout(t, func() int {
		return cmdVerify([]string{"--config", cfgPath, "--platform", "stripe"})
	})
	if code != 3 {
		t.Fatalf("verify exit code = %d, want 3; stdout=%s", code, stdout)
	}
	if !strings.Contains(stdout, "--force") {
		t.Fatalf("stdout = %q, want exact force command", stdout)
	}

	code, stdout = captureStdout(t, func() int {
		return cmdVerify([]string{"--config", cfgPath, "--platform", "stripe", "--force"})
	})
	if code != 0 {
		t.Fatalf("verify --force exit code = %d, want 0; stdout=%s", code, stdout)
	}
	rec, err := attest.Read("", "age://stripe/ops/key.age")
	if err != nil {
		t.Fatalf("attest.Read: %v", err)
	}
	if rec.Status != attest.StatusAcceptedBaseline || rec.Platform != "stripe" || rec.AccessLevel != "read-only" {
		t.Fatalf("record = (%q, %q, %q), want accepted_baseline/stripe/read-only", rec.Status, rec.Platform, rec.AccessLevel)
	}
	entries, err := audit.ReadAll()
	if err != nil {
		t.Fatalf("audit.ReadAll: %v", err)
	}
	last := entries[len(entries)-1]
	if last.Verification != string(attest.StatusAcceptedBaseline) || last.Decision != "allow" {
		t.Fatalf("audit verification/decision = (%q, %q), want accepted_baseline/allow", last.Verification, last.Decision)
	}

	code, _ = captureStdout(t, func() int {
		return cmdVerify([]string{"--config", cfgPath, "--platform", "stripe", "--accept-baseline"})
	})
	if code != 0 {
		t.Fatalf("deprecated verify --accept-baseline alias exit code = %d, want 0", code)
	}
}

func captureStdout(t *testing.T, f func() int) (int, string) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	code := f()
	_ = w.Close()
	os.Stdout = old
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
