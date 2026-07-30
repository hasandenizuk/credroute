// allow-claude-code: see identity.go header.
package main

import (
	"os"
	"strings"
	"testing"

	"github.com/hasandenizuk/credroute/internal/audit"
)

const identityTestConfigYAML = `version: 1
defaults:
  on_no_match: refuse
  verify: on
  sidecar_max_age: 24h
vault:
  backend: age
  age:
    store_dir: /tmp/vault
    identity_file: /tmp/id.txt
`

func TestCmdIdentityAdd_AndEdit(t *testing.T) {
	// M2 (Fable 5 review v2): identity add/edit now append an audit
	// entry on success, so every test that succeeds must sandbox the
	// state dir rather than writing to the real machine's audit.jsonl.
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	path := writeTestConfig(t, identityTestConfigYAML)

	if code := cmdIdentityAdd([]string{"--config", path, "--label", "Alex personal", "alex@example.com"}); code != 0 {
		t.Fatalf("identity add exit = %d, want 0", code)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "alex@example.com") || !strings.Contains(string(b), "Alex personal") {
		t.Errorf("config after identity add missing expected content:\n%s", b)
	}

	code := cmdIdentityEdit([]string{"--config", path, "--add-credential", "github:read-write:pat:age://github/alex/pat.age", "alex@example.com"})
	if code != 0 {
		t.Fatalf("identity edit exit = %d, want 0", code)
	}
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "age://github/alex/pat.age") {
		t.Errorf("config after identity edit missing the added credential:\n%s", b)
	}
}

func TestCmdIdentityAdd_Duplicate(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	path := writeTestConfig(t, identityTestConfigYAML)
	if code := cmdIdentityAdd([]string{"--config", path, "alex@example.com"}); code != 0 {
		t.Fatalf("first add exit = %d, want 0", code)
	}
	if code := cmdIdentityAdd([]string{"--config", path, "alex@example.com"}); code == 0 {
		t.Error("second add of the same identity should fail, got exit 0")
	}
}

func TestCmdIdentityEdit_UnknownIdentity(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	path := writeTestConfig(t, identityTestConfigYAML)
	code := cmdIdentityEdit([]string{"--config", path, "--label", "x", "nobody@example.com"})
	if code == 0 {
		t.Error("editing an unknown identity should fail, got exit 0")
	}
}

func TestCmdIdentityEdit_NothingToDo(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	path := writeTestConfig(t, identityTestConfigYAML)
	if code := cmdIdentityAdd([]string{"--config", path, "alex@example.com"}); code != 0 {
		t.Fatal("setup add failed")
	}
	if code := cmdIdentityEdit([]string{"--config", path, "alex@example.com"}); code != 1 {
		t.Errorf("identity edit with no flags exit = %d, want 1", code)
	}
}

// TestCmdIdentityAdd_AppendsAuditEntry guards M2 (Fable 5 review v2):
// identity/route/store mutations previously left no audit trail at all,
// so the routing table itself could be rewritten with zero record of
// who changed what.
func TestCmdIdentityAdd_AppendsAuditEntry(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	path := writeTestConfig(t, identityTestConfigYAML)

	if code := cmdIdentityAdd([]string{"--config", path, "--label", "Alex personal", "alex@example.com"}); code != 0 {
		t.Fatalf("identity add exit = %d, want 0", code)
	}

	entries, err := audit.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var found *audit.Entry
	for i := range entries {
		if entries[i].Op == "config" && entries[i].Command == "identity add" {
			found = &entries[i]
		}
	}
	if found == nil {
		t.Fatalf("no audit entry for the successful identity add, got: %+v", entries)
	}
	if found.Target != "alex@example.com" {
		t.Errorf("audit entry Target = %q, want %q", found.Target, "alex@example.com")
	}
	if found.ConfigPath != path {
		t.Errorf("audit entry ConfigPath = %q, want %q", found.ConfigPath, path)
	}
	if found.Decision != "allow" {
		t.Errorf("audit entry Decision = %q, want %q", found.Decision, "allow")
	}
}

func TestParseCredentialSpecs(t *testing.T) {
	specs, err := parseCredentialSpecs([]string{
		"google:read-only:oauth:age://google/alex/oauth-ro.json.age#~/.config/gws/profiles/personal-view",
		"github:read-write:pat:age://github/alex/pat.age",
	})
	if err != nil {
		t.Fatalf("parseCredentialSpecs: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2", len(specs))
	}
	if specs[0].platform != "google" || specs[0].access != "read-only" || specs[0].cred.Type != "oauth" {
		t.Errorf("spec[0] = %+v", specs[0])
	}
	if specs[0].cred.Vault != "age://google/alex/oauth-ro.json.age" {
		t.Errorf("spec[0].Vault = %q", specs[0].cred.Vault)
	}
	if specs[0].cred.Slot != "~/.config/gws/profiles/personal-view" {
		t.Errorf("spec[0].Slot = %q", specs[0].cred.Slot)
	}
	if specs[1].cred.Slot != "" {
		t.Errorf("spec[1].Slot = %q, want empty (no # given)", specs[1].cred.Slot)
	}
}

func TestParseCredentialSpecs_Malformed(t *testing.T) {
	cases := []string{
		"google:read-only",
		"google:read-only:oauth",
		":read-only:oauth:age://x.age",
	}
	for _, c := range cases {
		if _, err := parseCredentialSpecs([]string{c}); err == nil {
			t.Errorf("parseCredentialSpecs(%q) = nil error, want an error", c)
		}
	}
}
