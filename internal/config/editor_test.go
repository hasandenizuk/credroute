// allow-claude-code: see editor.go header.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const editorTestConfig = `version: 1

defaults:
  on_no_match: refuse
  verify: required
  sidecar_max_age: 24h

# a hand-written comment that must survive edits
clients:
  acme:
    roots: ["~/Projects/client.acme/**"]

identities:
  alex@example.com:
    label: "Alex personal" # trailing comment on an existing identity
    platforms:
      github:
        credentials:
          read-write:
            type: pat
            vault: age://github/alex-example-com/pat-repo.age

rules:
  - id: acme-google-ro
    match: { client: acme, platform: google }
    use: { identity: alex@example.com, access: read-only }

  - id: catch-all
    match: {}
    use: { identity: alex@example.com, access: read-only }

vault:
  backend: age
  age:
    store_dir: ~/Projects/shared/secrets
    identity_file: ~/.config/credroute/age-identity.txt
`

func writeEditorTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(editorTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDocument_AddIdentity(t *testing.T) {
	path := writeEditorTestConfig(t)
	doc, err := OpenDocument(path)
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}

	if err := doc.AddIdentity("new@example.com", "New identity"); err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}

	cfg, err := doc.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	got, ok := cfg.Identities["new@example.com"]
	if !ok {
		t.Fatal("new identity not present after AddIdentity")
	}
	if got.Label != "New identity" {
		t.Errorf("label = %q, want %q", got.Label, "New identity")
	}
	if len(got.Platforms) != 0 {
		t.Errorf("Platforms = %v, want empty", got.Platforms)
	}

	// The pre-existing identity is untouched.
	if _, ok := cfg.Identities["alex@example.com"]; !ok {
		t.Error("pre-existing identity alex@example.com was lost")
	}

	if err := doc.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "a hand-written comment that must survive edits") {
		t.Error("saved file lost the pre-existing comment")
	}
	if !strings.Contains(string(b), "trailing comment on an existing identity") {
		t.Error("saved file lost the trailing comment on an untouched identity")
	}
}

func TestDocument_AddIdentity_Duplicate(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.AddIdentity("alex@example.com", "dup"); err == nil {
		t.Error("expected an error adding a duplicate identity, got nil")
	}
}

func TestDocument_SetIdentityLabel(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.SetIdentityLabel("alex@example.com", "Renamed"); err != nil {
		t.Fatalf("SetIdentityLabel: %v", err)
	}
	cfg, err := doc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identities["alex@example.com"].Label != "Renamed" {
		t.Errorf("label = %q, want %q", cfg.Identities["alex@example.com"].Label, "Renamed")
	}
}

func TestDocument_SetIdentityLabel_UnknownIdentity(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.SetIdentityLabel("nobody@example.com", "x"); err == nil {
		t.Error("expected an error for an unknown identity, got nil")
	}
}

func TestDocument_UpsertCredential_AddsAndReplaces(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	// New platform+access on an existing identity.
	err = doc.UpsertCredential("alex@example.com", "google", "read-only", Credential{
		Type:  "oauth",
		Vault: "age://google/alex-example-com/oauth-ro.json.age",
		Slot:  "~/.config/gws/profiles/personal-view",
	})
	if err != nil {
		t.Fatalf("UpsertCredential (new): %v", err)
	}

	// Replace the existing github read-write credential's vault handle.
	err = doc.UpsertCredential("alex@example.com", "github", "read-write", Credential{
		Type:  "pat",
		Vault: "age://github/alex-example-com/pat-repo-v2.age",
	})
	if err != nil {
		t.Fatalf("UpsertCredential (replace): %v", err)
	}

	cfg, err := doc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	plats := cfg.Identities["alex@example.com"].Platforms
	google, ok := plats["google"].Credentials["read-only"]
	if !ok {
		t.Fatal("google read-only credential not added")
	}
	if google.Slot != "~/.config/gws/profiles/personal-view" {
		t.Errorf("google slot = %q", google.Slot)
	}
	gh := plats["github"].Credentials["read-write"]
	if gh.Vault != "age://github/alex-example-com/pat-repo-v2.age" {
		t.Errorf("github vault = %q, want the replaced handle", gh.Vault)
	}
}

func TestDocument_UpsertCredential_UnknownIdentity(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	err = doc.UpsertCredential("nobody@example.com", "google", "read-only", Credential{Type: "oauth", Vault: "age://x.age"})
	if err == nil {
		t.Error("expected an error for an unknown identity, got nil")
	}
}

func TestDocument_AddRule_InsertsBeforeCatchAll(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{
		ID:    "new-rule",
		Match: RuleMatch{Platform: StringOrList{"github"}},
		Use:   RuleUse{Identity: "alex@example.com", Access: "read-write"},
	}
	if err := doc.AddRule(rule, -1); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	cfg, err := doc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(cfg)
	want := []string{"acme-google-ro", "new-rule", "catch-all"}
	if !equalStrings(ids, want) {
		t.Errorf("rule order = %v, want %v", ids, want)
	}
}

func TestDocument_AddRule_ExplicitIndex(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{ID: "first", Match: RuleMatch{Platform: StringOrList{"github"}}, Use: RuleUse{Identity: "alex@example.com", Access: "read-write"}}
	if err := doc.AddRule(rule, 0); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	cfg, err := doc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(cfg)
	want := []string{"first", "acme-google-ro", "catch-all"}
	if !equalStrings(ids, want) {
		t.Errorf("rule order = %v, want %v", ids, want)
	}
}

func TestDocument_AssignRule(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	newIdentity := "alex@example.com"
	newAccess := "read-write"
	newVerify := "advisory"
	if err := doc.AssignRule("acme-google-ro", &newIdentity, &newAccess, &newVerify); err != nil {
		t.Fatalf("AssignRule: %v", err)
	}
	cfg, err := doc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for i := range cfg.Rules {
		if cfg.Rules[i].ID == "acme-google-ro" {
			rule = &cfg.Rules[i]
		}
	}
	if rule == nil {
		t.Fatal("rule acme-google-ro not found after AssignRule")
	}
	if rule.Use.Access != "read-write" {
		t.Errorf("access = %q, want read-write", rule.Use.Access)
	}
	if rule.Use.Verify != "advisory" {
		t.Errorf("verify = %q, want advisory", rule.Use.Verify)
	}

	// Clearing verify back to inherit-from-defaults.
	empty := ""
	if err := doc.AssignRule("acme-google-ro", nil, nil, &empty); err != nil {
		t.Fatalf("AssignRule (clear verify): %v", err)
	}
	cfg2, err := doc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for i := range cfg2.Rules {
		if cfg2.Rules[i].ID == "acme-google-ro" && cfg2.Rules[i].Use.Verify != "" {
			t.Errorf("verify = %q after clearing, want empty", cfg2.Rules[i].Use.Verify)
		}
	}
}

func TestDocument_AssignRule_UnknownID(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	id := "x"
	if err := doc.AssignRule("does-not-exist", &id, nil, nil); err == nil {
		t.Error("expected an error for an unknown rule id, got nil")
	}
}

func TestDocument_Snapshot_ValidatesWithConfigValidate(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	// Reference an undefined identity: Validate must catch it before Save.
	rule := Rule{ID: "bad", Match: RuleMatch{Platform: StringOrList{"github"}}, Use: RuleUse{Identity: "nobody@example.com", Access: "read-write"}}
	if err := doc.AddRule(rule, 0); err != nil {
		t.Fatal(err)
	}
	cfg, err := doc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	result := Validate(cfg)
	if result.OK() {
		t.Error("expected Validate to reject a rule referencing an undefined identity")
	}
}

func TestDocument_Save_RefusesUntilCalled(t *testing.T) {
	path := writeEditorTestConfig(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := OpenDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.AddIdentity("new@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	// No Save() call: the on-disk file must be unchanged.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("on-disk config changed before Save() was called")
	}
}

func ruleIDs(cfg *Config) []string {
	ids := make([]string, len(cfg.Rules))
	for i, r := range cfg.Rules {
		ids[i] = r.ID
	}
	return ids
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
