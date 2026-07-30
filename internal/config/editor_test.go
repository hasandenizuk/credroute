// allow-claude-code: see editor.go header.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
)

const editorTestConfig = `version: 1

defaults:
  on_no_match: refuse
  verify: on
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
    store_dir: ~/vault
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
	newVerify := "off"
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
	if rule.Use.Verify != "off" {
		t.Errorf("verify = %q, want off", rule.Use.Verify)
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

// TestDocument_AddIdentity_FreshInitStaysBlockStyle regression-tests the
// "identities: {}" / "rules: []" flow-style trap: a config written by
// `credroute init` (nil Identities/Rules, no omitempty on those two
// top-level fields) round-trips those keys as flow-style empty
// containers ("{}" / "[]" are the only way to write an empty
// mapping/sequence). Adding the first identity or rule into one of those
// must not leave the whole subtree flow-styled (YAML requires every
// descendant of a flow node to also be flow), or every later edit would
// render as a cramped, unreadable single line instead of the block style
// every documented example config uses.
func TestDocument_AddIdentity_FreshInitStaysBlockStyle(t *testing.T) {
	freshInit := `version: 1
defaults:
    on_no_match: refuse
    verify: on
    sidecar_max_age: 24h
clients: {}
identities: {}
rules: []
vault:
    backend: age
    age:
        store_dir: /tmp/vault
        identity_file: /tmp/id.txt
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(freshInit), 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := OpenDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.AddIdentity("alex@example.com", "Alex personal"); err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
	if err := doc.UpsertCredential("alex@example.com", "github", "read-write", Credential{Type: "pat", Vault: "age://github/alex/pat.age"}); err != nil {
		t.Fatalf("UpsertCredential: %v", err)
	}
	rule := Rule{ID: "gh-rule", Match: RuleMatch{Platform: StringOrList{"github"}}, Use: RuleUse{Identity: "alex@example.com", Access: "read-write"}}
	if err := doc.AddRule(rule, -1); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := doc.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if strings.Contains(out, "{alex@example.com") || strings.Contains(out, "identities: {a") {
		t.Errorf("identities rendered in flow style, want block:\n%s", out)
	}
	if strings.Contains(out, "rules: [{") {
		t.Errorf("rules rendered in flow style, want block:\n%s", out)
	}
	if !strings.Contains(out, "identities:\n    alex@example.com:\n") {
		t.Errorf("identities not in expected block layout:\n%s", out)
	}
	if !strings.Contains(out, "rules:\n    - id: gh-rule\n") {
		t.Errorf("rules not in expected block layout:\n%s", out)
	}
}

// TestOpenDocument_ConcurrentEditsSerializeInsteadOfLosingAnUpdate guards
// M1 (Fable 5 review v2): two concurrent editors of the same config used
// to last-writer-wins, with the second rename silently discarding the
// first editor's already-saved change. OpenDocument now flocks the
// config, so the second OpenDocument call blocks until the first
// editor's Close releases it, and reads the already-saved file rather
// than racing it.
func TestOpenDocument_ConcurrentEditsSerializeInsteadOfLosingAnUpdate(t *testing.T) {
	path := writeEditorTestConfig(t)

	docA, err := OpenDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := docA.AddIdentity("a@example.com", "A"); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	resultCh := make(chan error, 1)
	go func() {
		close(started)
		// Must block here until docA.Close() below releases the lock.
		docB, err := OpenDocument(path)
		if err != nil {
			resultCh <- err
			return
		}
		defer docB.Close()
		if err := docB.AddIdentity("b@example.com", "B"); err != nil {
			resultCh <- err
			return
		}
		resultCh <- docB.Save()
	}()
	<-started
	time.Sleep(50 * time.Millisecond) // let the goroutine actually block on the flock

	if err := docA.Save(); err != nil {
		t.Fatalf("docA.Save: %v", err)
	}
	if err := docA.Close(); err != nil {
		t.Fatalf("docA.Close: %v", err)
	}

	select {
	case err := <-resultCh:
		if err != nil {
			t.Fatalf("second editor's edit/save: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the second editor; the lock may never have been released")
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Identities["a@example.com"]; !ok {
		t.Error("identity a@example.com (first editor's change) was lost")
	}
	if _, ok := cfg.Identities["b@example.com"]; !ok {
		t.Error("identity b@example.com (second editor's change) was lost")
	}
}

// TestDocument_UpsertCredential_InvalidatesSidecarWhenHandleChangesUnderSameSlot
// guards H2 (Fable 5 review v2): sidecars for slot-carrying credentials
// are keyed by slot only, so re-pointing the SAME slot at a different
// vault handle must invalidate the old sidecar rather than leaving a
// "verified" attestation earned by the old handle readable under the new
// one.
func TestDocument_UpsertCredential_InvalidatesSidecarWhenHandleChangesUnderSameSlot(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Close()

	const slot = "~/.config/gws/profiles/personal-view"
	const oldHandle = "age://google/alex-example-com/oauth-ro-a.json.age"
	const newHandle = "age://google/alex-example-com/oauth-ro-b.json.age"

	if err := doc.UpsertCredential("alex@example.com", "google", "read-only", Credential{
		Type: "oauth", Vault: oldHandle, Slot: slot,
	}); err != nil {
		t.Fatalf("initial UpsertCredential: %v", err)
	}

	rec := &attest.Record{
		Slot:              slot,
		VaultHandle:       oldHandle,
		ExpectedIdentity:  "alex@example.com",
		Status:            attest.StatusVerified,
		IdentityConfirmed: true,
		Method:            "test",
		CheckedAt:         time.Now().UTC(),
	}
	if err := attest.Write(rec); err != nil {
		t.Fatalf("attest.Write: %v", err)
	}
	if _, err := attest.Read(slot, oldHandle); err != nil {
		t.Fatalf("sanity check: sidecar should be readable before the edit: %v", err)
	}

	if err := doc.UpsertCredential("alex@example.com", "google", "read-only", Credential{
		Type: "oauth", Vault: newHandle, Slot: slot,
	}); err != nil {
		t.Fatalf("replacing UpsertCredential: %v", err)
	}

	if _, err := attest.Read(slot, newHandle); !attest.IsNotFound(err) {
		t.Errorf("sidecar for slot %q should have been invalidated after its vault handle changed, got err=%v", slot, err)
	}
}

// TestDocument_UpsertCredential_NoInvalidationWhenNothingChanged confirms
// the H2 fix does not fire (and does not error) when a credential is
// re-upserted with the same slot/vault handle it already had.
func TestDocument_UpsertCredential_NoInvalidationWhenNothingChanged(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Close()

	cred := Credential{Type: "pat", Vault: "age://github/alex-example-com/pat-repo.age"}
	if err := doc.UpsertCredential("alex@example.com", "github", "read-write", cred); err != nil {
		t.Fatalf("UpsertCredential: %v", err)
	}
}

// TestDocument_AddRule_ExplicitIndexPastCatchAllIsClamped guards L4
// (Fable 5 review v2): an explicit --index landing at or after a
// trailing catch-all rule's position used to be inserted verbatim,
// producing a config that config.Validate would then refuse ("catch-all
// only legal as final rule"). It is now clamped to just before the
// catch-all, same as the smart default (index < 0).
func TestDocument_AddRule_ExplicitIndexPastCatchAllIsClamped(t *testing.T) {
	doc, err := OpenDocument(writeEditorTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{ID: "explicit-past-end", Match: RuleMatch{Platform: StringOrList{"github"}}, Use: RuleUse{Identity: "alex@example.com", Access: "read-write"}}
	// The base config has 2 rules (acme-google-ro, catch-all); index 5 is
	// well past the end and past the catch-all.
	if err := doc.AddRule(rule, 5); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	cfg, err := doc.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"acme-google-ro", "explicit-past-end", "catch-all"}
	if got := ruleIDs(cfg); !equalStrings(got, want) {
		t.Errorf("rule order = %v, want %v", got, want)
	}
	// The fixture's own pre-existing rule references a platform/credential
	// this test does not touch, so assert on the specific thing this fix
	// is about (the catch-all placement) rather than full validity.
	result := Validate(cfg)
	for _, e := range result.Errors {
		if strings.Contains(e.String(), "final rule") {
			t.Errorf("clamped insert should not trigger the catch-all-placement error, got: %v", e)
		}
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
