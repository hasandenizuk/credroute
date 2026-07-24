// allow-claude-code: see verify.go header.
package main

import (
	"strings"
	"testing"

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
