// allow-claude-code: see config.go header.
package config

import (
	"strings"
	"testing"
)

func baseValidConfig() *Config {
	return &Config{
		Version: 1,
		Defaults: Defaults{
			OnNoMatch:     "refuse",
			Verify:        "required",
			SidecarMaxAge: "24h",
		},
		Clients: map[string]Client{
			"acme": {Roots: []string{"~/Projects/client.acme/**"}},
		},
		Identities: map[string]Identity{
			"alex@example.com": {
				Label: "Alex",
				Platforms: map[string]Platform{
					"google": {Credentials: map[string]Credential{
						"read-only": {Type: "oauth", Vault: "age://google/alex/ro.age"},
					}},
				},
			},
		},
		Rules: []Rule{
			{
				ID:    "acme-google-ro",
				Match: RuleMatch{Client: "acme", Platform: StringOrList{"google"}},
				Use:   RuleUse{Identity: "alex@example.com", Access: "read-only"},
			},
		},
		Vault: VaultConfig{
			Backend: "age",
			Age:     AgeConfig{StoreDir: "~/vault", IdentityFile: "~/.config/credroute/age-identity.txt"},
		},
	}
}

func hasErrorContaining(res ValidationResult, substr string) bool {
	for _, e := range res.Errors {
		if strings.Contains(e.String(), substr) {
			return true
		}
	}
	return false
}

func hasWarningContaining(res ValidationResult, substr string) bool {
	for _, w := range res.Warnings {
		if strings.Contains(w.String(), substr) {
			return true
		}
	}
	return false
}

func TestValidate_BaseConfigIsValid(t *testing.T) {
	res := Validate(baseValidConfig())
	if !res.OK() {
		t.Fatalf("expected no errors, got: %v", res.Errors)
	}
}

func TestValidate_DanglingIdentityReference(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules[0].Use.Identity = "nobody@example.com"

	res := Validate(cfg)
	if res.OK() {
		t.Fatal("expected an error for a dangling identity reference")
	}
	if !hasErrorContaining(res, `references undefined identity "nobody@example.com"`) {
		t.Errorf("errors did not mention the dangling identity: %v", res.Errors)
	}
}

func TestValidate_DanglingClientReference(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules[0].Match.Client = "nosuchclient"

	res := Validate(cfg)
	if res.OK() {
		t.Fatal("expected an error for a dangling client reference")
	}
	if !hasErrorContaining(res, `references undefined client "nosuchclient"`) {
		t.Errorf("errors did not mention the dangling client: %v", res.Errors)
	}
}

func TestValidate_MissingCredentialForRulePlatform(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules[0].Use.Access = "read-write" // identity only has read-only

	res := Validate(cfg)
	if res.OK() {
		t.Fatal("expected an error: identity has no read-write google credential")
	}
	if !hasErrorContaining(res, `no "read-write" credential for platform "google"`) {
		t.Errorf("errors did not mention the missing credential: %v", res.Errors)
	}
}

func TestValidate_UnknownAccessLevel(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules[0].Use.Access = "superuser"

	res := Validate(cfg)
	if !hasErrorContaining(res, `unknown access level "superuser"`) {
		t.Errorf("errors did not flag the unknown access level: %v", res.Errors)
	}
}

func TestValidate_UnknownCredentialType(t *testing.T) {
	cfg := baseValidConfig()
	id := cfg.Identities["alex@example.com"]
	cred := id.Platforms["google"].Credentials["read-only"]
	cred.Type = "carrier-pigeon"
	id.Platforms["google"].Credentials["read-only"] = cred
	cfg.Identities["alex@example.com"] = id

	res := Validate(cfg)
	if !hasErrorContaining(res, `unknown credential type "carrier-pigeon"`) {
		t.Errorf("errors did not flag the unknown credential type: %v", res.Errors)
	}
}

func TestValidate_CatchAllOnlyLegalAsLastRule(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules = append([]Rule{{ID: "catchall", Use: RuleUse{Identity: "alex@example.com", Access: "read-only"}}}, cfg.Rules...)

	res := Validate(cfg)
	if !hasErrorContaining(res, "only legal as the final rule") {
		t.Errorf("errors did not flag the misplaced catch-all: %v", res.Errors)
	}
}

func TestValidate_DuplicateRuleID(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules = append(cfg.Rules, Rule{
		ID:    "acme-google-ro",
		Match: RuleMatch{Platform: StringOrList{"github"}},
		Use:   RuleUse{Identity: "alex@example.com", Access: "read-only"},
	})

	res := Validate(cfg)
	if !hasErrorContaining(res, "duplicate rule id") {
		t.Errorf("errors did not flag the duplicate rule id: %v", res.Errors)
	}
}

// TestValidate_RuleIDControlCharacterIsRejected guards L3 (Fable 5 review
// v2): a rule id containing a literal newline is not a YAML-injection
// vector (yaml.v3 quotes it safely), but it can spoof terminal output
// (route ls, error messages) and audit log lines. Rejected uniformly by
// config.Validate rather than only by ad hoc callers.
func TestValidate_RuleIDControlCharacterIsRejected(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules[0].ID = "evil\nid"

	res := Validate(cfg)
	if !hasErrorContaining(res, "control character") {
		t.Errorf("errors did not flag the control character in the rule id: %v", res.Errors)
	}
}

// TestValidate_IdentityIDControlCharacterIsRejected is
// TestValidate_RuleIDControlCharacterIsRejected's identity-id
// counterpart.
func TestValidate_IdentityIDControlCharacterIsRejected(t *testing.T) {
	cfg := baseValidConfig()
	evil := cfg.Identities["alex@example.com"]
	delete(cfg.Identities, "alex@example.com")
	cfg.Identities["evil\nid"] = evil
	cfg.Rules[0].Use.Identity = "evil\nid"

	res := Validate(cfg)
	if !hasErrorContaining(res, "control character") {
		t.Errorf("errors did not flag the control character in the identity id: %v", res.Errors)
	}
}

// TestValidate_RuleIDTooLongIsRejected guards the maxIDLength half of L3.
func TestValidate_RuleIDTooLongIsRejected(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules[0].ID = strings.Repeat("x", maxIDLength+1)

	res := Validate(cfg)
	if !hasErrorContaining(res, "longer than the") {
		t.Errorf("errors did not flag the over-length rule id: %v", res.Errors)
	}
}

func TestValidate_ShadowedRule(t *testing.T) {
	cfg := baseValidConfig()
	// A second rule with an identical match block can never fire: the
	// first rule (same client+platform) always wins.
	cfg.Rules = append(cfg.Rules, Rule{
		ID:    "acme-google-ro-again",
		Match: RuleMatch{Client: "acme", Platform: StringOrList{"google"}},
		Use:   RuleUse{Identity: "alex@example.com", Access: "read-only"},
	})

	res := Validate(cfg)
	if !hasWarningContaining(res, `"acme-google-ro-again" is shadowed by earlier rule "acme-google-ro"`) {
		t.Errorf("warnings did not flag the shadowed rule: %v", res.Warnings)
	}
}

func TestValidate_BroaderEarlierRuleShadowsNarrowerLaterRule(t *testing.T) {
	cfg := baseValidConfig()
	// The base rule (client=acme, platform=google) matches every request
	// a later, more specific rule (same client+platform, plus a task)
	// would match, so the later rule is unreachable. This is exactly why
	// the spec's worked example puts the task-specific "acme-gsc" rule
	// BEFORE the broad "acme-google-ro" rule.
	cfg.Rules = append(cfg.Rules, Rule{
		ID:    "acme-google-gsc",
		Match: RuleMatch{Client: "acme", Platform: StringOrList{"google"}, Task: StringOrList{"gsc"}},
		Use:   RuleUse{Identity: "alex@example.com", Access: "read-only"},
	})

	res := Validate(cfg)
	if !hasWarningContaining(res, "acme-google-gsc") {
		t.Errorf("expected acme-google-gsc to be flagged as shadowed by the broader earlier rule: %v", res.Warnings)
	}
}

func TestValidate_DifferentPlatformIsNotShadowed(t *testing.T) {
	cfg := baseValidConfig()
	// Same client, but a different platform: the earlier rule's platform
	// condition does not hold for this rule's requests, so it is
	// genuinely reachable, not shadowed.
	id := cfg.Identities["alex@example.com"]
	id.Platforms["github"] = Platform{Credentials: map[string]Credential{
		"read-only": {Type: "pat", Vault: "age://github/alex/ro.age"},
	}}
	cfg.Identities["alex@example.com"] = id
	cfg.Rules = append(cfg.Rules, Rule{
		ID:    "acme-github-ro",
		Match: RuleMatch{Client: "acme", Platform: StringOrList{"github"}},
		Use:   RuleUse{Identity: "alex@example.com", Access: "read-only"},
	})

	res := Validate(cfg)
	if hasWarningContaining(res, "acme-github-ro") {
		t.Errorf("did not expect acme-github-ro to be flagged as shadowed: %v", res.Warnings)
	}
}

func TestValidate_UnknownVaultBackend(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Vault.Backend = "sops"

	res := Validate(cfg)
	if !hasErrorContaining(res, `unknown backend "sops"`) {
		t.Errorf("errors did not flag the unsupported backend: %v", res.Errors)
	}
}

func TestValidate_UnsupportedVersion(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Version = 2

	res := Validate(cfg)
	if !hasErrorContaining(res, "unsupported version 2") {
		t.Errorf("errors did not flag the unsupported version: %v", res.Errors)
	}
}

func TestValidate_InvalidSidecarMaxAge(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Defaults.SidecarMaxAge = "not-a-duration"

	res := Validate(cfg)
	if !hasErrorContaining(res, "invalid duration") {
		t.Errorf("errors did not flag the invalid duration: %v", res.Errors)
	}
}
