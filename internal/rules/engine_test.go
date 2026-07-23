// allow-claude-code: see glob.go header.
package rules

import (
	"testing"

	"github.com/hasandenizuk/credroute/internal/config"
)

func testConfig(withCatchall bool) *config.Config {
	cfg := &config.Config{
		Version: 1,
		Clients: map[string]config.Client{
			"acme": {Roots: []string{"~/Projects/client.acme/**"}},
		},
		Identities: map[string]config.Identity{
			"alex@example.com": {
				Label: "Alex personal",
				Platforms: map[string]config.Platform{
					"google": {Credentials: map[string]config.Credential{
						"read-write": {Type: "oauth", Vault: "age://google/alex/rw.age"},
					}},
					"github": {Credentials: map[string]config.Credential{
						"read-write": {Type: "pat", Vault: "age://github/alex/pat.age"},
					}},
				},
			},
			"reports@acme-corp.com": {
				Label: "Acme reporting",
				Platforms: map[string]config.Platform{
					"google": {Credentials: map[string]config.Credential{
						"read-only": {Type: "oauth", Vault: "age://google/reports/ro.age"},
					}},
				},
			},
		},
		Rules: []config.Rule{
			{
				ID:    "acme-gsc",
				Match: config.RuleMatch{Client: "acme", Platform: config.StringOrList{"google"}, Task: config.StringOrList{"gsc"}},
				Use:   config.RuleUse{Identity: "reports@acme-corp.com", Access: "read-only"},
			},
			{
				ID:    "acme-google-rw",
				Match: config.RuleMatch{Client: "acme", Platform: config.StringOrList{"google"}},
				Use:   config.RuleUse{Identity: "alex@example.com", Access: "read-write"},
			},
			{
				ID:    "personal-google",
				Match: config.RuleMatch{Dir: "~/Projects/personal/**", Platform: config.StringOrList{"google"}},
				Use:   config.RuleUse{Identity: "alex@example.com", Access: "read-write"},
			},
		},
	}
	if withCatchall {
		cfg.Rules = append(cfg.Rules, config.Rule{
			ID:  "catchall",
			Use: config.RuleUse{Identity: "alex@example.com", Access: "read-write"},
		})
	}
	return cfg
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	t.Setenv("HOME", "/home/testuser")
	cfg := testConfig(true)

	cases := []struct {
		name        string
		q           Query
		wantRule    string
		wantNoMatch bool
	}{
		{
			name:     "acme google with gsc task hits the narrow rule first",
			q:        Query{Dir: "/home/testuser/Projects/client.acme/project.audit", Platform: "google", Task: "gsc"},
			wantRule: "acme-gsc",
		},
		{
			name:     "acme google without task falls through to the broad acme rule",
			q:        Query{Dir: "/home/testuser/Projects/client.acme/project.audit", Platform: "google"},
			wantRule: "acme-google-rw",
		},
		{
			name:     "acme google with an unrelated task still falls through (task never matches without exact tag)",
			q:        Query{Dir: "/home/testuser/Projects/client.acme/project.audit", Platform: "google", Task: "other"},
			wantRule: "acme-google-rw",
		},
		{
			name:     "personal dir google hits the personal rule",
			q:        Query{Dir: "/home/testuser/Projects/personal/hobby", Platform: "google"},
			wantRule: "personal-google",
		},
		{
			name:     "acme dir but github platform falls through to catchall",
			q:        Query{Dir: "/home/testuser/Projects/client.acme/project.audit", Platform: "github"},
			wantRule: "catchall",
		},
		{
			name:     "unrelated dir and platform hits catchall",
			q:        Query{Dir: "/home/testuser/Projects/other/whatever", Platform: "clickup"},
			wantRule: "catchall",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(cfg, tc.q)
			if err != nil {
				t.Fatalf("Evaluate error: %v", err)
			}
			if tc.wantNoMatch {
				if result.Resolution != nil {
					t.Fatalf("expected no match, got rule %q", result.Resolution.Rule.ID)
				}
				return
			}
			if result.Resolution == nil {
				t.Fatalf("expected match %q, got no match", tc.wantRule)
			}
			if result.Resolution.Rule.ID != tc.wantRule {
				t.Errorf("matched rule = %q, want %q", result.Resolution.Rule.ID, tc.wantRule)
			}
		})
	}
}

func TestEvaluate_NoMatchRefuses(t *testing.T) {
	t.Setenv("HOME", "/home/testuser")
	cfg := testConfig(false) // no catchall rule

	result, err := Evaluate(cfg, Query{Dir: "/home/testuser/Projects/other/whatever", Platform: "clickup"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Resolution != nil {
		t.Fatalf("expected no match (fail closed), got rule %q", result.Resolution.Rule.ID)
	}
	if len(result.Trace) != len(cfg.Rules) {
		t.Fatalf("trace has %d entries, want %d (every rule should be evaluated when nothing matches)", len(result.Trace), len(cfg.Rules))
	}
	for _, tr := range result.Trace {
		if tr.Matched {
			t.Errorf("rule %q unexpectedly reported matched=true", tr.RuleID)
		}
	}
}

func TestEvaluate_OrderingBeatsSpecificity(t *testing.T) {
	// A broad rule placed before a narrow rule wins even though the
	// narrow rule would also match: document order is the only
	// precedence (spec 3.2), no specificity scoring.
	t.Setenv("HOME", "/home/testuser")
	cfg := &config.Config{
		Version: 1,
		Identities: map[string]config.Identity{
			"alex@example.com": {Platforms: map[string]config.Platform{
				"google": {Credentials: map[string]config.Credential{"read-write": {Type: "oauth", Vault: "age://a"}}},
			}},
			"reports@acme-corp.com": {Platforms: map[string]config.Platform{
				"google": {Credentials: map[string]config.Credential{"read-only": {Type: "oauth", Vault: "age://b"}}},
			}},
		},
		Rules: []config.Rule{
			{ID: "broad-first", Match: config.RuleMatch{Platform: config.StringOrList{"google"}}, Use: config.RuleUse{Identity: "alex@example.com", Access: "read-write"}},
			{ID: "narrow-second", Match: config.RuleMatch{Platform: config.StringOrList{"google"}, Task: config.StringOrList{"gsc"}}, Use: config.RuleUse{Identity: "reports@acme-corp.com", Access: "read-only"}},
		},
	}

	result, err := Evaluate(cfg, Query{Dir: "/home/testuser/anywhere", Platform: "google", Task: "gsc"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Resolution == nil || result.Resolution.Rule.ID != "broad-first" {
		got := "no match"
		if result.Resolution != nil {
			got = result.Resolution.Rule.ID
		}
		t.Fatalf("expected broad-first to win by ordering, got %s", got)
	}
}

func TestEvaluate_TraceStopsAnnotatingAfterWinner(t *testing.T) {
	t.Setenv("HOME", "/home/testuser")
	cfg := testConfig(true)

	result, err := Evaluate(cfg, Query{Dir: "/home/testuser/Projects/client.acme/x", Platform: "google", Task: "gsc"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if len(result.Trace) != len(cfg.Rules) {
		t.Fatalf("trace length = %d, want %d", len(result.Trace), len(cfg.Rules))
	}
	if !result.Trace[0].Matched || !result.Trace[0].Evaluated {
		t.Fatalf("winning rule 0 should be matched and evaluated: %+v", result.Trace[0])
	}
	for i := 1; i < len(result.Trace); i++ {
		if result.Trace[i].Evaluated {
			t.Errorf("rule %d (%s) should not be evaluated after the winner was found", i, result.Trace[i].RuleID)
		}
	}
}

func TestEvaluate_ConditionsComputedForEveryRuleEvenAfterWinner(t *testing.T) {
	// The engine always evaluates every rule's conditions (not just up to
	// the winner) so `explain --all` has real MISS data to show, per the
	// spec: "why did rule 7 not fire" must be answerable.
	t.Setenv("HOME", "/home/testuser")
	cfg := testConfig(true)

	result, err := Evaluate(cfg, Query{Dir: "/home/testuser/Projects/client.acme/x", Platform: "google", Task: "gsc"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	// rules[1] ("acme-google-rw") did not win (acme-gsc won at index 0)
	// but should still carry its own condition-by-condition trace.
	rule1 := result.Trace[1]
	if rule1.Evaluated {
		t.Fatalf("rule[1] should be marked not-evaluated for the default explain view")
	}
	if len(rule1.Conditions) == 0 {
		t.Fatalf("rule[1] should still have its conditions computed for explain --all, got none")
	}
	for _, c := range rule1.Conditions {
		if c.Key == "platform" && !c.Pass {
			t.Errorf("rule[1] platform condition should pass (both rules target google): %+v", c)
		}
	}
}

func TestEvaluate_ResolvesCredentialForPlatform(t *testing.T) {
	t.Setenv("HOME", "/home/testuser")
	cfg := testConfig(true)

	result, err := Evaluate(cfg, Query{Dir: "/home/testuser/Projects/client.acme/x", Platform: "google", Task: "gsc"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	res := result.Resolution
	if res == nil {
		t.Fatal("expected a match")
	}
	if !res.CredentialFound {
		t.Fatal("expected credential to be found for reports@acme-corp.com/google/read-only")
	}
	if res.Credential.Vault != "age://google/reports/ro.age" {
		t.Errorf("vault handle = %q, want age://google/reports/ro.age", res.Credential.Vault)
	}
	if res.IdentityLabel != "Acme reporting" {
		t.Errorf("identity label = %q, want %q", res.IdentityLabel, "Acme reporting")
	}
}
