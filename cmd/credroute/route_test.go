// allow-claude-code: see route.go header.
package main

import (
	"os"
	"strings"
	"testing"
)

const routeTestConfigYAML = `version: 1
defaults:
  on_no_match: refuse
  verify: required
  sidecar_max_age: 24h
identities:
  alex@example.com:
    label: "Alex personal"
    platforms:
      github:
        credentials:
          read-write:
            type: pat
            vault: age://github/alex/pat.age
vault:
  backend: age
  age:
    store_dir: /tmp/vault
    identity_file: /tmp/id.txt
`

func TestCmdRouteAdd_AndLs(t *testing.T) {
	// M2 (Fable 5 review v2): route add/assign now append an audit entry
	// on success, so every test that succeeds must sandbox the state dir
	// rather than writing to the real machine's audit.jsonl.
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	path := writeTestConfig(t, routeTestConfigYAML)

	code := cmdRouteAdd([]string{"--config", path, "--platform", "github", "--identity", "alex@example.com", "--access", "read-write", "gh-rule"})
	if code != 0 {
		t.Fatalf("route add exit = %d, want 0", code)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "gh-rule") {
		t.Errorf("config after route add missing the new rule:\n%s", b)
	}

	code = cmdRouteLs([]string{"--config", path, "--json"})
	if code != 0 {
		t.Fatalf("route ls exit = %d, want 0", code)
	}
}

func TestCmdRouteAdd_MissingRequiredFlags(t *testing.T) {
	path := writeTestConfig(t, routeTestConfigYAML)
	code := cmdRouteAdd([]string{"--config", path, "--platform", "github", "gh-rule"})
	if code != 1 {
		t.Errorf("route add without --identity/--access exit = %d, want 1", code)
	}
}

func TestCmdRouteAdd_UndefinedIdentityRefused(t *testing.T) {
	path := writeTestConfig(t, routeTestConfigYAML)
	code := cmdRouteAdd([]string{"--config", path, "--platform", "github", "--identity", "nobody@example.com", "--access", "read-write", "bad-rule"})
	if code != 5 {
		t.Errorf("route add referencing an undefined identity exit = %d, want 5 (config invalid, refused before save)", code)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "bad-rule") {
		t.Error("an invalid route add must not be saved to disk")
	}
}

func TestCmdRouteAdd_InsertsBeforeCatchAll(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	withCatchAll := routeTestConfigYAML + `rules:
  - id: catch-all
    match: {}
    use: { identity: alex@example.com, access: read-write }
`
	path := writeTestConfig(t, withCatchAll)
	code := cmdRouteAdd([]string{"--config", path, "--platform", "github", "--identity", "alex@example.com", "--access", "read-write", "gh-rule"})
	if code != 0 {
		t.Fatalf("route add exit = %d, want 0", code)
	}
	cfg, err := loadAndValidate(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 2 || cfg.Rules[0].ID != "gh-rule" || cfg.Rules[1].ID != "catch-all" {
		var ids []string
		for _, r := range cfg.Rules {
			ids = append(ids, r.ID)
		}
		t.Errorf("rule order after add = %v, want [gh-rule catch-all]", ids)
	}
}

func TestCmdRouteAssign(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	withRule := routeTestConfigYAML + `rules:
  - id: gh-rule
    match: { platform: github }
    use: { identity: alex@example.com, access: read-only }
`
	path := writeTestConfig(t, withRule)
	code := cmdRouteAssign([]string{"--config", path, "--access", "read-write", "gh-rule"})
	if code != 0 {
		t.Fatalf("route assign exit = %d, want 0", code)
	}
	cfg, err := loadAndValidate(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules[0].Use.Access != "read-write" {
		t.Errorf("access after assign = %q, want read-write", cfg.Rules[0].Use.Access)
	}
}

func TestCmdRouteAssign_NothingToDo(t *testing.T) {
	withRule := routeTestConfigYAML + `rules:
  - id: gh-rule
    match: { platform: github }
    use: { identity: alex@example.com, access: read-only }
`
	path := writeTestConfig(t, withRule)
	if code := cmdRouteAssign([]string{"--config", path, "gh-rule"}); code != 1 {
		t.Errorf("route assign with no flags exit = %d, want 1", code)
	}
}

func TestCmdRouteAssign_UnknownRule(t *testing.T) {
	path := writeTestConfig(t, routeTestConfigYAML)
	code := cmdRouteAssign([]string{"--config", path, "--access", "read-write", "does-not-exist"})
	if code == 0 {
		t.Error("assigning an unknown rule id should fail, got exit 0")
	}
}
