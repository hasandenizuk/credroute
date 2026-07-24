// allow-claude-code: see config.go header.
package config

import (
	"os"
	"path/filepath"
	"testing"
)

const minimalConfigYAML = `
version: 1
defaults:
  on_no_match: refuse
  verify: required
  sidecar_max_age: 24h
clients:
  acme:
    roots: ["~/Projects/client.acme/**"]
identities:
  alex@example.com:
    label: "Alex"
    platforms:
      google:
        credentials:
          read-only:
            type: oauth
            vault: age://google/alex/ro.age
          read-write:
            type: oauth
            vault: age://google/alex/rw.age
rules:
  - id: acme-gsc
    match: { client: acme, platform: google, task: [gsc, gsc-alt] }
    use: { identity: alex@example.com, access: read-only }
  - id: catchall
    use: { identity: alex@example.com, access: read-write }
vault:
  backend: age
  age:
    store_dir: ~/vault
    identity_file: ~/.config/credroute/age-identity.txt
`

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoad_ParsesMinimalConfig(t *testing.T) {
	path := writeTempConfig(t, minimalConfigYAML)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
	if cfg.Defaults.OnNoMatch != "refuse" {
		t.Errorf("OnNoMatch = %q, want refuse", cfg.Defaults.OnNoMatch)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(cfg.Rules))
	}
	if cfg.Rules[0].ID != "acme-gsc" {
		t.Errorf("rules[0].id = %q, want acme-gsc", cfg.Rules[0].ID)
	}
	// platform as a scalar string decodes into a one-element list.
	if got := cfg.Rules[0].Match.Platform; len(got) != 1 || got[0] != "google" {
		t.Errorf("rules[0].match.platform = %v, want [google]", got)
	}
	// task given as a YAML list decodes into a multi-element list.
	if got := cfg.Rules[0].Match.Task; len(got) != 2 || got[0] != "gsc" || got[1] != "gsc-alt" {
		t.Errorf("rules[0].match.task = %v, want [gsc gsc-alt]", got)
	}
	if !cfg.Rules[1].Match.IsEmpty() {
		t.Errorf("rules[1] (catchall) match should be empty, got %+v", cfg.Rules[1].Match)
	}
	identity, ok := cfg.Identities["alex@example.com"]
	if !ok {
		t.Fatal("missing identity alex@example.com")
	}
	if identity.Platforms["google"].Credentials["read-only"].Vault != "age://google/alex/ro.age" {
		t.Errorf("unexpected read-only vault handle: %+v", identity.Platforms["google"].Credentials["read-only"])
	}
}

func TestLoad_UnknownFieldIsAStrictError(t *testing.T) {
	bad := minimalConfigYAML + "\nunknown_top_level_key: true\n"
	path := writeTempConfig(t, bad)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown top-level field, got nil")
	}
}

func TestLoad_MissingFileIsAnError(t *testing.T) {
	if _, err := Load("/nonexistent/path/config.yaml"); err == nil {
		t.Fatal("expected an error for a missing config file, got nil")
	}
}

// TestLoad_CREDROUTE_CONFIG_Env is F10: an empty path argument falls back
// to CREDROUTE_CONFIG when it is set, and an explicit path always wins
// over it.
func TestLoad_CREDROUTE_CONFIG_Env(t *testing.T) {
	path := writeTempConfig(t, minimalConfigYAML)
	t.Setenv("CREDROUTE_CONFIG", path)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") with CREDROUTE_CONFIG set: %v", err)
	}
	if cfg.Path != path {
		t.Fatalf("cfg.Path = %q, want %q (CREDROUTE_CONFIG)", cfg.Path, path)
	}

	otherPath := writeTempConfig(t, minimalConfigYAML)
	cfg2, err := Load(otherPath)
	if err != nil {
		t.Fatalf("Load(explicit path) with CREDROUTE_CONFIG also set: %v", err)
	}
	if cfg2.Path != otherPath {
		t.Fatalf("explicit --config path did not win over CREDROUTE_CONFIG: got %q, want %q", cfg2.Path, otherPath)
	}
}

// TestLoad_Include is F11: a top-level include: list is merged into the
// including config rather than tripping KnownFields, clients/identities
// are unioned, and included rules are appended after the parent's own.
func TestLoad_Include(t *testing.T) {
	dir := t.TempDir()

	includedPath := filepath.Join(dir, "bluesky.yaml")
	includedYAML := `
version: 1
clients:
  bluesky:
    roots: ["~/Projects/client.bluesky/**"]
identities:
  bot@bluesky.io:
    label: "Bluesky bot"
    platforms:
      github:
        credentials:
          read-write:
            type: pat
            vault: age://github/bot/pat.age
rules:
  - id: bluesky-github
    match: { client: bluesky, platform: github }
    use: { identity: bot@bluesky.io, access: read-write }
`
	if err := os.WriteFile(includedPath, []byte(includedYAML), 0o644); err != nil {
		t.Fatalf("write included config: %v", err)
	}

	mainYAML := `
version: 1
defaults:
  on_no_match: refuse
  verify: required
include: ["bluesky.yaml"]
identities:
  alex@example.com:
    label: "Alex"
    platforms:
      google:
        credentials:
          read-only:
            type: oauth
            vault: age://google/alex/ro.age
rules:
  - id: catchall
    use: { identity: alex@example.com, access: read-only }
vault:
  backend: age
  age:
    store_dir: ~/vault
    identity_file: ~/.config/credroute/age-identity.txt
`
	mainPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(mainPath, []byte(mainYAML), 0o644); err != nil {
		t.Fatalf("write main config: %v", err)
	}

	cfg, err := Load(mainPath)
	if err != nil {
		t.Fatalf("Load with include:: %v", err)
	}
	if _, ok := cfg.Clients["bluesky"]; !ok {
		t.Fatal("included client \"bluesky\" was not merged in")
	}
	if _, ok := cfg.Identities["bot@bluesky.io"]; !ok {
		t.Fatal("included identity \"bot@bluesky.io\" was not merged in")
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("len(cfg.Rules) = %d, want 2 (1 parent + 1 included)", len(cfg.Rules))
	}
	if cfg.Rules[0].ID != "catchall" {
		t.Fatalf("cfg.Rules[0].ID = %q, want the parent's own rule first", cfg.Rules[0].ID)
	}
	if cfg.Rules[1].ID != "bluesky-github" {
		t.Fatalf("cfg.Rules[1].ID = %q, want the included rule appended after", cfg.Rules[1].ID)
	}
}

// TestLoad_Include_DuplicateKeyIsAnError: a client/identity id defined in
// both the parent and an include is a fail-closed error, never a silent
// overwrite.
func TestLoad_Include_DuplicateKeyIsAnError(t *testing.T) {
	dir := t.TempDir()

	includedPath := filepath.Join(dir, "dup.yaml")
	includedYAML := `
version: 1
identities:
  alex@example.com:
    label: "Duplicate Alex"
`
	if err := os.WriteFile(includedPath, []byte(includedYAML), 0o644); err != nil {
		t.Fatalf("write included config: %v", err)
	}

	mainPath := filepath.Join(dir, "config.yaml")
	mainYAML := minimalConfigYAML + "include: [\"dup.yaml\"]\n"
	if err := os.WriteFile(mainPath, []byte(mainYAML), 0o644); err != nil {
		t.Fatalf("write main config: %v", err)
	}

	if _, err := Load(mainPath); err == nil {
		t.Fatal("expected an error for a duplicate identity id across parent and include")
	}
}

func TestExpandHome(t *testing.T) {
	t.Setenv("HOME", "/home/testuser")

	cases := []struct {
		in   string
		want string
	}{
		{"~", "/home/testuser"},
		{"~/foo/bar", "/home/testuser/foo/bar"},
		{"/already/absolute", "/already/absolute"},
		{"", ""},
	}
	for _, tc := range cases {
		got, err := ExpandHome(tc.in)
		if err != nil {
			t.Fatalf("ExpandHome(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
