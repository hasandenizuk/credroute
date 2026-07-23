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
