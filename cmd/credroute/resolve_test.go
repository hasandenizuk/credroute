// allow-claude-code: see resolve.go header.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDoResolveRefusesNewerSyncConflictSibling(t *testing.T) {
	cfgPath := writeTestConfig(t, `
version: 1
defaults: { verify: required, on_no_match: refuse }
identities: {}
rules: []
vault:
  backend: age
  age:
    store_dir: /tmp/store
    identity_file: /tmp/id.txt
`)
	conflictPath := filepath.Join(filepath.Dir(cfgPath), "config.sync-conflict-20260725-120102-ABC123.yaml")
	if err := os.WriteFile(conflictPath, []byte("conflict"), 0o600); err != nil {
		t.Fatalf("write conflict sibling: %v", err)
	}
	newer := time.Now().Add(time.Hour)
	if err := os.Chtimes(conflictPath, newer, newer); err != nil {
		t.Fatalf("touch conflict sibling: %v", err)
	}

	resp, code := doResolve(cfgPath, "github", "", t.TempDir(), "", "")
	if code != 5 {
		t.Fatalf("doResolve exit code = %d, want 5; resp=%+v", code, resp)
	}
	if resp.Status != "config_error" {
		t.Fatalf("status = %q, want config_error", resp.Status)
	}
	if !strings.Contains(resp.Detail, conflictPath) {
		t.Fatalf("detail = %q, want exact conflict path %q", resp.Detail, conflictPath)
	}
}

func TestDoResolveRefusesGenericConflictedCopySibling(t *testing.T) {
	cfgPath := writeTestConfig(t, `
version: 1
defaults: { verify: required, on_no_match: refuse }
identities: {}
rules: []
vault:
  backend: age
  age:
    store_dir: /tmp/store
    identity_file: /tmp/id.txt
`)
	conflictPath := filepath.Join(filepath.Dir(cfgPath), "config (conflicted copy 2026-07-25).yaml")
	if err := os.WriteFile(conflictPath, []byte("conflict"), 0o600); err != nil {
		t.Fatalf("write conflict-like sibling: %v", err)
	}
	newer := time.Now().Add(time.Hour)
	if err := os.Chtimes(conflictPath, newer, newer); err != nil {
		t.Fatalf("touch conflict-like sibling: %v", err)
	}

	resp, code := doResolve(cfgPath, "github", "", t.TempDir(), "", "")
	if code != 5 {
		t.Fatalf("doResolve exit code = %d, want config refusal 5; resp=%+v", code, resp)
	}
	if resp.Status != "config_error" {
		t.Fatalf("status = %q, want config_error", resp.Status)
	}
	if !strings.Contains(resp.Detail, conflictPath) {
		t.Fatalf("detail = %q, want exact conflict path %q", resp.Detail, conflictPath)
	}
}

func TestDoResolveRefusesMalformedScopeProfileUnderRequiredVerify(t *testing.T) {
	profilesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(profilesDir, "github.yaml"), []byte("platform: ["), 0o600); err != nil {
		t.Fatalf("write malformed profile: %v", err)
	}
	t.Setenv("CREDROUTE_PROFILES_DIR", profilesDir)

	cfgPath := writeTestConfig(t, `
version: 1
defaults: { verify: required, on_no_match: refuse }
identities:
  alex@example.com:
    platforms:
      github:
        credentials:
          read-only: { type: pat, vault: age://github/alex/pat.age }
rules:
  - id: r1
    match: { platform: github }
    use: { identity: alex@example.com, access: read-only }
vault:
  backend: age
  age:
    store_dir: /tmp/store
    identity_file: /tmp/id.txt
`)

	resp, code := doResolve(cfgPath, "github", "", t.TempDir(), "", "")
	if code != 5 {
		t.Fatalf("doResolve exit code = %d, want 5; resp=%+v", code, resp)
	}
	if resp.Status != "config_error" {
		t.Fatalf("status = %q, want config_error", resp.Status)
	}
	if !strings.Contains(resp.Detail, "scope profiles") {
		t.Fatalf("detail = %q, want scope profile load detail", resp.Detail)
	}
}
