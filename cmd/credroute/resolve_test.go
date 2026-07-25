// allow-claude-code: see resolve.go header.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
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

func TestDoResolveRefusesObservedScopesAboveResolvedAccess(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	slot := filepath.Join(t.TempDir(), "gh-slot")
	handle := "age://github/alex/pat.age"
	if err := attest.Write(&attest.Record{
		Slot:              slot,
		VaultHandle:       handle,
		ExpectedIdentity:  "alex@example.com",
		ObservedIdentity:  "alex@example.com",
		IdentityConfirmed: true,
		Platform:          "github",
		AccessLevel:       "read-only",
		Status:            attest.StatusVerified,
		Method:            "http_whoami",
		ObservedScopes:    []string{"repo"},
	}); err != nil {
		t.Fatalf("attest.Write: %v", err)
	}

	cfgPath := writeTestConfig(t, fmt.Sprintf(`
version: 1
defaults: { verify: required, on_no_match: refuse }
identities:
  alex@example.com:
    platforms:
      github:
        credentials:
          read-only: { type: pat, vault: %s, slot: %s }
rules:
  - id: r1
    match: { platform: github }
    use: { identity: alex@example.com, access: read-only }
vault:
  backend: age
  age:
    store_dir: /tmp/store
    identity_file: /tmp/id.txt
`, handle, slot))

	resp, code := doResolve(cfgPath, "github", "", t.TempDir(), "", "")
	if code != 3 {
		t.Fatalf("doResolve exit code = %d, want 3; resp=%+v", code, resp)
	}
	if resp.Status != "mismatch" {
		t.Fatalf("status = %q, want mismatch", resp.Status)
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
