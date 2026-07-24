// allow-claude-code: see hook.go header.
package main

import (
	"encoding/json"
	"testing"

	"github.com/hasandenizuk/credroute/internal/attest"
)

// TestEvaluateClaudeCodeHook_DeniesOnMismatch is F6: feed a realistic
// Claude Code PreToolUse payload (JSON, tool_input.command - exactly the
// shape the old $1/TOOL_INPUT_COMMAND-reading hook.sh could never see) for
// a github-shaped command, with the credential's attestation sidecar
// already recording a mismatch. The hook must deny.
func TestEvaluateClaudeCodeHook_DeniesOnMismatch(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	slot := "/tmp/does-not-need-to-exist-for-this-test/gh-slot"
	vaultHandle := "age://github/alex/pat.age"
	if err := attest.Write(&attest.Record{
		Slot:             slot,
		VaultHandle:      vaultHandle,
		ExpectedIdentity: "alex@example.com",
		ObservedIdentity: "someone-else",
		Status:           attest.StatusMismatch,
		Method:           "http_whoami",
	}); err != nil {
		t.Fatalf("attest.Write: %v", err)
	}

	cfgYAML := `
version: 1
defaults:
  on_no_match: refuse
  verify: required
identities:
  alex@example.com:
    label: "Alex"
    platforms:
      github:
        credentials:
          read-write:
            type: pat
            vault: age://github/alex/pat.age
            slot: ` + slot + `
rules:
  - id: r1
    match: { platform: github }
    use: { identity: alex@example.com, access: read-write }
vault:
  backend: age
  age:
    store_dir: /tmp/does-not-need-to-exist-for-this-test/store
    identity_file: /tmp/does-not-need-to-exist-for-this-test/identity.txt
`
	cfgPath := writeTestConfig(t, cfgYAML)

	payload, err := json.Marshal(map[string]interface{}{
		"tool_name": "Bash",
		"tool_input": map[string]string{
			"command": "gh pr create --title x",
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	decision := evaluateClaudeCodeHook(payload, cfgPath)
	if decision.Allow {
		t.Fatalf("evaluateClaudeCodeHook allowed a github command over a mismatched credential; reason=%q", decision.Reason)
	}
	if decision.Reason == "" {
		t.Fatal("a deny decision must always explain why")
	}
}

// TestEvaluateClaudeCodeHook_AllowsUnrelatedCommand: a command with no
// detected credentialed platform must allow through untouched (this hook
// only ever tightens a route the operator actually configured).
func TestEvaluateClaudeCodeHook_AllowsUnrelatedCommand(t *testing.T) {
	payload, err := json.Marshal(map[string]interface{}{
		"tool_name": "Bash",
		"tool_input": map[string]string{
			"command": "ls -la",
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	decision := evaluateClaudeCodeHook(payload, "/nonexistent/config.yaml")
	if !decision.Allow {
		t.Fatalf("evaluateClaudeCodeHook denied an unrelated command; reason=%q", decision.Reason)
	}
}

// TestEvaluateClaudeCodeHook_FailsOpenOnUnparseableJSON: the old hook.sh's
// bug was silently seeing an empty command; the new one must instead
// visibly fail open (allow, with a reason saying why) rather than crash
// or hang, if it is ever fed something that is not valid PreToolUse JSON.
func TestEvaluateClaudeCodeHook_FailsOpenOnUnparseableJSON(t *testing.T) {
	decision := evaluateClaudeCodeHook([]byte("not json"), "/nonexistent/config.yaml")
	if !decision.Allow {
		t.Fatal("evaluateClaudeCodeHook did not fail open on unparseable input")
	}
	if decision.Reason == "" {
		t.Fatal("expected a reason explaining the parse failure")
	}
}

// TestWriteHookDecision_ExitCodes checks the Claude Code hook decision
// contract's exit code mapping (0 allow, 2 deny).
func TestWriteHookDecision_ExitCodes(t *testing.T) {
	if code := writeHookDecision(hookDecision{Allow: true, Reason: "ok"}); code != 0 {
		t.Fatalf("allow exit code = %d, want 0", code)
	}
	if code := writeHookDecision(hookDecision{Allow: false, Reason: "no"}); code != 2 {
		t.Fatalf("deny exit code = %d, want 2", code)
	}
}
