// allow-claude-code: see hook.go header.
package main

import (
	"encoding/json"
	"os"
	"strings"
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

	decision := evaluateClaudeCodeHook(payload, cfgPath, t.TempDir())
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

	decision := evaluateClaudeCodeHook(payload, "/nonexistent/config.yaml", t.TempDir())
	if !decision.Allow {
		t.Fatalf("evaluateClaudeCodeHook denied an unrelated command; reason=%q", decision.Reason)
	}
}

func TestEvaluateClaudeCodeHook_DeniesUnparseableJSONInsideClientRoot(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeTestConfig(t, `
version: 1
defaults: { on_no_match: refuse, verify: required }
clients:
  acme:
    roots: [`+root+`]
identities: {}
rules: []
vault:
  backend: age
  age: { store_dir: /tmp/store, identity_file: /tmp/id.txt }
`)
	decision := evaluateClaudeCodeHook([]byte("not json"), cfgPath, root)
	if decision.Allow {
		t.Fatal("evaluateClaudeCodeHook allowed unparseable input inside a configured client root")
	}
	if decision.Reason == "" {
		t.Fatal("expected a reason explaining the parse failure")
	}
}

func TestEvaluateClaudeCodeHook_DeniesUnparseableJSONWhenConfigMissing(t *testing.T) {
	decision := evaluateClaudeCodeHook([]byte("not json"), "/nonexistent/config.yaml", t.TempDir())
	if decision.Allow {
		t.Fatal("evaluateClaudeCodeHook should deny unparseable input when config cannot load")
	}
	if !strings.Contains(decision.Reason, "config") {
		t.Fatalf("reason = %q, want config load detail", decision.Reason)
	}
}

func TestEvaluateClaudeCodeHook_DeniesUnparseableJSONWhenConfigCannotLoad(t *testing.T) {
	cfgPath := writeTestConfig(t, "version: [")

	decision := evaluateClaudeCodeHook([]byte("not json"), cfgPath, t.TempDir())
	if decision.Allow {
		t.Fatalf("evaluateClaudeCodeHook allowed unparseable input with malformed config; reason=%q", decision.Reason)
	}
	if !strings.Contains(decision.Reason, "config") {
		t.Fatalf("reason = %q, want config load detail", decision.Reason)
	}
}

func TestCmdHookClaudeCode_DeniesUnreadableStdinWhenConfigCannotLoad(t *testing.T) {
	cfgPath := writeTestConfig(t, "version: [")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdin: %v", err)
	}
	_ = w.Close()
	_ = r.Close()
	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	code, stderr := captureStderr(t, func() int {
		return cmdHookClaudeCode([]string{"--config", cfgPath})
	})
	if code != 2 {
		t.Fatalf("cmdHookClaudeCode exit = %d, want deny exit 2", code)
	}
	if !strings.Contains(stderr, "config") {
		t.Fatalf("stderr = %q, want config load detail", stderr)
	}
}

func TestDetectHookPlatform_ParsesArgv(t *testing.T) {
	platform, err := detectHookPlatform("git clone https://github.com/foo/bar.git")
	if err != nil {
		t.Fatalf("detectHookPlatform: %v", err)
	}
	if platform != "" {
		t.Fatalf("git clone detected platform %q, want none", platform)
	}
	platform, err = detectHookPlatform(`g"h" auth token`)
	if err != nil {
		t.Fatalf("detectHookPlatform obfuscated gh: %v", err)
	}
	if platform != "github" {
		t.Fatalf("obfuscated gh detected platform %q, want github", platform)
	}
}

func TestDetectHookPlatform_AllowsBenignDoubleQuotedSubstitution(t *testing.T) {
	platform, err := detectHookPlatform(`echo "$(date)"`)
	if err != nil {
		t.Fatalf("detectHookPlatform benign substitution: %v", err)
	}
	if platform != "" {
		t.Fatalf("benign substitution detected platform %q, want none", platform)
	}
}

func TestDetectHookPlatform_DeniesQuotedCommandPositions(t *testing.T) {
	tests := []string{
		`eval '/usr/bin/gh auth token'`,
		`eval "gh auth token"`,
		`sh -c '/usr/bin/gh auth token'`,
		`ssh host '/usr/bin/gh auth token'`,
	}
	for _, tc := range tests {
		platform, err := detectHookPlatform(tc)
		if err != nil {
			t.Fatalf("detectHookPlatform(%q): %v", tc, err)
		}
		if platform != "github" {
			t.Fatalf("detectHookPlatform(%q) = %q, want github", tc, platform)
		}
	}
}

func TestDetectHookPlatform_DeniesCredentialBypassShapes(t *testing.T) {
	tests := []string{
		"echo x && gh auth token",
		"true; gh auth token",
		"GIT_PAGER=cat gh auth token",
		"sudo gh auth token",
		"bash -c 'gh auth token'",
		"$(gh auth token)",
		"`gh auth token`",
		`timeout 5 /usr/bin/gh auth token`,
		`nice -n 10 /usr/bin/gh auth token`,
		`stdbuf -o0 /usr/bin/gh auth token`,
		`setsid /usr/bin/gh auth token`,
		`flock /tmp/l /usr/bin/gh auth token`,
		`command /usr/bin/gh auth token`,
		`exec /usr/bin/gh auth token`,
		`eval "/usr/bin/gh auth token"`,
		`sudo -u alex /usr/bin/gh auth token`,
		`find . -name x -exec /usr/bin/gh auth token \;`,
		`xargs -I {} /usr/bin/gh auth token`,
		`cmd & /usr/bin/gh auth token`,
		`cmd |& /usr/bin/gh auth token`,
		`echo "$(g"h" auth token)"`,
	}
	for _, tc := range tests {
		platform, err := detectHookPlatform(tc)
		if err != nil {
			t.Fatalf("detectHookPlatform(%q): %v", tc, err)
		}
		if platform != "github" {
			t.Fatalf("detectHookPlatform(%q) = %q, want github", tc, platform)
		}
	}
}

func TestDetectHookPlatform_GitPushWithOptions(t *testing.T) {
	tests := []string{
		`git -C /repo push`,
		`git -c k=v push`,
		`git --git-dir=/repo/.git push`,
	}
	for _, tc := range tests {
		platform, err := detectHookPlatform(tc)
		if err != nil {
			t.Fatalf("detectHookPlatform(%q): %v", tc, err)
		}
		if platform != "github" {
			t.Fatalf("detectHookPlatform(%q) = %q, want github", tc, platform)
		}
	}
}

func TestDetectHookPlatform_AllowsOrdinaryDeveloperCommands(t *testing.T) {
	tests := []string{
		`git clone https://github.com/foo/bar.git`,
		`git clone git@github.com:foo/bar.git`,
		`curl https://github.com/foo/bar`,
		`open https://github.com/foo/bar`,
		`python -m pip install github-cli-tool`,
		`npm install github-slugger`,
		`rg github.com README.md`,
		`grep github.com README.md`,
		`ls /tmp/github-notes`,
		`cat docs/github.md`,
		`echo github.com/foo/bar`,
		`go env GOPATH`,
		`git status`,
		`git fetch origin main`,
		`git -- status`,
	}
	for _, tc := range tests {
		platform, err := detectHookPlatform(tc)
		if err != nil {
			t.Fatalf("detectHookPlatform(%q): %v", tc, err)
		}
		if platform != "" {
			t.Fatalf("detectHookPlatform(%q) = %q, want none", tc, platform)
		}
	}
}

func TestDetectHookPlatform_AllowsSingleQuotedCredentialLiteral(t *testing.T) {
	tests := []string{
		`echo 'gh auth token'`,
		`echo 'git push'`,
	}
	for _, tc := range tests {
		platform, err := detectHookPlatform(tc)
		if err != nil {
			t.Fatalf("detectHookPlatform(%q): %v", tc, err)
		}
		if platform != "" {
			t.Fatalf("detectHookPlatform(%q) = %q, want none", tc, platform)
		}
	}
}

func TestDetectHookPlatform_AllowsGithubURLButDeniesPlainCommand(t *testing.T) {
	allowed, err := detectHookPlatform("git clone https://github.com/foo/bar.git")
	if err != nil {
		t.Fatalf("detectHookPlatform url: %v", err)
	}
	if allowed != "" {
		t.Fatalf("github URL detected platform %q, want none", allowed)
	}

	denied, err := detectHookPlatform("gh auth token")
	if err != nil {
		t.Fatalf("detectHookPlatform command: %v", err)
	}
	if denied != "github" {
		t.Fatalf("plain gh command detected platform %q, want github", denied)
	}
}

func TestEvaluateClaudeCodeHook_DeniesCredentialCommandWhenConfigCannotLoad(t *testing.T) {
	cfgPath := writeTestConfig(t, "version: [")
	payload, err := json.Marshal(map[string]interface{}{
		"tool_name": "Bash",
		"tool_input": map[string]string{
			"command": "gh auth token",
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	decision := evaluateClaudeCodeHook(payload, cfgPath, t.TempDir())
	if decision.Allow {
		t.Fatalf("evaluateClaudeCodeHook allowed credential command with malformed config; reason=%q", decision.Reason)
	}
	if !strings.Contains(decision.Reason, "config") {
		t.Fatalf("reason = %q, want config load detail", decision.Reason)
	}

	_, stderr := captureStderr(t, func() int {
		return writeHookDecision(decision)
	})
	if !strings.Contains(stderr, "config") {
		t.Fatalf("stderr = %q, want config load detail", stderr)
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
