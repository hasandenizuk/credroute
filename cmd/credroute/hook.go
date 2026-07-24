// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 8) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
//
// `credroute hook claude-code` is F6's fix: Claude Code delivers PreToolUse
// hook input as JSON on stdin, not as $1 or an env var, so the old shell
// hook (reading $1/TOOL_INPUT_COMMAND) always saw an empty command and
// allowed everything through - the flagship harness's enforcement was a
// no-op. This subcommand does the real parsing and decision in Go, and
// the installed hook.sh template is now a thin `exec credroute hook
// claude-code` wrapper that just pipes stdin through (adapter.go/
// templates/claude-code/hook.sh).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func cmdHook(args []string) int {
	if len(args) == 0 || args[0] != "claude-code" {
		fmt.Fprintln(os.Stderr, "credroute hook: expected subcommand \"claude-code\"")
		return 1
	}
	return cmdHookClaudeCode(args[1:])
}

// claudeCodePreToolUseInput is the subset of Claude Code's PreToolUse hook
// JSON payload this command needs. Claude Code sends the attempted
// command in tool_input.command for the Bash tool; other tools are
// allowed through untouched (nothing credential-shaped to detect).
type claudeCodePreToolUseInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// hookDecision is this command's internal allow/deny verdict, before it is
// rendered to Claude Code's on-stdout JSON contract.
type hookDecision struct {
	Allow  bool
	Reason string
}

func cmdHookClaudeCode(args []string) int {
	fs := flag.NewFlagSet("hook claude-code", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to config.yaml (default: $CREDROUTE_CONFIG, else ~/.config/credroute/config.yaml)")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return writeHookDecision(hookDecision{Allow: true, Reason: fmt.Sprintf("could not read PreToolUse stdin: %v; failing open", err)})
	}
	decision := evaluateClaudeCodeHook(raw, *configPath)
	return writeHookDecision(decision)
}

// evaluateClaudeCodeHook is the pure decision logic, unit-testable without
// touching stdin/stdout: parse the PreToolUse payload, detect a
// credential-shaped platform from the attempted command (same detection
// list the old hook.sh used), and - only when one is detected - run
// credroute's own resolve+verify decision (doResolve, shared with
// `credroute resolve`) against it. A command with no detected platform, or
// a payload that fails to parse, allows through untouched: this hook only
// ever tightens a route the operator has actually configured, never
// blocks unrelated tool calls.
func evaluateClaudeCodeHook(raw []byte, configPath string) hookDecision {
	var in claudeCodePreToolUseInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return hookDecision{Allow: true, Reason: fmt.Sprintf("could not parse PreToolUse JSON: %v; failing open", err)}
	}

	platform := detectHookPlatform(in.ToolInput.Command)
	if platform == "" {
		return hookDecision{Allow: true, Reason: "no credentialed platform detected in this command"}
	}

	resp, exitCode := doResolve(configPath, platform, "", "", "", "")
	if exitCode == 0 {
		return hookDecision{Allow: true, Reason: fmt.Sprintf("credroute resolve ok: identity=%s platform=%s", resp.Identity, platform)}
	}
	return hookDecision{
		Allow:  false,
		Reason: fmt.Sprintf("credroute refused (%s, exit %d): %s. Run `credroute resolve --platform %s` for the remediation detail.", platform, exitCode, resp.Detail, platform),
	}
}

// detectHookPlatform infers a credentialed platform from an attempted
// shell command, mirroring the detection list the previous hook.sh
// shipped (F6 fixes HOW this runs, not the detection heuristic itself).
func detectHookPlatform(command string) string {
	switch {
	case containsAnySubstring(command, "gws", "gmail", "gdrive", "google", "gtm-ga4"):
		return "google"
	case containsAnySubstring(command, "gh ", "git push", "github"):
		return "github"
	default:
		return ""
	}
}

func containsAnySubstring(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// writeHookDecision renders d to stdout as Claude Code's PreToolUse
// hookSpecificOutput JSON contract (permissionDecision: "allow"/"deny",
// with a reason), and returns the matching process exit code: 0 for
// allow, 2 for deny (Claude Code's documented "blocking" exit code, shown
// to the model via stderr on other hooks; here the JSON on stdout is the
// primary channel and the exit code is a compatible fallback).
func writeHookDecision(d hookDecision) int {
	type hookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	}
	out := struct {
		HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
	}{}
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecisionReason = d.Reason
	exitCode := 0
	if d.Allow {
		out.HookSpecificOutput.PermissionDecision = "allow"
	} else {
		out.HookSpecificOutput.PermissionDecision = "deny"
		exitCode = 2
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	return exitCode
}
