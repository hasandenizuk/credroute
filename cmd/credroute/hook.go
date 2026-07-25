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
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
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
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: credroute hook claude-code [--config path]\n\n")
		fmt.Fprintf(fs.Output(), "Reads Claude Code PreToolUse JSON from stdin and applies a best-effort command-name check before calling credroute resolve. This hook is a convenience guard, not a security boundary; renamed binaries and variable-expanded paths can avoid name-based detection.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		cwd, _ := os.Getwd()
		state := configuredClientRootState(*configPath, cwd)
		if state.Inside || state.Err != nil {
			if state.Err != nil {
				return writeHookDecision(hookDecision{Allow: false, Reason: fmt.Sprintf("could not read PreToolUse stdin: %v; could not load config: %v; refusing credential hook decision", err, state.Err)})
			}
			return writeHookDecision(hookDecision{Allow: false, Reason: fmt.Sprintf("could not read PreToolUse stdin: %v; refusing inside a configured client root", err)})
		}
		return writeHookDecision(hookDecision{Allow: true, Reason: fmt.Sprintf("could not read PreToolUse stdin: %v; no configured client root matched cwd", err)})
	}
	cwd, _ := os.Getwd()
	decision := evaluateClaudeCodeHook(raw, *configPath, cwd)
	return writeHookDecision(decision)
}

// evaluateClaudeCodeHook is the pure decision logic, unit-testable without
// touching stdin/stdout: parse the PreToolUse payload, detect a
// credential-shaped platform from the attempted command, and - only when
// one is detected - run credroute's own resolve+verify decision (doResolve,
// shared with `credroute resolve`) against it. This hook is a best-effort
// convenience guard, not a security boundary: renamed binaries, variables
// that expand to binaries, and equivalent shell tricks can avoid name-based
// detection. The security boundary remains the vault plus credroute's
// identity verification before secret handoff.
func evaluateClaudeCodeHook(raw []byte, configPath string, cwd string) hookDecision {
	var in claudeCodePreToolUseInput
	if err := json.Unmarshal(raw, &in); err != nil {
		state := configuredClientRootState(configPath, cwd)
		if state.Inside || state.Err != nil {
			if state.Err != nil {
				return hookDecision{Allow: false, Reason: fmt.Sprintf("could not parse PreToolUse JSON: %v; could not load config: %v; refusing credential hook decision", err, state.Err)}
			}
			return hookDecision{Allow: false, Reason: fmt.Sprintf("could not parse PreToolUse JSON: %v; refusing inside a configured client root", err)}
		}
		return hookDecision{Allow: true, Reason: fmt.Sprintf("could not parse PreToolUse JSON: %v; no configured client root matched cwd", err)}
	}

	platform, parseErr := detectHookPlatform(in.ToolInput.Command)
	if parseErr != nil {
		state := configuredClientRootState(configPath, cwd)
		if state.Inside || state.Err != nil {
			if state.Err != nil {
				return hookDecision{Allow: false, Reason: fmt.Sprintf("could not parse shell command: %v; could not load config: %v; refusing credential hook decision", parseErr, state.Err)}
			}
			return hookDecision{Allow: false, Reason: fmt.Sprintf("could not parse shell command: %v; refusing inside a configured client root", parseErr)}
		}
		return hookDecision{Allow: true, Reason: fmt.Sprintf("could not parse shell command: %v; no configured client root matched cwd", parseErr)}
	}
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

// detectHookPlatform infers a credentialed platform from an attempted shell
// command. It scans every token by basename so unknown wrappers do not turn
// into allow decisions, then falls back to bounded substring matching for
// malformed shell fragments the token pass cannot parse.
func detectHookPlatform(command string) (string, error) {
	return detectHookPlatformDepth(command, 0)
}

func detectHookPlatformDepth(command string, depth int) (string, error) {
	if depth > 4 {
		return "", fmt.Errorf("shell command nesting too deep")
	}
	commands, err := simpleShellCommands(command)
	if err != nil {
		return "", err
	}
	for _, cmd := range commands {
		platform, err := detectSimpleHookCommand(cmd, depth)
		if err != nil {
			return "", err
		}
		if platform != "" {
			return platform, nil
		}
	}
	return detectHookPlatformSubstring(command), nil
}

func detectSimpleHookCommand(command string, depth int) (string, error) {
	argv, err := splitShellCommand(command)
	if err != nil {
		return "", err
	}
	argv = dropLeadingEnvAssignments(argv)
	if len(argv) == 0 {
		return "", nil
	}
	prog := filepath.Base(argv[0])
	if isHookShell(prog) && len(argv) >= 3 && argv[1] == "-c" {
		return detectHookPlatformDepth(argv[2], depth+1)
	}
	if prog == "eval" && len(argv) >= 2 {
		return detectHookPlatformDepth(strings.Join(argv[1:], " "), depth+1)
	}
	if prog == "ssh" {
		if command, ok := sshCommandArg(argv[1:]); ok {
			return detectHookPlatformDepth(command, depth+1)
		}
	}
	for i, token := range argv {
		if isExternalReferenceToken(token) {
			continue
		}
		base := filepath.Base(token)
		if platform := platformForHookProgram(base, argv[i:]); platform != "" {
			return platform, nil
		}
	}
	return "", nil
}

func platformForHookProgram(prog string, argv []string) string {
	switch prog {
	case "gws", "gmail", "gdrive", "google", "gtm-ga4":
		return "google"
	case "gh", "github":
		return "github"
	case "git":
		if gitArgsContainPush(argv[1:]) {
			return "github"
		}
	}
	return ""
}

func gitArgsContainPush(argv []string) bool {
	for _, arg := range argv {
		if arg == "--" {
			return false
		}
		if arg == "push" {
			return true
		}
	}
	return false
}

func simpleShellCommands(command string) ([]string, error) {
	var commands []string
	var cur []rune
	var quote rune
	escaped := false
	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if escaped {
			cur = append(cur, r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			cur = append(cur, r)
			continue
		}
		if quote != 0 {
			if quote == '"' {
				if r == '`' {
					inner, end, err := readBacktick(runes, i+1)
					if err != nil {
						return nil, err
					}
					commands = appendNonEmpty(commands, inner)
					i = end
					continue
				}
				if r == '$' && i+1 < len(runes) && runes[i+1] == '(' {
					inner, end, err := readDollarParen(runes, i+2)
					if err != nil {
						return nil, err
					}
					commands = appendNonEmpty(commands, inner)
					i = end
					continue
				}
			}
			if r == quote {
				quote = 0
			}
			cur = append(cur, r)
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			cur = append(cur, r)
			continue
		}
		if r == '`' {
			inner, end, err := readBacktick(runes, i+1)
			if err != nil {
				return nil, err
			}
			commands = appendNonEmpty(commands, string(cur))
			commands = appendNonEmpty(commands, inner)
			cur = nil
			i = end
			continue
		}
		if r == '$' && i+1 < len(runes) && runes[i+1] == '(' {
			inner, end, err := readDollarParen(runes, i+2)
			if err != nil {
				return nil, err
			}
			commands = appendNonEmpty(commands, string(cur))
			commands = appendNonEmpty(commands, inner)
			cur = nil
			i = end
			continue
		}
		if isShellSeparator(runes, i) {
			commands = appendNonEmpty(commands, string(cur))
			cur = nil
			if (r == '&' || r == '|') && i+1 < len(runes) && runes[i+1] == r {
				i++
			}
			continue
		}
		cur = append(cur, r)
	}
	if escaped {
		return nil, fmt.Errorf("trailing escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	commands = appendNonEmpty(commands, string(cur))
	return commands, nil
}

func appendNonEmpty(commands []string, command string) []string {
	if strings.TrimSpace(command) == "" {
		return commands
	}
	return append(commands, command)
}

func isShellSeparator(runes []rune, i int) bool {
	switch runes[i] {
	case ';', '\n':
		return true
	case '|':
		return true
	case '&':
		return true
	}
	return false
}

func readBacktick(runes []rune, start int) (string, int, error) {
	var inner []rune
	escaped := false
	for i := start; i < len(runes); i++ {
		r := runes[i]
		if escaped {
			inner = append(inner, r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '`' {
			return string(inner), i, nil
		}
		inner = append(inner, r)
	}
	return "", 0, fmt.Errorf("unterminated command substitution")
}

func readDollarParen(runes []rune, start int) (string, int, error) {
	var inner []rune
	depth := 1
	var quote rune
	escaped := false
	for i := start; i < len(runes); i++ {
		r := runes[i]
		if escaped {
			inner = append(inner, r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			inner = append(inner, r)
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			inner = append(inner, r)
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			inner = append(inner, r)
			continue
		}
		if r == '(' {
			depth++
		}
		if r == ')' {
			depth--
			if depth == 0 {
				return string(inner), i, nil
			}
		}
		inner = append(inner, r)
	}
	return "", 0, fmt.Errorf("unterminated command substitution")
}

func dropLeadingEnvAssignments(argv []string) []string {
	for len(argv) > 0 && isEnvAssignment(argv[0]) {
		argv = argv[1:]
	}
	return argv
}

func isEnvAssignment(s string) bool {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return false
	}
	for n, r := range s[:i] {
		if n == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isHookShell(prog string) bool {
	return prog == "sh" || prog == "bash" || prog == "zsh"
}

func sshCommandArg(argv []string) (string, bool) {
	seenHost := false
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			if !seenHost && i+1 < len(argv) {
				seenHost = true
				i++
			}
			if seenHost && i+1 < len(argv) {
				return strings.Join(argv[i+1:], " "), true
			}
			return "", false
		}
		if !seenHost && strings.HasPrefix(arg, "-") {
			if sshOptionTakesValue(arg) && len(arg) == 2 {
				i++
			}
			continue
		}
		if !seenHost {
			seenHost = true
			continue
		}
		return strings.Join(argv[i:], " "), true
	}
	return "", false
}

func sshOptionTakesValue(arg string) bool {
	switch arg {
	case "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w":
		return true
	}
	return false
}

func isExternalReferenceToken(token string) bool {
	return strings.Contains(token, "://") || hookScpStylePattern.MatchString(token)
}

var (
	hookToolPattern     = regexp.MustCompile(`(^|[^A-Za-z0-9_:@-])(gws|gmail|gdrive|google|gtm-ga4|gh|github)([^A-Za-z0-9_-]|$)`)
	hookGitPushPattern  = regexp.MustCompile(`(^|[^A-Za-z0-9_./:@-])(git)(?:[[:space:]]+[^[:space:];|&]+)*[[:space:]]+push([^A-Za-z0-9_-]|$)`)
	hookScpStylePattern = regexp.MustCompile(`^[^[:space:]@]+@[^[:space:]:]+:.+$`)
)

func detectHookPlatformSubstring(command string) string {
	gitPushMatches := hookGitPushPattern.FindAllStringSubmatchIndex(command, -1)
	for _, match := range gitPushMatches {
		if len(match) < 6 {
			continue
		}
		if isInsideSingleQuotedShellSpan(command, match[4]) {
			continue
		}
		return "github"
	}
	matches := hookToolPattern.FindAllStringSubmatchIndex(command, -1)
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}
		if isInsideSingleQuotedShellSpan(command, match[4]) {
			continue
		}
		tool := command[match[4]:match[5]]
		if token, ok := containingShellToken(command, match[4], match[5]); ok {
			if isExternalReferenceToken(token) || filepath.Base(token) != tool {
				continue
			}
		}
		switch tool {
		case "gws", "gmail", "gdrive", "google", "gtm-ga4":
			return "google"
		case "gh", "github":
			return "github"
		}
	}
	return ""
}

func isInsideSingleQuotedShellSpan(command string, index int) bool {
	inSingle := false
	inDouble := false
	escaped := false
	for i, r := range command {
		if i >= index {
			break
		}
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
		}
	}
	return inSingle
}

func containingShellToken(command string, start, end int) (string, bool) {
	if start < 0 || end > len(command) || start >= end {
		return "", false
	}
	left := start
	for left > 0 && !isHookTokenBoundary(rune(command[left-1])) {
		left--
	}
	right := end
	for right < len(command) && !isHookTokenBoundary(rune(command[right])) {
		right++
	}
	return command[left:right], true
}

func isHookTokenBoundary(r rune) bool {
	return unicode.IsSpace(r) || r == '\'' || r == '"' || r == ';' || r == '|' || r == '&' || r == '(' || r == ')' || r == '{' || r == '}'
}

func splitShellCommand(command string) ([]string, error) {
	var argv []string
	var cur []rune
	var quote rune
	escaped := false
	for _, r := range command {
		if escaped {
			cur = append(cur, r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			cur = append(cur, r)
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' {
			if len(cur) > 0 {
				argv = append(argv, string(cur))
				cur = nil
			}
			continue
		}
		cur = append(cur, r)
	}
	if escaped {
		return nil, fmt.Errorf("trailing escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if len(cur) > 0 {
		argv = append(argv, string(cur))
	}
	return argv, nil
}

type clientRootState struct {
	Inside bool
	Err    error
}

func configuredClientRootState(configPath, cwd string) clientRootState {
	cfg, err := config.Load(configPath)
	if err != nil {
		return clientRootState{Err: err}
	}
	if cwd == "" {
		return clientRootState{}
	}
	if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = resolved
	}
	for _, client := range cfg.Clients {
		for _, root := range client.Roots {
			expanded, err := config.ExpandHome(root)
			if err != nil {
				continue
			}
			if resolved, err := filepath.EvalSymlinks(expanded); err == nil {
				expanded = resolved
			}
			if rules.MatchGlob(filepath.Join(expanded, "**"), cwd) || rules.MatchGlob(expanded, cwd) {
				return clientRootState{Inside: true}
			}
		}
	}
	return clientRootState{}
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
		fmt.Fprintln(os.Stderr, d.Reason)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	return exitCode
}
