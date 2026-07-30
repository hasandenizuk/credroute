// allow-claude-code: see describe.go header.
//
// This is the drift-check: for every command in internal/describe's
// manifest, it invokes the REAL cmdXxx function (the same one main.go
// dispatches to) with "--help", captures the flag.FlagSet's own usage
// text (stdlib's flag package prints it and returns flag.ErrHelp before
// any of the command's actual logic runs, since every command calls
// fs.Parse and returns immediately on error), and diffs the real flag
// names against what the manifest declares. A command whose flags this
// file's authors forget to update in internal/describe/manifest.go
// fails here, instead of silently drifting from what an agent would
// discover at runtime.
//
// This does not (and cannot, without a much larger refactor extracting
// every command's flag registration into a shared constructor) verify
// positional-argument names, "required"/"allowed values" metadata,
// purpose text, examples, or exit codes: the stdlib flag package has no
// representation for any of those. Only flag NAMES are mechanically
// checked.
package main

import (
	"bufio"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/hasandenizuk/credroute/internal/describe"
)

// commandFuncs maps a describe.Command.Name to the real function main.go
// dispatches to for it. Kept in this test file (not main.go) so adding a
// command here is a one-line, review-visible reminder to also add it to
// the manifest, and vice versa: TestDescribeManifest_CoversEveryDispatchedCommand
// below checks this map and the manifest have exactly the same key set.
var commandFuncs = map[string]func([]string) int{
	"init":             cmdInit,
	"resolve":          cmdResolve,
	"explain":          cmdExplain,
	"exec":             cmdExec,
	"login":            cmdLogin,
	"verify":           cmdVerify,
	"config validate":  cmdConfigValidate,
	"doctor":           cmdDoctor,
	"profiles ls":      cmdProfilesLs,
	"profiles show":    cmdProfilesShow,
	"adapter install":  cmdAdapterInstall,
	"audit":            cmdAudit,
	"identity add":     cmdIdentityAdd,
	"identity edit":    cmdIdentityEdit,
	"route add":        cmdRouteAdd,
	"route assign":     cmdRouteAssign,
	"route ls":         cmdRouteLs,
	"store add":        cmdStoreAdd,
	"store ls":         cmdStoreLs,
	"store remove":     cmdStoreRemove,
	"describe":         cmdDescribe,
	"handle get":       cmdHandleGet,
	"hook claude-code": cmdHookClaudeCode,
	// "version" is deliberately excluded: cmdVersion registers no
	// flag.FlagSet at all (see version.go), so there is nothing for
	// --help to print; it is still checked for manifest presence by
	// TestDescribeManifest_CoversEveryDispatchedCommand via
	// noFlagSetCommands below.
}

// noFlagSetCommands lists manifest commands that register no
// flag.FlagSet (so the --help capture below does not apply to them) but
// must still appear in the manifest.
var noFlagSetCommands = map[string]bool{
	"version": true,
}

var flagLineRE = regexp.MustCompile(`(?m)^  -(\S+)`)

// captureHelpFlagNames runs cmd([]string{"--help"}) with os.Stderr
// redirected to a pipe, and returns the set of flag names flag.PrintDefaults
// wrote (stdlib's default usage format is "  -name ...\n\t...", one flag
// per such line). cmd must return without side effects on --help, which
// holds for every command here because reorderArgsForFlagParse leaves
// "--help" as a token flag.Parse's internal help handling intercepts
// before any command's own logic runs.
func captureHelpFlagNames(t *testing.T, cmd func([]string) int) map[string]bool {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	cmd([]string{"--help"})
	os.Stderr = orig
	_ = w.Close()

	names := map[string]bool{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if m := flagLineRE.FindStringSubmatch(scanner.Text()); m != nil {
			names[m[1]] = true
		}
	}
	return names
}

// manifestFlagNames returns the flag-kind Param names a manifest command
// declares, plus the four global flag names if the command opts into
// them (Command.Globals).
func manifestFlagNames(cmd describe.Command) map[string]bool {
	names := map[string]bool{}
	for _, p := range cmd.Params {
		if p.Kind == "flag" {
			names[p.Name] = true
		}
	}
	if cmd.Globals {
		for _, p := range describe.GlobalParams() {
			names[p.Name] = true
		}
	}
	return names
}

func TestDescribeManifest_FlagsMatchRealFlagSets(t *testing.T) {
	for _, cmd := range describe.Manifest() {
		cmd := cmd
		if noFlagSetCommands[cmd.Name] {
			continue
		}
		t.Run(cmd.Name, func(t *testing.T) {
			fn, ok := commandFuncs[cmd.Name]
			if !ok {
				t.Fatalf("manifest command %q has no entry in commandFuncs; add one so this test can verify it", cmd.Name)
			}
			real := captureHelpFlagNames(t, fn)
			want := manifestFlagNames(cmd)

			for name := range want {
				if !real[name] {
					t.Errorf("manifest declares --%s but the real command has no such flag", name)
				}
			}
			for name := range real {
				if !want[name] {
					t.Errorf("real command has flag --%s but the manifest does not declare it", name)
				}
			}
		})
	}
}

// TestDescribeManifest_CoversEveryDispatchedCommand checks that
// commandFuncs (the real dispatch table this test drives) and the
// manifest name exactly the same set of commands, so a command added to
// main.go's run() without a matching manifest entry (or vice versa) is
// caught here rather than shipping undocumented or documented-but-fake.
func TestDescribeManifest_CoversEveryDispatchedCommand(t *testing.T) {
	manifestNames := map[string]bool{}
	for _, cmd := range describe.Manifest() {
		manifestNames[cmd.Name] = true
	}

	dispatched := map[string]bool{}
	for name := range commandFuncs {
		dispatched[name] = true
	}
	for name := range noFlagSetCommands {
		dispatched[name] = true
	}

	var onlyInManifest, onlyInDispatch []string
	for name := range manifestNames {
		if !dispatched[name] {
			onlyInManifest = append(onlyInManifest, name)
		}
	}
	for name := range dispatched {
		if !manifestNames[name] {
			onlyInDispatch = append(onlyInDispatch, name)
		}
	}
	sort.Strings(onlyInManifest)
	sort.Strings(onlyInDispatch)

	if len(onlyInManifest) > 0 {
		t.Errorf("manifest has commands not covered by this test's dispatch table: %v", onlyInManifest)
	}
	if len(onlyInDispatch) > 0 {
		t.Errorf("this test's dispatch table has commands missing from the manifest: %v", onlyInDispatch)
	}
}

// TestRunSwitchTopLevelCommandsAreDescribed closes the L5 (Fable 5 review
// v2) gap left by the two tests above: they mechanically cross-check the
// manifest against commandFuncs, but neither one is ever compared against
// main.go's REAL switch statement, so a command added to run() and
// forgotten in both places (manifest and commandFuncs alike) previously
// shipped undescribed with nothing to catch it.
//
// This parses cmd/credroute/main.go itself (go/parser, stdlib) and pulls
// every string case value out of run()'s switch, then checks each token
// is covered by an exact-match manifest/commandFuncs entry (for a
// single-word command like "audit") or a "token " prefix match (for a
// command that fans out into subcommands of its own, like "route" ->
// "route add"/"route assign"/"route ls").
func TestRunSwitchTopLevelCommandsAreDescribed(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var runDecl *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "run" {
			runDecl = fn
			break
		}
	}
	if runDecl == nil {
		t.Fatal("main.go: no func run found; this test needs updating to match main.go's structure")
	}

	ignore := map[string]bool{"-h": true, "--help": true, "help": true}
	var tokens []string
	ast.Inspect(runDecl.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range cc.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil || ignore[v] {
					continue
				}
				tokens = append(tokens, v)
			}
		}
		return true
	})
	if len(tokens) == 0 {
		t.Fatal("found no case tokens in run()'s switch; this test needs updating to match main.go's structure")
	}

	described := map[string]bool{}
	for _, cmd := range describe.Manifest() {
		described[cmd.Name] = true
	}
	for name := range commandFuncs {
		described[name] = true
	}
	for name := range noFlagSetCommands {
		described[name] = true
	}

	for _, tok := range tokens {
		if described[tok] {
			continue
		}
		found := false
		for name := range described {
			if strings.HasPrefix(name, tok+" ") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("run() dispatches command %q but no manifest/commandFuncs entry named %q or %q... describes it", tok, tok, tok+" ")
		}
	}
}

func TestCmdDescribe_JSONAndFilter(t *testing.T) {
	if code := cmdDescribe([]string{"--json"}); code != 0 {
		t.Fatalf("describe --json exit = %d, want 0", code)
	}
	if code := cmdDescribe([]string{"--json", "route add"}); code != 0 {
		t.Fatalf("describe --json 'route add' exit = %d, want 0", code)
	}
	if code := cmdDescribe([]string{"--json", "not-a-real-command"}); code != 1 {
		t.Errorf("describe of an unknown command exit = %d, want 1", code)
	}
}

func TestCmdDescribe_LookupIsCaseSensitiveExactMatch(t *testing.T) {
	if _, ok := describe.Lookup("route"); ok {
		t.Error("Lookup(\"route\") should not match \"route add\"/\"route ls\"/etc, want false")
	}
	if _, ok := describe.Lookup("route add"); !ok {
		t.Error("Lookup(\"route add\") should match, want true")
	}
}

func TestDescribeManifest_LoginDocumentsHelperExitPassthrough(t *testing.T) {
	cmd, ok := describe.Lookup("login")
	if !ok {
		t.Fatal("manifest missing login command")
	}
	if got := cmd.ExitCodes["helper"]; !strings.Contains(got, "returns that same helper exit code") {
		t.Fatalf("login helper exit documentation = %q, want pass-through note", got)
	}
	if got := cmd.ExitCodes["4"]; !strings.Contains(got, "snapshot") {
		t.Fatalf("login exit 4 documentation = %q, want login-specific slot failure note", got)
	}
}

func TestGlobalParams_NamesAreStable(t *testing.T) {
	got := map[string]bool{}
	for _, p := range describe.GlobalParams() {
		got[p.Name] = true
	}
	for _, want := range []string{"config", "json", "quiet", "v"} {
		if !got[want] {
			t.Errorf("GlobalParams missing %q", want)
		}
	}
}

// TestReorderArgsForFlagParse_HelpPassesThrough guards the assumption
// captureHelpFlagNames relies on: "--help" must survive
// reorderArgsForFlagParse unchanged (it is not a registered flag on any
// FlagSet here, so it must not be treated as a valued flag that eats the
// next token).
func TestReorderArgsForFlagParse_HelpPassesThrough(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("platform", "", "")
	got := reorderArgsForFlagParse(fs, []string{"--help"})
	if len(got) != 1 || got[0] != "--help" {
		t.Errorf("reorderArgsForFlagParse([--help]) = %v, want [--help]", got)
	}
}
