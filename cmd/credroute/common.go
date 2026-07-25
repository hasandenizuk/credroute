// allow-claude-code: see internal/rules/glob.go header.
//
// credroute is the CLI entry point. This file holds flag/config helpers
// shared by every subcommand.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/config"
)

// globalFlags are accepted by every subcommand: --config, --json,
// --quiet, -v.
type globalFlags struct {
	configPath string
	jsonOut    bool
	quiet      bool
	verbose    bool
}

func addGlobalFlags(fs *flag.FlagSet, g *globalFlags) {
	fs.StringVar(&g.configPath, "config", "", "path to config.yaml (default: $CREDROUTE_CONFIG, else ~/.config/credroute/config.yaml)")
	fs.BoolVar(&g.jsonOut, "json", false, "emit machine-readable JSON")
	fs.BoolVar(&g.quiet, "quiet", false, "suppress non-essential output")
	fs.BoolVar(&g.verbose, "v", false, "verbose output")
}

// wantJSON reports whether output should be JSON: explicit --json, or
// stdout is not a terminal (per spec 4.2, JSON is the default when stdout
// is not a TTY).
func wantJSON(g *globalFlags) bool {
	if g.jsonOut {
		return true
	}
	return !isTerminal(os.Stdout)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// loadAndValidate loads the config at path (or the default path if empty)
// and runs semantic validation. Returns an error suitable for direct
// display if either step fails.
func loadAndValidate(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if conflictPath, err := config.NewerSyncConflictSibling(cfg.Path); err != nil {
		return nil, err
	} else if conflictPath != "" {
		return nil, fmt.Errorf("newer sync-conflict sibling found next to config: %s", conflictPath)
	}
	result := config.Validate(cfg)
	if !result.OK() {
		var msgs []string
		for _, e := range result.Errors {
			msgs = append(msgs, e.String())
		}
		return nil, fmt.Errorf("config invalid (%d error(s)):\n  %s", len(result.Errors), strings.Join(msgs, "\n  "))
	}
	return cfg, nil
}

// resolveQueryDir returns dirFlag if set, otherwise the current working
// directory, with symlinks resolved (F8, spec 3.1: matching happens
// "after ~ and symlink expansion") before any client-root/glob match ever
// sees it. A dir that does not exist yet, or that EvalSymlinks otherwise
// cannot resolve, is passed through unresolved rather than failing
// resolve/exec outright; the glob match then simply finds no client root
// for it, which is the existing fail-closed behavior for an unmatched dir.
func resolveQueryDir(dirFlag string) (string, error) {
	dir := dirFlag
	if dir == "" {
		d, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = d
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	return dir, nil
}

// decisionFor maps an exit code to the audit log's coarse allow/refuse
// decision (spec 9.3: "decision":"allow"/"refuse"). Only exit 0 allows;
// every non-zero exit is a refusal of some kind.
func decisionFor(exitCode int) string {
	if exitCode == 0 {
		return "allow"
	}
	return "refuse"
}

// auditCaller is the caller label recorded on every audit entry logged
// directly by this CLI (as opposed to a harness adapter calling
// credroute itself, which would pass its own caller label if this were
// exposed as a flag; milestone 3 keeps it fixed).
const auditCaller = "cli"

func appendAuditOrWarn(entry audit.Entry) error {
	if err := audit.Append(entry); err != nil {
		fmt.Fprintf(os.Stderr, "credroute: warning: audit entry was not written: %v\n", err)
		return err
	}
	return nil
}

func stateDirForOutput() string {
	if os.Getenv("CREDROUTE_STATE_DIR") == "" {
		return ""
	}
	dir, err := audit.StateDir()
	if err != nil {
		return ""
	}
	return dir
}

// reorderArgsForFlagParse reorders args so every flag (and its value, if
// it takes one) is grouped before the positional arguments, working
// around the stdlib flag package's behavior of stopping flag parsing at
// the first non-flag argument (F13: documented forms like
// "handle get <handle> --to-file x" and "adapter install <name> --force"
// must both work, with flags in any position). fs must already have every
// flag registered (via *Var calls) so a boolean flag (no attached value)
// can be told apart from a valued one. A literal "--" and everything
// after it is left exactly where it is and never reordered, so a command
// like `exec --platform google -- gws --profile x` still hands its own
// flags to the child process untouched.
func reorderArgsForFlagParse(fs *flag.FlagSet, args []string) []string {
	var flags, positionals []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				// "--flag=value" or "-flag=value": one self-contained token.
				flags = append(flags, a)
				i++
				continue
			}
			fl := fs.Lookup(name)
			flags = append(flags, a)
			i++
			if fl == nil {
				// Unknown flag: leave the rest alone and let flag.Parse
				// produce its normal "flag provided but not defined"
				// error once it reaches this token.
				continue
			}
			if isBoolFlag(fl) {
				continue
			}
			// A valued flag given as two tokens: the next token is its
			// value (the "--flag=value" single-token form was handled
			// above).
			if i < len(args) {
				flags = append(flags, args[i])
				i++
			}
			continue
		}
		positionals = append(positionals, a)
		i++
	}
	return append(flags, positionals...)
}

// isBoolFlag reports whether fl's Value implements the stdlib's unexported
// "boolFlag" convention (an IsBoolFlag() bool method), which is how
// flag.Bool-created flags are recognized as taking no separate value.
func isBoolFlag(fl *flag.Flag) bool {
	type boolFlag interface{ IsBoolFlag() bool }
	bf, ok := fl.Value.(boolFlag)
	return ok && bf.IsBoolFlag()
}
