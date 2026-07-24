// allow-claude-code: see internal/rules/glob.go header.
//
// credroute is the CLI entry point. This file holds flag/config helpers
// shared by every subcommand.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

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
	fs.StringVar(&g.configPath, "config", "", "path to config.yaml (default ~/.config/credroute/config.yaml)")
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
// directory.
func resolveQueryDir(dirFlag string) (string, error) {
	if dirFlag != "" {
		return dirFlag, nil
	}
	return os.Getwd()
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
