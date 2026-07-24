// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 8) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/hasandenizuk/credroute/internal/adapter"
)

func cmdAdapter(args []string) int {
	if len(args) == 0 || args[0] != "install" {
		fmt.Fprintln(os.Stderr, "credroute adapter: expected subcommand \"install\"")
		return 1
	}
	return cmdAdapterInstall(args[1:])
}

func cmdAdapterInstall(args []string) int {
	fs := flag.NewFlagSet("adapter install", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	dirFlag := fs.String("dir", "", "target directory (default: the adapter's conventional location)")
	dryRun := fs.Bool("dry-run", false, "print what would be written without writing")
	force := fs.Bool("force", false, "overwrite files that already exist")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute adapter install: expected exactly one adapter name (claude-code, codex, agy)")
		return 1
	}

	kind, err := adapter.ParseKind(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute adapter install:", err)
		return 1
	}

	result, err := adapter.Install(kind, adapter.InstallOptions{Dir: *dirFlag, DryRun: *dryRun, Force: *force})
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute adapter install:", err)
		return 1
	}

	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return 0
	}
	if g.quiet {
		return 0
	}
	fmt.Printf("adapter %s -> %s\n", result.Kind, result.Dir)
	for _, f := range result.Files {
		state := "written"
		switch {
		case *dryRun && f.Exists:
			state = "would write (exists, needs --force)"
		case *dryRun:
			state = "would write"
		case f.Skipped:
			state = "skipped (exists, use --force to overwrite)"
		}
		fmt.Printf("  %-32s %s\n", state, f.Path)
	}
	return 0
}
