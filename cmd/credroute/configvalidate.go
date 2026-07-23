// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hasandenizuk/credroute/internal/config"
)

func cmdConfigValidate(args []string) int {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	path := g.configPath
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute config validate:", err)
		return 5
	}

	result := config.Validate(cfg)
	for _, w := range result.Warnings {
		fmt.Printf("WARNING %s\n", w.String())
	}
	for _, e := range result.Errors {
		fmt.Printf("ERROR   %s\n", e.String())
	}

	if !result.OK() {
		fmt.Fprintf(os.Stderr, "credroute config validate: %d error(s), %d warning(s)\n", len(result.Errors), len(result.Warnings))
		return 5
	}

	if !g.quiet {
		fmt.Printf("config valid: %s (%d rule(s), %d identitie(s), %d client(s), %d warning(s))\n",
			cfg.Path, len(cfg.Rules), len(cfg.Identities), len(cfg.Clients), len(result.Warnings))
	}
	return 0
}
