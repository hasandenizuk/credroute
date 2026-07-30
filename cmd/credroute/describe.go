// allow-claude-code: new multi-file build for the "agent-native command
// layer" milestone (roadmap.md section 4): `credroute describe`, the
// self-description half. Serves internal/describe.Manifest() so an
// agent can discover every command's parameters at runtime rather than
// guessing from documentation that can go stale.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hasandenizuk/credroute/internal/describe"
)

func cmdDescribe(args []string) int {
	fs := flag.NewFlagSet("describe", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON instead of the human-readable listing")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}

	commands := describe.Manifest()
	if fs.NArg() > 0 {
		name := strings.Join(fs.Args(), " ")
		cmd, ok := describe.Lookup(name)
		if !ok {
			fmt.Fprintf(os.Stderr, "credroute describe: unknown command %q\n", name)
			return 1
		}
		commands = []describe.Command{cmd}
	}

	if *jsonOut || !isTerminal(os.Stdout) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(commands)
		return 0
	}

	for i, cmd := range commands {
		if i > 0 {
			fmt.Println()
		}
		printCommandHuman(cmd)
	}
	return 0
}

func printCommandHuman(cmd describe.Command) {
	fmt.Printf("credroute %s\n", cmd.Name)
	fmt.Printf("  %s\n", cmd.Purpose)

	params := cmd.Params
	if cmd.Globals {
		params = append(append([]describe.Param{}, params...), describe.GlobalParams()...)
	}
	if len(params) > 0 {
		fmt.Println("  params:")
		for _, p := range params {
			req := ""
			if p.Required {
				req = ", required"
			}
			allowed := ""
			if len(p.Allowed) > 0 {
				allowed = " (allowed: " + strings.Join(p.Allowed, ", ") + ")"
			}
			def := ""
			if p.Default != "" {
				def = " (default: " + p.Default + ")"
			}
			label := p.Name
			if p.Kind == "flag" {
				label = "--" + p.Name
			}
			fmt.Printf("    %-24s %s [%s%s]%s%s\n", label, p.Description, p.Type, req, allowed, def)
		}
	}
	if len(cmd.ExitCodes) > 0 {
		fmt.Println("  exit codes:")
		seen := map[string]bool{}
		for _, code := range []string{"0", "1", "2", "3", "4", "5"} {
			if msg, ok := cmd.ExitCodes[code]; ok {
				fmt.Printf("    %s  %s\n", code, msg)
				seen[code] = true
			}
		}
		var extra []string
		for code := range cmd.ExitCodes {
			if !seen[code] {
				extra = append(extra, code)
			}
		}
		sort.Strings(extra)
		for _, code := range extra {
			fmt.Printf("    %s  %s\n", code, cmd.ExitCodes[code])
		}
	}
	for _, ex := range cmd.Examples {
		fmt.Printf("  example: %s\n", ex)
	}
}
