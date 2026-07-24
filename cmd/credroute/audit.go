// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 9.3) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hasandenizuk/credroute/internal/audit"
)

func cmdAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	since := fs.String("since", "", "only show entries within this duration of now, e.g. 24h")
	platform := fs.String("platform", "", "filter by platform")
	identity := fs.String("identity", "", "filter by identity")
	failures := fs.Bool("failures", false, "only show refused / non-zero-exit entries")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	entries, err := audit.ReadAll()
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute audit:", err)
		return 1
	}

	filter := audit.Filter{Platform: *platform, Identity: *identity, FailuresOnly: *failures}
	if *since != "" {
		d, parseErr := time.ParseDuration(*since)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "credroute audit: invalid --since %q: %v\n", *since, parseErr)
			return 1
		}
		filter.Since = time.Now().UTC().Add(-d)
	}
	filtered := audit.Query(entries, filter)

	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(filtered)
		return 0
	}
	if g.quiet {
		return 0
	}
	if len(filtered) == 0 {
		fmt.Println("no matching audit entries")
		return 0
	}
	for _, e := range filtered {
		fmt.Printf("%s  %-8s %-7s platform=%-8s identity=%-28s access=%-11s verify=%-11s exit=%d rule=%s\n",
			e.TS.Format(time.RFC3339), e.Op, e.Decision, e.Platform, e.Identity, e.Access, e.Verification, e.Exit, e.Rule)
	}
	return 0
}
