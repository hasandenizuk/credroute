// allow-claude-code: new multi-file build for the "agent-native command
// layer" milestone (roadmap.md section 4): shared plumbing for every
// command that edits config.yaml (identity add/edit, route add/assign).
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/config"
)

// withConfigEdit is the single entry point every config-editing command
// (identity add/edit, route add/assign) goes through. It:
//
//  1. Opens the config named by g.configPath (or the default resolution)
//     as an editable node tree.
//  2. Refuses (exit 1) if the config declares any include: files: safely
//     editing a multi-file config (which included file should a new
//     identity or rule land in?) is out of scope for this milestone; the
//     operator edits those by hand.
//  3. Runs mutate against the in-memory tree.
//  4. Re-decodes the WOULD-BE result and runs the exact same strict
//     schema + semantic check `credroute config validate` runs. Saving
//     only happens if that comes back clean, so a bad edit never reaches
//     disk.
//  5. Saves atomically and reports what happened.
//
// commandName is used only to prefix error/status messages (e.g.
// "identity add", "route assign"). target names the specific identity id
// or rule id being changed, recorded on the audit entry logged for a
// successful edit (M2, Fable 5 review v2).
func withConfigEdit(g *globalFlags, commandName, target string, mutate func(*config.Document) error) int {
	prefix := "credroute " + commandName

	doc, err := config.OpenDocument(g.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prefix, err)
		return 5
	}
	defer doc.Close()

	before, err := doc.Snapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: existing config does not parse, refusing to edit: %v\n", prefix, err)
		return 5
	}
	if len(before.Include) > 0 {
		fmt.Fprintf(os.Stderr, "%s: this config uses include: (%s); imperative editing of multi-file configs is not supported yet, edit the file by hand\n", prefix, strings.Join(before.Include, ", "))
		return 1
	}

	if err := mutate(doc); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prefix, err)
		return 1
	}

	after, err := doc.Snapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: edited config no longer parses: %v\n", prefix, err)
		return 5
	}
	result := config.Validate(after)
	if !result.OK() {
		fmt.Fprintf(os.Stderr, "%s: refusing to save; the edited config would be invalid (%d error(s)):\n", prefix, len(result.Errors))
		for _, e := range result.Errors {
			fmt.Fprintln(os.Stderr, "  "+e.String())
		}
		return 5
	}

	if err := doc.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prefix, err)
		return 1
	}

	_ = appendAuditOrWarn(audit.Entry{
		Op:         "config",
		Command:    commandName,
		Target:     target,
		ConfigPath: doc.Path,
		Exit:       0,
		Decision:   "allow",
		Caller:     auditCaller,
	})

	if !g.quiet {
		fmt.Printf("%s: saved %s\n", prefix, doc.Path)
		for _, w := range result.Warnings {
			fmt.Fprintln(os.Stderr, "  warning: "+w.String())
		}
	}
	return 0
}
