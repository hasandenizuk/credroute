// allow-claude-code: new multi-file build for the "agent-native command
// layer" milestone (roadmap.md section 4): `route add` / `route assign` /
// `route ls`, imperative commands so an operator or agent never
// hand-writes rules[] in config.yaml.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hasandenizuk/credroute/internal/config"
)

func cmdRoute(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "credroute route: expected subcommand \"add\", \"assign\", or \"ls\"")
		return 1
	}
	switch args[0] {
	case "add":
		return cmdRouteAdd(args[1:])
	case "assign":
		return cmdRouteAssign(args[1:])
	case "ls":
		return cmdRouteLs(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "credroute route: unknown subcommand %q (expected: add, assign, ls)\n", args[0])
		return 1
	}
}

func cmdRouteAdd(args []string) int {
	fs := flag.NewFlagSet("route add", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	client := fs.String("client", "", "match.client: sugar for \"dir matches clients.<name>.roots\"")
	dir := fs.String("dir", "", "match.dir glob")
	var platforms, tasks stringList
	fs.Var(&platforms, "platform", "match.platform (repeatable for a list)")
	fs.Var(&tasks, "task", "match.task (repeatable for a list)")
	identity := fs.String("identity", "", "use.identity (required)")
	access := fs.String("access", "", "use.access: read-only or read-write (required)")
	verify := fs.String("verify", "", "use.verify override: on or off (default: inherit defaults.verify)")
	index := fs.Int("index", -1, "0-based insert position; default -1 means append, but before a trailing catch-all rule if one exists")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute route add: expected exactly one rule id")
		return 1
	}
	id := fs.Arg(0)
	if *identity == "" || *access == "" {
		fmt.Fprintln(os.Stderr, "credroute route add: --identity and --access are required")
		return 1
	}

	rule := config.Rule{
		ID: id,
		Match: config.RuleMatch{
			Client:   *client,
			Dir:      *dir,
			Platform: config.StringOrList(platforms),
			Task:     config.StringOrList(tasks),
		},
		Use: config.RuleUse{
			Identity: *identity,
			Access:   *access,
			Verify:   *verify,
		},
	}

	return withConfigEdit(g, "route add", id, func(doc *config.Document) error {
		return doc.AddRule(rule, *index)
	})
}

func cmdRouteAssign(args []string) int {
	fs := flag.NewFlagSet("route assign", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	identity := fs.String("identity", "", "new use.identity")
	access := fs.String("access", "", "new use.access")
	verify := fs.String("verify", "", "new use.verify (on/off); pass --verify= (empty) to clear the override back to defaults.verify")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute route assign: expected exactly one rule id")
		return 1
	}
	ruleID := fs.Arg(0)

	var setIdentity, setAccess, setVerify *string
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "identity":
			v := *identity
			setIdentity = &v
		case "access":
			v := *access
			setAccess = &v
		case "verify":
			v := *verify
			setVerify = &v
		}
	})
	if setIdentity == nil && setAccess == nil && setVerify == nil {
		fmt.Fprintln(os.Stderr, "credroute route assign: nothing to do (pass --identity, --access, and/or --verify)")
		return 1
	}

	return withConfigEdit(g, "route assign", ruleID, func(doc *config.Document) error {
		return doc.AssignRule(ruleID, setIdentity, setAccess, setVerify)
	})
}

// routeSummary is the `route ls` JSON/table row shape.
type routeSummary struct {
	ID       string   `json:"id"`
	Client   string   `json:"client,omitempty"`
	Dir      string   `json:"dir,omitempty"`
	Platform []string `json:"platform,omitempty"`
	Task     []string `json:"task,omitempty"`
	Identity string   `json:"identity"`
	Access   string   `json:"access"`
	Verify   string   `json:"verify,omitempty"`
}

func cmdRouteLs(args []string) int {
	fs := flag.NewFlagSet("route ls", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute route ls:", err)
		return 5
	}

	summaries := make([]routeSummary, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		summaries = append(summaries, routeSummary{
			ID:       r.ID,
			Client:   r.Match.Client,
			Dir:      r.Match.Dir,
			Platform: []string(r.Match.Platform),
			Task:     []string(r.Match.Task),
			Identity: r.Use.Identity,
			Access:   r.Use.Access,
			Verify:   r.Use.Verify,
		})
	}

	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summaries)
		return 0
	}
	if g.quiet {
		return 0
	}
	if len(summaries) == 0 {
		fmt.Println("no rules defined")
		return 0
	}
	for i, s := range summaries {
		var match []string
		if s.Client != "" {
			match = append(match, "client="+s.Client)
		}
		if s.Dir != "" {
			match = append(match, "dir="+s.Dir)
		}
		if len(s.Platform) > 0 {
			match = append(match, "platform="+strings.Join(s.Platform, ","))
		}
		if len(s.Task) > 0 {
			match = append(match, "task="+strings.Join(s.Task, ","))
		}
		matchStr := strings.Join(match, " ")
		if matchStr == "" {
			matchStr = "(catch-all)"
		}
		verify := s.Verify
		if verify == "" {
			verify = "(inherit)"
		}
		fmt.Printf("%2d. %-20s %-50s -> identity=%s access=%s verify=%s\n", i, s.ID, matchStr, s.Identity, s.Access, verify)
	}
	return 0
}
