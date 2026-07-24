// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 6) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hasandenizuk/credroute/internal/scope"
)

func cmdProfiles(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "credroute profiles: expected subcommand \"ls\" or \"show\"")
		return 1
	}
	switch args[0] {
	case "ls":
		return cmdProfilesLs(args[1:])
	case "show":
		return cmdProfilesShow(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "credroute profiles: unknown subcommand %q (expected: ls, show)\n", args[0])
		return 1
	}
}

type profileSummary struct {
	Platform        string   `json:"platform"`
	Source          string   `json:"source"` // builtin | user
	Aliases         []string `json:"aliases,omitempty"`
	CredentialTypes []string `json:"credential_types,omitempty"`
	AccessLevels    []string `json:"access_levels,omitempty"`
}

func cmdProfilesLs(args []string) int {
	fs := flag.NewFlagSet("profiles ls", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	reg, err := scope.LoadDefaultRegistry()
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute profiles ls:", err)
		return 1
	}

	var summaries []profileSummary
	for _, p := range reg.List() {
		summaries = append(summaries, profileSummary{
			Platform:        p.Platform,
			Source:          reg.Source(p.Platform),
			Aliases:         p.Aliases,
			CredentialTypes: p.CredentialTypes,
			AccessLevels:    accessLevelNames(p),
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
		fmt.Println("no scope profiles loaded")
		return 0
	}
	for _, s := range summaries {
		fmt.Printf("%-10s source=%-8s access_levels=%-20s credential_types=%s\n",
			s.Platform, s.Source, strings.Join(s.AccessLevels, ","), strings.Join(s.CredentialTypes, ","))
	}
	return 0
}

type profileDetail struct {
	Platform        string                         `json:"platform"`
	Source          string                         `json:"source"`
	Aliases         []string                       `json:"aliases,omitempty"`
	CredentialTypes []string                       `json:"credential_types,omitempty"`
	IdentityProbe   scope.IdentityProbe            `json:"identity_probe,omitempty"`
	AccessLevels    map[string]profileAccessDetail `json:"access_levels,omitempty"`
	ExecEnv         string                         `json:"exec_env,omitempty"`
	LoginHelper     string                         `json:"login_helper,omitempty"`
}

type profileAccessDetail struct {
	Scopes []string `json:"scopes"`
}

func cmdProfilesShow(args []string) int {
	fs := flag.NewFlagSet("profiles show", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	task := fs.String("task", "", "show the scope set for this task/alias instead of the union")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute profiles show: expected exactly one platform name")
		return 1
	}
	platform := fs.Arg(0)

	reg, err := scope.LoadDefaultRegistry()
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute profiles show:", err)
		return 1
	}
	p, ok := reg.Get(platform)
	if !ok {
		fmt.Fprintf(os.Stderr, "credroute profiles show: no profile for platform %q (generic passthrough: routing works without one, but nothing is scope-derived)\n", platform)
		return 1
	}

	detail := profileDetail{
		Platform:        p.Platform,
		Source:          reg.Source(platform),
		Aliases:         p.Aliases,
		CredentialTypes: p.CredentialTypes,
		IdentityProbe:   p.IdentityProbe,
		ExecEnv:         p.ExecEnv,
		LoginHelper:     p.Login.Helper,
		AccessLevels:    map[string]profileAccessDetail{},
	}
	for _, level := range accessLevelNames(p) {
		detail.AccessLevels[level] = profileAccessDetail{Scopes: p.ScopesFor(level, *task)}
	}

	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(detail)
		return 0
	}
	if g.quiet {
		return 0
	}
	fmt.Printf("platform         %s\n", detail.Platform)
	fmt.Printf("source           %s\n", detail.Source)
	if len(detail.Aliases) > 0 {
		fmt.Printf("aliases          %s\n", strings.Join(detail.Aliases, ", "))
	}
	if len(detail.CredentialTypes) > 0 {
		fmt.Printf("credential_types %s\n", strings.Join(detail.CredentialTypes, ", "))
	}
	if detail.ExecEnv != "" {
		fmt.Printf("exec_env         %s\n", detail.ExecEnv)
	}
	if detail.LoginHelper != "" {
		fmt.Printf("login_helper     %s\n", detail.LoginHelper)
	}
	for _, level := range accessLevelNames(p) {
		fmt.Printf("access_level     %s\n", level)
		for _, s := range detail.AccessLevels[level].Scopes {
			fmt.Printf("  scope          %s\n", s)
		}
	}
	return 0
}

// accessLevelRank orders "read-only" before "read-write" (matching every
// example in the spec); anything else sorts after those two.
func accessLevelRank(level string) int {
	switch level {
	case "read-only":
		return 0
	case "read-write":
		return 1
	default:
		return 2
	}
}

func accessLevelNames(p *scope.Profile) []string {
	names := make([]string, 0, len(p.AccessLevels))
	for k := range p.AccessLevels {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		ri, rj := accessLevelRank(names[i]), accessLevelRank(names[j])
		if ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	return names
}
