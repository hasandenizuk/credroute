// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/scope"
)

func cmdConfigValidate(args []string) int {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
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
	result.Errors = append(result.Errors, validateLoginProfilesForConfig(cfg)...)
	for _, w := range cfg.LoadWarnings {
		fmt.Printf("WARNING %s\n", w)
	}
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

func validateLoginProfilesForConfig(cfg *config.Config) []config.ValidationError {
	reg, err := scope.LoadDefaultRegistry()
	if err != nil {
		return []config.ValidationError{{Path: "profiles", Message: fmt.Sprintf("could not load scope profiles: %v", err)}}
	}
	var errs []config.ValidationError
	for identityID, identity := range cfg.Identities {
		for platform, plat := range identity.Platforms {
			profile, ok := reg.Get(platform)
			if !ok || profile.Login.Helper == "" {
				continue
			}
			hasSlotPlaceholder := strings.Contains(profile.Login.Helper, "{slot}")
			if profile.Login.SlotEnv != "" && !hasSlotPlaceholder {
				errs = append(errs, config.ValidationError{
					Path:    fmt.Sprintf("profiles.%s.login.helper", platform),
					Message: "must include {slot} when login.slot_env is declared",
				})
			}
			for access, cred := range plat.Credentials {
				if hasSlotPlaceholder || cred.Slot == "" {
					continue
				}
				slot, expErr := rules.ExpandHome(cred.Slot)
				if expErr != nil {
					continue
				}
				info, statErr := os.Stat(slot)
				if statErr == nil && info.IsDir() {
					errs = append(errs, config.ValidationError{
						Path:    fmt.Sprintf("identities.%s.platforms.%s.credentials.%s.slot", identityID, platform, access),
						Message: "directory slot requires the platform login.helper to include {slot}",
					})
				}
			}
		}
	}
	return errs
}
