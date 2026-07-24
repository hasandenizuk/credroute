// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 10) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/config"
)

const (
	defaultVaultDir     = "~/Projects/shared/secrets"
	defaultIdentityFile = "~/.config/credroute/age-identity.txt"
)

func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	yes := fs.Bool("yes", false, "non-interactive: scaffold from flags/env only, never prompt (required when stdin is not a TTY)")
	force := fs.Bool("force", false, "overwrite an existing config file")
	vaultDir := fs.String("vault-dir", "", "vault.age.store_dir (default: "+defaultVaultDir+")")
	identityFile := fs.String("identity-file", "", "vault.age.identity_file (default: "+defaultIdentityFile+")")
	identityID := fs.String("identity", "", "optional: scaffold one identity, keyed by this id (usually an email)")
	identityLabel := fs.String("identity-label", "", "label for --identity")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}

	if !*yes && !isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "credroute init: stdin is not a terminal; pass --yes (with --vault-dir/--identity-file/--identity as needed) to run non-interactively")
		return 1
	}

	path := g.configPath
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "credroute init:", err)
			return 1
		}
		path = p
	}
	expandedPath, err := config.ExpandHome(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute init:", err)
		return 1
	}
	if _, statErr := os.Stat(expandedPath); statErr == nil && !*force {
		fmt.Fprintf(os.Stderr, "credroute init: %s already exists; pass --force to overwrite\n", expandedPath)
		return 1
	}

	vd := *vaultDir
	if vd == "" {
		vd = defaultVaultDir
	}
	idf := *identityFile
	if idf == "" {
		idf = defaultIdentityFile
	}
	id := *identityID
	label := *identityLabel

	if !*yes {
		reader := bufio.NewReader(os.Stdin)
		vd = promptDefault(reader, "Vault store_dir", vd)
		idf = promptDefault(reader, "Age identity_file", idf)
		if id == "" {
			id = promptDefault(reader, "First identity id (email, blank to skip)", "")
		}
		if id != "" && label == "" {
			label = promptDefault(reader, "Label for "+id, "")
		}
	}

	cfg := &config.Config{
		Version: 1,
		Defaults: config.Defaults{
			OnNoMatch:     "refuse",
			Verify:        "required",
			SidecarMaxAge: "24h",
		},
		Vault: config.VaultConfig{
			Backend: "age",
			Age:     config.AgeConfig{StoreDir: vd, IdentityFile: idf},
		},
	}
	if id != "" {
		cfg.Identities = map[string]config.Identity{id: {Label: label}}
	}

	var report []string

	if expandedVault, expErr := config.ExpandHome(vd); expErr == nil {
		if info, statErr := os.Stat(expandedVault); statErr == nil && info.IsDir() {
			report = append(report, fmt.Sprintf("detected existing vault dir at %s", expandedVault))
		} else {
			report = append(report, fmt.Sprintf("vault dir %s does not exist yet; create it (or point --vault-dir elsewhere) before running resolve/exec", expandedVault))
		}
	}

	if err := writeConfigSkeleton(expandedPath, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "credroute init:", err)
		return 1
	}
	report = append(report, fmt.Sprintf("wrote %s", expandedPath))

	if err := attest.EnsureMachineKey(); err != nil {
		fmt.Fprintln(os.Stderr, "credroute init: warning: could not prepare the machine key:", err)
	} else {
		report = append(report, "machine key ready")
	}

	if id != "" {
		report = append(report, fmt.Sprintf("scaffolded identity %q (add its platform credentials by hand, then run `credroute config validate`)", id))
	}

	if g.quiet {
		return 0
	}
	for _, line := range report {
		fmt.Println(line)
	}
	fmt.Printf("next: edit %s to add rules, then run `credroute config validate` and `credroute doctor`\n", expandedPath)
	return 0
}

func promptDefault(r *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func writeConfigSkeleton(path string, cfg *config.Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
