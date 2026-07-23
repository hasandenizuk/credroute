// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/vault"
)

// execEnvVars maps a platform to the credential env var its scope profile
// (spec section 6.1) declares. Milestone 1 hardcodes the two profiles the
// spec worked example uses; the full profile system is milestone 3.
var execEnvVars = map[string]string{
	"google": "GOOGLE_OAUTH_TOKEN_JSON",
	"github": "GH_TOKEN",
}

func cmdExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	platform := fs.String("platform", "", "platform to resolve")
	task := fs.String("task", "", "task tag")
	dir := fs.String("dir", "", "directory to resolve for (default: cwd)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	childArgs := fs.Args()
	if len(childArgs) == 0 {
		fmt.Fprintln(os.Stderr, "credroute exec: missing command after --")
		return 1
	}
	if *platform == "" {
		fmt.Fprintln(os.Stderr, "credroute exec: --platform is required")
		return 1
	}

	queryDir, err := resolveQueryDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute exec:", err)
		return 1
	}

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute exec:", err)
		return 5
	}

	result, err := rules.Evaluate(cfg, rules.Query{Dir: queryDir, Platform: *platform, Task: *task})
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute exec:", err)
		return 5
	}
	if result.Resolution == nil {
		fmt.Fprintln(os.Stderr, "credroute exec: no rule matched this context; refusing (fail closed)")
		return 2
	}
	res := result.Resolution
	if !res.CredentialFound {
		fmt.Fprintf(os.Stderr, "credroute exec: identity %q has no %q credential for platform %q\n", res.Identity, res.Access, *platform)
		return 5
	}

	backend, err := buildVaultBackend(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute exec:", err)
		return 4
	}

	secret, err := backend.Retrieve(context.Background(), vault.Handle(res.Credential.Vault))
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute exec:", err)
		return 4
	}
	defer secret.Zero()

	if !g.quiet {
		fmt.Fprintf(os.Stderr, "credroute: %s (%s, %s, rule=%s) -> %s\n", res.Identity, *platform, res.Access, res.Rule.ID, childArgs[0])
	}

	cmd := exec.Command(childArgs[0], childArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := secret.WithBytes(func(b []byte) error {
		env := os.Environ()
		env = append(env, "CREDROUTE_SECRET="+string(b))
		if varName, ok := execEnvVars[*platform]; ok {
			env = append(env, varName+"="+string(b))
		}
		cmd.Env = env
		// The secret never touches argv or stdout/stderr; it exists only
		// in the child's environment block. Note: os/exec.Cmd.Env requires
		// Go strings, which are immutable, so this copy cannot be wiped
		// after Run() the way secret.Zero() wipes the original bytes.
		// This mirrors the spec's own limitation (9.2: no swap-out
		// mitigation claimed); the process environment is reclaimed by
		// the OS when this process and the child both exit.
		return cmd.Run()
	})

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "credroute exec:", runErr)
		return 1
	}
	return 0
}

func buildVaultBackend(cfg *config.Config) (vault.Backend, error) {
	switch cfg.Vault.Backend {
	case "age":
		return vault.NewAgeBackend(cfg.Vault.Age.StoreDir, cfg.Vault.Age.IdentityFile)
	default:
		return nil, fmt.Errorf("unsupported vault backend %q", cfg.Vault.Backend)
	}
}
