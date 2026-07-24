// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/scope"
	"github.com/hasandenizuk/credroute/internal/vault"
	"github.com/hasandenizuk/credroute/internal/verify"
)

func cmdExec(args []string) (exitCode int) {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	platform := fs.String("platform", "", "platform to resolve")
	task := fs.String("task", "", "task tag")
	dir := fs.String("dir", "", "directory to resolve for (default: cwd)")
	access := fs.String("access", "", "request an access level (read-only|read-write); refuses if the matched rule resolves to a different level")
	exportGeneric := fs.Bool("export-generic", false, "also export the secret as the generic CREDROUTE_SECRET env var, even when a platform-specific var already carries it (F16: opt-in, reduces default secret spread)")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
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
	if *access != "" && *access != "read-only" && *access != "read-write" {
		fmt.Fprintf(os.Stderr, "credroute exec: --access must be read-only or read-write (got %q)\n", *access)
		return 1
	}

	queryDir, err := resolveQueryDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute exec:", err)
		return 1
	}

	// Every return point below this line has enough context to be worth
	// an audit entry (spec 9.3: "refusals are always logged"); the
	// deferred append fires with whatever exitCode the return path set,
	// success or refusal alike. Best-effort: an audit write failure never
	// changes exec's own exit code.
	entry := audit.Entry{ID: audit.NewID(), Op: "exec", Dir: queryDir, Platform: *platform, Task: *task, Caller: auditCaller}
	defer func() {
		entry.Exit = exitCode
		entry.Decision = decisionFor(exitCode)
		_ = audit.Append(entry)
	}()

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
	entry.Identity = res.Identity
	entry.Access = res.Access
	entry.Rule = res.Rule.ID
	entry.Client = res.Rule.Match.Client
	if !res.CredentialFound {
		fmt.Fprintf(os.Stderr, "credroute exec: identity %q has no %q credential for platform %q\n", res.Identity, res.Access, *platform)
		return 5
	}

	// F12: the caller can request a minimum/expected access level; a
	// mismatch against what the rule actually resolves to is an error,
	// never a silent substitution.
	if *access != "" && *access != res.Access {
		fmt.Fprintf(os.Stderr, "credroute exec: requested access %q but matched rule %q resolves to access %q\n", *access, res.Rule.ID, res.Access)
		return 5
	}

	slot := expandSlot(res.Credential.Slot)

	// F1: verify and refuse BEFORE ever touching the vault, exactly like
	// resolve - the shared decision in verifygate.go is what keeps the
	// two paths from drifting apart again.
	pre := runVerifyPrecheck("", res.Rule.Use.Verify, cfg.Defaults.Verify, cfg.Defaults.SidecarMaxAge, slot, res.Credential.Vault)
	entry.Verification = pre.Status
	if pre.Refuse() {
		fmt.Fprintf(os.Stderr, "credroute exec: refused: verification status %q under verify=%s; refusing (run `credroute verify --platform %s` to re-attest)\n", pre.Status, pre.Mode, *platform)
		return 3
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

	// F1/spec 5.2: "every operation that observes or changes what is in a
	// slot ... writes the observed result before doing anything else with
	// it". exec now records a fresh observation too, not just a read - by
	// default including a live identity probe when one exists for the
	// platform (F2), unless CREDROUTE_NO_NETWORK=1. A refusal discovered
	// only by this fresh probe still aborts before injection.
	registry := verify.NewRegistry(verify.LiveProbesEnabled())
	outcome, verifyErr := verify.Run(context.Background(), verify.Request{
		Platform:         *platform,
		CredentialType:   res.Credential.Type,
		ExpectedIdentity: res.Identity,
		VaultHandle:      res.Credential.Vault,
		Slot:             slot,
		Secret:           secret,
		CheckedBy:        attest.DefaultCheckedBy(buildVersion),
	}, registry)
	if verifyErr != nil {
		if g.verbose {
			fmt.Fprintf(os.Stderr, "credroute exec: warning: could not record a fresh attestation: %v\n", verifyErr)
		}
	} else {
		freshStatus := verify.ResolveStatusForAttest(outcome.Status)
		entry.Verification = freshStatus
		if verify.ShouldRefuse(pre.Mode, freshStatus) {
			fmt.Fprintf(os.Stderr, "credroute exec: refused after re-attestation: verification status %q under verify=%s (run `credroute verify --platform %s` for detail)\n", freshStatus, pre.Mode, *platform)
			return 3
		}
	}

	// Scope resolution (D7/D10, spec 6.1): the platform's scope profile
	// names the env var the secret is injected under, plus (informational
	// only) the scope set that credential is expected to carry.
	var scopeResult scope.Result
	if scopeReg, scopeErr := scope.LoadDefaultRegistry(); scopeErr == nil {
		scopeResult = scopeReg.Resolve(*platform, res.Access, *task)
	}

	if !g.quiet {
		fmt.Fprintf(os.Stderr, "credroute: %s (%s, %s, rule=%s) -> %s\n", res.Identity, *platform, res.Access, res.Rule.ID, childArgs[0])
	}

	cmd := exec.Command(childArgs[0], childArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := secret.WithBytes(func(b []byte) error {
		env := os.Environ()
		// F16: only inject the generic CREDROUTE_SECRET when there is no
		// platform-specific var to carry it (nothing else would hand the
		// secret to the child at all), or when the caller explicitly
		// opts in with --export-generic even though a platform var
		// already exists. Reduces default secret spread across the
		// child's environment.
		injectedPlatformVar := false
		if scopeResult.ExecEnv != "" {
			env = append(env, scopeResult.ExecEnv+"="+string(b))
			injectedPlatformVar = true
		}
		if *exportGeneric || !injectedPlatformVar {
			env = append(env, "CREDROUTE_SECRET="+string(b))
		}
		if len(scopeResult.Scopes) > 0 {
			env = append(env, "CREDROUTE_SCOPES="+strings.Join(scopeResult.Scopes, ","))
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
