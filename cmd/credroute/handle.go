// allow-claude-code: see handle.go header.
//
// `credroute handle get` is the plumbing secret retrieval path (spec
// 4.4.2): for adapters that must place a secret themselves, rather than
// go through `credroute exec`. It is deliberately hard to misuse: writing
// to stdout requires an explicit --force-reveal flag AND a real terminal,
// so an agent cannot accidentally dump a secret into a transcript by
// forgetting a flag or piping output.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/vault"
	"github.com/hasandenizuk/credroute/internal/verify"
)

func cmdHandleGet(args []string) int {
	fs := flag.NewFlagSet("handle get", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	toFile := fs.String("to-file", "", "write the secret to this path (0600 perms), instead of stdout")
	toFD := fs.Int("to-fd", 0, "write the secret to this open file descriptor, instead of stdout")
	forceReveal := fs.Bool("force-reveal", false, "allow printing the secret to stdout; refused without this even so (see below)")
	allowUnmodeled := fs.Bool("allow-unmodeled-handle", false, "break-glass: retrieve a vault handle not modeled in config")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute handle get: expected exactly one vault handle, e.g. age://google/me/oauth-ro.json.age")
		return 1
	}
	handleStr := fs.Arg(0)
	exitCode := 1
	entry := audit.Entry{ID: audit.NewID(), Op: "handle get", Target: handleStr, Caller: auditCaller}
	defer func() {
		entry.Exit = exitCode
		entry.Decision = decisionFor(exitCode)
		_ = appendAuditOrWarn(entry)
	}()

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute handle get:", err)
		exitCode = 5
		return exitCode
	}

	id, platform, access, cred, findErr := findCredentialByVaultHandle(cfg, handleStr)
	switch {
	case findErr == nil:
		entry.Identity = id
		entry.Platform = platform
		entry.Access = access
		slot := expandSlot(cred.Slot)
		pre := runVerifyPrecheck("", "", cfg.Defaults.Verify, cfg.Defaults.SidecarMaxAge, slot, cred.Vault, id, platform, access)
		entry.Verification = pre.Status
		if pre.Refuse() {
			fmt.Fprintf(os.Stderr, "credroute handle get: refused: verification status %q under verify=%s for identity %q on platform %q (run `credroute verify --platform %s` to re-attest)\n", pre.Status, pre.Mode, id, platform, platform)
			exitCode = 3
			return exitCode
		}
	case errors.Is(findErr, errCredentialAmbiguous):
		entry.Verification = verify.ResolveUnverified
		fmt.Fprintf(os.Stderr, "credroute handle get: refused: %v\n", findErr)
		exitCode = 3
		return exitCode
	case errors.Is(findErr, errCredentialNoMatch):
		entry.Verification = "bypass_unmodeled_handle"
		if !*allowUnmodeled {
			fmt.Fprintf(os.Stderr, "credroute handle get: refused: vault handle %q is not modeled in config; pass --allow-unmodeled-handle for break-glass retrieval\n", handleStr)
			exitCode = 3
			return exitCode
		}
		entry.Exit = 0
		entry.Decision = "allow"
		if err := audit.Append(entry); err != nil {
			fmt.Fprintf(os.Stderr, "credroute handle get: refused: break-glass audit entry could not be written: %v\n", err)
			exitCode = 5
			return exitCode
		}
	default:
		entry.Verification = verify.ResolveUnverified
		fmt.Fprintln(os.Stderr, "credroute handle get:", findErr)
		exitCode = 5
		return exitCode
	}

	backend, err := buildVaultBackend(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute handle get:", err)
		exitCode = 4
		return exitCode
	}

	secret, err := backend.Retrieve(context.Background(), vault.Handle(handleStr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute handle get:", err)
		exitCode = 4
		return exitCode
	}
	defer secret.Zero()

	if findErr == nil {
		registry := verify.NewRegistry(verify.LiveProbesEnabled())
		outcome, verifyErr := verify.Run(context.Background(), verify.Request{
			Platform:         platform,
			CredentialType:   cred.Type,
			ExpectedIdentity: id,
			AccessLevel:      access,
			VaultHandle:      cred.Vault,
			Slot:             expandSlot(cred.Slot),
			Secret:           secret,
			CheckedBy:        attest.DefaultCheckedBy(buildVersion),
		}, registry)
		freshStatus := verify.ResolveStatusForAttest(outcome.Status)
		if freshStatus == "" {
			freshStatus = verify.ResolveUnverified
		}
		entry.Verification = freshStatus
		mode := verify.EffectiveVerifyMode("", "", cfg.Defaults.Verify)
		if verifyErr != nil {
			if verify.ShouldRefuse(mode, freshStatus) {
				fmt.Fprintf(os.Stderr, "credroute handle get: refused after re-attestation: verification status %q under verify=%s\n", freshStatus, mode)
				exitCode = 3
				return exitCode
			}
			fmt.Fprintf(os.Stderr, "credroute handle get: warning: could not record a fresh attestation: %v\n", verifyErr)
			if mode == "on" {
				fmt.Fprintln(os.Stderr, "credroute handle get: refused: fresh observation could not be recorded under verify=on")
				exitCode = 3
				return exitCode
			}
		} else if verify.ShouldRefuse(mode, freshStatus) {
			fmt.Fprintf(os.Stderr, "credroute handle get: refused after re-attestation: verification status %q under verify=%s\n", freshStatus, mode)
			exitCode = 3
			return exitCode
		}
	}

	if !g.quiet {
		if stateDir := stateDirForOutput(); stateDir != "" {
			fmt.Fprintf(os.Stderr, "credroute: state_dir=%s\n", stateDir)
		}
	}

	switch {
	case *toFile != "":
		exitCode = writeSecretToFile(secret, *toFile)
		return exitCode
	case *toFD != 0:
		exitCode = writeSecretToFD(secret, *toFD)
		return exitCode
	default:
		exitCode = revealSecretToStdout(secret, *forceReveal)
		return exitCode
	}
}

func writeSecretToFile(secret *vault.Secret, path string) int {
	return runWithSecretBytes(secret, func(b []byte) int {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "credroute handle get:", err)
			return 4
		}
		return 0
	})
}

func writeSecretToFD(secret *vault.Secret, fd int) int {
	return runWithSecretBytes(secret, func(b []byte) int {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("fd%d", fd))
		if f == nil {
			fmt.Fprintf(os.Stderr, "credroute handle get: fd %d is not usable\n", fd)
			return 1
		}
		defer f.Close()
		if _, err := f.Write(b); err != nil {
			fmt.Fprintln(os.Stderr, "credroute handle get:", err)
			return 4
		}
		return 0
	})
}

// revealSecretToStdout is the one path in the whole CLI that can print a
// secret. handleRevealAllowed is a pure function so the gating logic is
// unit-testable without a real terminal.
func revealSecretToStdout(secret *vault.Secret, forceReveal bool) int {
	allowed, reason := handleRevealAllowed(forceReveal, isTerminal(os.Stdout))
	if !allowed {
		fmt.Fprintln(os.Stderr, "credroute handle get:", reason)
		return 1
	}
	if !confirmInteractive("This will print a secret to your terminal. Type \"yes\" to continue: ") {
		fmt.Fprintln(os.Stderr, "credroute handle get: not confirmed, aborting")
		return 1
	}
	return runWithSecretBytes(secret, func(b []byte) int {
		os.Stdout.Write(b)
		fmt.Println()
		return 0
	})
}

// handleRevealAllowed reports whether `handle get` may print the secret
// to stdout, and if not, why. Secrets never print by accident (spec 4.4:
// "designed to be unusable by an agent by accident"): both an explicit
// --force-reveal AND a real terminal on stdout are required, closing off
// the two most common accidental-leak shapes (a forgotten flag, and
// output piped or redirected into a log/file/transcript).
func handleRevealAllowed(forceReveal, isTTYStdout bool) (bool, string) {
	if !forceReveal {
		return false, "refusing to print the secret to stdout without --force-reveal; use --to-file or --to-fd, or pass --force-reveal if you really mean it"
	}
	if !isTTYStdout {
		return false, "refusing to print the secret to a non-terminal stdout even with --force-reveal (a pipe or redirect was detected); use --to-file or --to-fd instead"
	}
	return true, ""
}

func confirmInteractive(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line) == "yes"
}

// runWithSecretBytes is a small adapter from vault.Secret.WithBytes's
// error-returning callback to this file's int-exit-code style, so every
// hand-off path shares the same defer secret.Zero() call site.
func runWithSecretBytes(secret *vault.Secret, f func([]byte) int) int {
	code := 1
	err := secret.WithBytes(func(b []byte) error {
		code = f(b)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute handle get:", err)
		return 1
	}
	return code
}
