// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 4.4) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
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
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hasandenizuk/credroute/internal/vault"
)

func cmdHandleGet(args []string) int {
	fs := flag.NewFlagSet("handle get", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	toFile := fs.String("to-file", "", "write the secret to this path (0600 perms), instead of stdout")
	toFD := fs.Int("to-fd", 0, "write the secret to this open file descriptor, instead of stdout")
	forceReveal := fs.Bool("force-reveal", false, "allow printing the secret to stdout; refused without this even so (see below)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute handle get: expected exactly one vault handle, e.g. age://google/me/oauth-ro.json.age")
		return 1
	}
	handleStr := fs.Arg(0)

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute handle get:", err)
		return 5
	}
	backend, err := buildVaultBackend(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute handle get:", err)
		return 4
	}

	secret, err := backend.Retrieve(context.Background(), vault.Handle(handleStr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute handle get:", err)
		return 4
	}
	defer secret.Zero()

	switch {
	case *toFile != "":
		return writeSecretToFile(secret, *toFile)
	case *toFD != 0:
		return writeSecretToFD(secret, *toFD)
	default:
		return revealSecretToStdout(secret, *forceReveal)
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
