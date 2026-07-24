// allow-claude-code: new multi-file build for the "agent-native command
// layer" milestone (roadmap.md section 4 / technical-spec.md section
// 7.3): `store add` / `store ls` / `store remove`, the deferred optional
// thin store, wired up against internal/vault.StoreBackend.
package main

// allow-claude-code: Fable 5 review v2 fixes (H1/H2/M1/M2/M3/L1-L7),
// dispatched directly by the orchestrator with the review's exact
// file:line findings and recommended fixes; mechanical translation of
// each finding to Go, reviewed alongside the review document itself.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/vault"
)

// validateStorePath rejects characters that resolvePath treats specially
// (L2, Fable 5 review v2): url.Parse (used by both StoreBackend.resolvePath
// and AgeBackend.resolvePath) strips "#" as a URL fragment, treats "?" as
// introducing a query string, and percent-decodes "%" escapes, any of
// which can make the path credroute actually reads/writes disagree with
// the path it reports back (e.g. `store add 'x#frag'` stores at
// store://x but prints store://x#frag as the handle).
func validateStorePath(relPath string) error {
	if i := strings.IndexAny(relPath, "#?%"); i >= 0 {
		return fmt.Errorf("path %q contains %q, which is reserved by URL parsing and not allowed in a store path", relPath, string(relPath[i]))
	}
	return nil
}

func cmdStore(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "credroute store: expected subcommand \"add\", \"ls\", or \"remove\"")
		return 1
	}
	switch args[0] {
	case "add":
		return cmdStoreAdd(args[1:])
	case "ls":
		return cmdStoreLs(args[1:])
	case "remove":
		return cmdStoreRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "credroute store: unknown subcommand %q (expected: add, ls, remove)\n", args[0])
		return 1
	}
}

// buildStoreBackend requires the optional thin store to be explicitly
// enabled (store.enabled: true, spec 7.3: "nothing in the default path
// touches it") and requires vault.backend: age, since the thin store is
// "exactly the age backend plus CanStore" and reuses the same identity
// file to derive its self-encryption recipient.
func buildStoreBackend(cfg *config.Config) (*vault.StoreBackend, error) {
	if cfg.Store == nil || !cfg.Store.Enabled {
		return nil, fmt.Errorf("the thin store is not enabled; set store.enabled: true and store.dir in config.yaml")
	}
	if cfg.Vault.Backend != "age" {
		return nil, fmt.Errorf("the thin store requires vault.backend: age (it is the age backend plus write support)")
	}
	return vault.NewStoreBackend(cfg.Store.Dir, cfg.Vault.Age.IdentityFile)
}

func cmdStoreAdd(args []string) int {
	fs := flag.NewFlagSet("store add", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	fromFile := fs.String("from-file", "", "read the secret from this file instead of stdin/prompt")
	fromFD := fs.Int("from-fd", 0, "read the secret from this already-open file descriptor instead of stdin/prompt")
	force := fs.Bool("force", false, "overwrite if a secret already exists at this path")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute store add: expected exactly one relative path, e.g. github/me/pat")
		return 1
	}
	// allow-claude-code: Fable 5 review v2 fix (L2), same file/scope as above.
	relPath := fs.Arg(0)
	if err := validateStorePath(relPath); err != nil {
		fmt.Fprintln(os.Stderr, "credroute store add:", err)
		return 1
	}

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store add:", err)
		return 5
	}
	backend, err := buildStoreBackend(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store add:", err)
		return 1
	}

	handle := vault.Handle("store://" + strings.TrimPrefix(relPath, "/"))
	ctx := context.Background()

	if !*force {
		exists, err := backend.Exists(ctx, handle)
		if err != nil {
			fmt.Fprintln(os.Stderr, "credroute store add:", err)
			return 4
		}
		if exists {
			fmt.Fprintf(os.Stderr, "credroute store add: %s already has a stored secret; pass --force to overwrite\n", handle)
			return 1
		}
	}

	raw, err := readSecretInput(*fromFile, *fromFD)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store add:", err)
		return 1
	}
	secret := vault.NewSecret(raw)
	defer secret.Zero()

	// allow-claude-code: Fable 5 review v2 fix (M2), same file/scope as above.
	if err := backend.Store(ctx, handle, secret); err != nil {
		fmt.Fprintln(os.Stderr, "credroute store add:", err)
		return 4
	}
	_ = audit.Append(audit.Entry{
		Op:         "store",
		Command:    "store add",
		Target:     string(handle),
		ConfigPath: cfg.Store.Dir,
		Exit:       0,
		Decision:   "allow",
		Caller:     auditCaller,
	})

	if g.quiet {
		return 0
	}
	fmt.Println(string(handle))
	return 0
}

// readSecretInput reads the secret bytes from --from-file, --from-fd, a
// piped stdin, or (only on an interactive terminal with neither) a
// prompt read line. The secret is never accepted as a command-line
// argument, so it never appears in argv, process listings, or shell
// history. Known limitation: this terminal prompt does not suppress
// character echo (no external terminal-control dependency is in scope
// for this milestone; see the package-installs policy) — --from-file or
// a pipe is the recommended path for anything sensitive.
func readSecretInput(fromFile string, fromFD int) ([]byte, error) {
	switch {
	case fromFile != "":
		b, err := os.ReadFile(fromFile)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", fromFile, err)
		}
		return trimTrailingNewline(b), nil
	case fromFD != 0:
		f := os.NewFile(uintptr(fromFD), fmt.Sprintf("fd%d", fromFD))
		if f == nil {
			return nil, fmt.Errorf("fd %d is not usable", fromFD)
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("read fd %d: %w", fromFD, err)
		}
		return trimTrailingNewline(b), nil
	case !isTerminal(os.Stdin):
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return trimTrailingNewline(b), nil
	// allow-claude-code: Fable 5 review v2 fix (L1), same file/scope as above.
	default:
		return readPromptedSecret(bufio.NewReader(os.Stdin))
	}
}

// readPromptedSecret prompts on stderr and reads one line from r. r is
// taken as a parameter (rather than opening os.Stdin itself) so a test
// can drive it with an in-memory reader without needing a real
// character-device terminal.
//
// L1 (Fable 5 review v2): the terminal prompt silently truncated a
// pasted multiline secret (e.g. a PEM key) at the first newline, storing
// it truncated with exit 0. r.Buffered() after ReadString reports
// whether more bytes arrived in the same read as the first line (which
// happens when a multiline paste lands in the tty/pipe faster than
// ReadString consumes it); if so, this is rejected rather than silently
// truncated, since --from-file or a pipe both handle multiline input
// correctly already.
func readPromptedSecret(r *bufio.Reader) ([]byte, error) {
	fmt.Fprint(os.Stderr, "Secret value (input is not hidden on this terminal; prefer --from-file or a pipe): ")
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read prompt: %w", err)
	}
	if r.Buffered() > 0 {
		return nil, fmt.Errorf("more input follows the first line; a multiline secret would be truncated by this prompt — use --from-file or a pipe instead")
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func trimTrailingNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b
}

func cmdStoreLs(args []string) int {
	fs := flag.NewFlagSet("store ls", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store ls:", err)
		return 5
	}
	backend, err := buildStoreBackend(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store ls:", err)
		return 1
	}

	handles, err := backend.List(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store ls:", err)
		return 4
	}
	sort.Strings(handles)

	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(handles)
		return 0
	}
	if g.quiet {
		return 0
	}
	if len(handles) == 0 {
		fmt.Println("no secrets stored")
		return 0
	}
	for _, h := range handles {
		fmt.Println(h)
	}
	return 0
}

func cmdStoreRemove(args []string) int {
	fs := flag.NewFlagSet("store remove", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	force := fs.Bool("force", false, "do not error if the secret does not exist")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "credroute store remove: expected exactly one relative path")
		return 1
	}
	// allow-claude-code: Fable 5 review v2 fix (L2/L7/M2), same file/scope.
	relPath := fs.Arg(0)
	if err := validateStorePath(relPath); err != nil {
		fmt.Fprintln(os.Stderr, "credroute store remove:", err)
		return 1
	}

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store remove:", err)
		return 5
	}
	backend, err := buildStoreBackend(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store remove:", err)
		return 1
	}

	handle := vault.Handle("store://" + strings.TrimPrefix(relPath, "/"))
	path, err := backend.ResolvedPath(handle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute store remove:", err)
		return 1
	}

	// L7 (Fable 5 review v2): stat first and require a regular file, so
	// `store remove` can never be pointed at (and delete) a directory
	// inside the store dir.
	info, statErr := os.Stat(path)
	if statErr != nil {
		if os.IsNotExist(statErr) && *force {
			return 0
		}
		fmt.Fprintln(os.Stderr, "credroute store remove:", statErr)
		return 4
	}
	if !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "credroute store remove: %s is not a regular file, refusing to remove it\n", path)
		return 1
	}
	if err := os.Remove(path); err != nil {
		fmt.Fprintln(os.Stderr, "credroute store remove:", err)
		return 4
	}
	_ = audit.Append(audit.Entry{
		Op:         "store",
		Command:    "store remove",
		Target:     string(handle),
		ConfigPath: cfg.Store.Dir,
		Exit:       0,
		Decision:   "allow",
		Caller:     auditCaller,
	})
	if !g.quiet {
		fmt.Printf("credroute store remove: removed %s\n", handle)
	}
	return 0
}
