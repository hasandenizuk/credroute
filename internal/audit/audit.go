// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 9.3) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
//
// Package audit implements the append-only audit log (spec 9.3): one JSON
// line per resolve/exec/verify operation, recording context and outcome
// but never a secret. Entry deliberately has no field that can hold
// secret bytes, so there is no code path by which this package could leak
// one.
package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Entry is one audit log line (spec 9.3 example).
type Entry struct {
	TS       time.Time `json:"ts"`
	ID       string    `json:"id"`
	Op       string    `json:"op"` // resolve | exec | verify | config | store
	Dir      string    `json:"dir,omitempty"`
	Platform string    `json:"platform,omitempty"`
	Task     string    `json:"task,omitempty"`
	Rule     string    `json:"rule,omitempty"`
	// Client is the client name the matched rule's match.client named, if
	// any (F17: lets `credroute audit --client` filter by it).
	Client       string `json:"client,omitempty"`
	Identity     string `json:"identity,omitempty"`
	Access       string `json:"access,omitempty"`
	Verification string `json:"verification,omitempty"`
	Exit         int    `json:"exit"`
	Decision     string `json:"decision"` // allow | refuse
	Caller       string `json:"caller,omitempty"`
	// Command, Target, and ConfigPath are set only on Op "config"/"store"
	// entries (M2, Fable 5 review v2: `identity add/edit`, `route
	// add/assign`, and `store add/remove` previously left no audit trail
	// at all, so the routing table itself could be rewritten with zero
	// record of who changed what). Command is the credroute subcommand
	// that ran (e.g. "identity add", "store remove"); Target is the
	// specific thing it changed (an identity id, rule id, or store
	// handle); ConfigPath is the config file it changed it in, or the
	// store dir for a store command.
	Command    string `json:"command,omitempty"`
	Target     string `json:"target,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
}

// NewID generates an opaque, sortable-by-time identifier for one audit
// entry (also used as `credroute resolve`'s response `audit_id`, spec
// 4.2). This is a lightweight timestamp+random scheme, not a full ULID
// implementation (no ULID library is available under this project's
// stdlib-only dependency constraint); it is unique and time-ordered,
// which is all the spec's examples rely on.
func NewID() string {
	var r [5]byte
	_, _ = rand.Read(r[:])
	return fmt.Sprintf("%013X%s", time.Now().UTC().UnixMilli(), hex.EncodeToString(r[:]))
}

// StateDir returns the credroute state directory, normally
// ~/.local/state/credroute (spec 9.3: audit.jsonl is "machine-local, not
// synced"). Set CREDROUTE_STATE_DIR to override, mirroring
// internal/attest's env var so both land under the same tree by default
// and tests never touch a real home directory.
func StateDir() (string, error) {
	if v := os.Getenv("CREDROUTE_STATE_DIR"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("audit: determine home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "credroute"), nil
}

// LogPath returns the path to the audit log file.
func LogPath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "audit.jsonl"), nil
}

// Append writes e as one JSON line to the audit log, creating the state
// directory and file if needed. ID/TS default when unset so callers can
// pass a partially-filled Entry. Append is best-effort by design at the
// call sites (resolve/exec/verify never fail an operation just because
// the audit log could not be written), but returns any error so a caller
// that does want to surface it (or a test) can.
//
// F14: the file is opened O_APPEND, and Go's Write issues one write()
// syscall for the single JSON line, which POSIX serializes at the kernel
// level against other O_APPEND writers to the same file, so concurrent
// `credroute` runs cannot interleave or corrupt each other's line. Sync
// adds durability on top: a crash immediately after Append no longer
// silently loses the entry.
func Append(e Entry) error {
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}

	path, err := LogPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("audit: create state dir: %w", err)
	}

	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	b = append(b, '\n')

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("audit: write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("audit: fsync %s: %w", path, err)
	}
	return nil
}

// ReadAll returns every entry in the audit log, oldest first. A missing
// log file is not an error: it reads as zero entries (nothing has been
// logged yet).
func ReadAll() ([]Entry, error) {
	path, err := LogPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read %s: %w", path, err)
	}

	var entries []Entry
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("audit: parse %s: %w", path, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Filter selects a subset of entries for `credroute audit`.
type Filter struct {
	// Since keeps only entries at or after this time. Zero means no
	// lower bound.
	Since time.Time
	// Platform, if non-empty, keeps only entries with an exact match.
	Platform string
	// Identity, if non-empty, keeps only entries with an exact match.
	Identity string
	// Client, if non-empty, keeps only entries with an exact match (F17).
	Client string
	// FailuresOnly keeps only entries with a non-zero exit code (spec
	// 9.3: "refusals are always logged: the audit trail of what almost
	// went wrong is the operational payoff").
	FailuresOnly bool
}

// Query filters entries against f. Order is preserved (ReadAll returns
// oldest first).
func Query(entries []Entry, f Filter) []Entry {
	var out []Entry
	for _, e := range entries {
		if !f.Since.IsZero() && e.TS.Before(f.Since) {
			continue
		}
		if f.Platform != "" && e.Platform != f.Platform {
			continue
		}
		if f.Identity != "" && e.Identity != f.Identity {
			continue
		}
		if f.Client != "" && e.Client != f.Client {
			continue
		}
		if f.FailuresOnly && e.Exit == 0 {
			continue
		}
		out = append(out, e)
	}
	return out
}
