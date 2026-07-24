// allow-claude-code: new multi-file build for the "agent-native command
// layer" milestone (roadmap.md section 4 / technical-spec.md section
// 7.3): the deferred optional thin store, now built alongside the
// imperative commands that need a write-capable vault backend.
//
// StoreBackend is deliberately "the age backend plus CanStore" (spec
// 7.3), shelling out to age/age-keygen exactly like AgeBackend rather
// than sharing an implementation with it, so the two stay independently
// simple: AgeBackend must never be able to write (it points at the
// operator's real, pre-existing vault), and StoreBackend must never be
// silently used where AgeBackend's read-only guarantee was assumed.
package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StoreBackend is the optional thin secret store: an age-encrypted
// per-file store the router itself can write to, encrypting on write to
// the operator's own recipient (derived from IdentityFile via
// `age-keygen -y`, so no separate recipient configuration is needed) and
// decrypting on read exactly like AgeBackend.
type StoreBackend struct {
	Dir          string // absolute path; "~" already expanded by the caller
	IdentityFile string // absolute path; "~" already expanded by the caller

	// ageBin/ageKeygenBin override the binaries used for exec.LookPath and
	// exec.Command. Empty means "age" / "age-keygen". Only used by tests.
	ageBin       string
	ageKeygenBin string
}

// NewStoreBackend constructs a StoreBackend. dir and identityFile are
// expanded ("~") here so callers can pass raw config values.
func NewStoreBackend(dir, identityFile string) (*StoreBackend, error) {
	d, err := expandHome(dir)
	if err != nil {
		return nil, fmt.Errorf("vault: expand store.dir: %w", err)
	}
	idf, err := expandHome(identityFile)
	if err != nil {
		return nil, fmt.Errorf("vault: expand identity_file: %w", err)
	}
	return &StoreBackend{Dir: d, IdentityFile: idf}, nil
}

func (b *StoreBackend) bin() string {
	if b.ageBin != "" {
		return b.ageBin
	}
	return "age"
}

func (b *StoreBackend) keygenBin() string {
	if b.ageKeygenBin != "" {
		return b.ageKeygenBin
	}
	return "age-keygen"
}

// Name implements Backend.
func (b *StoreBackend) Name() string { return "store" }

// Capabilities implements Backend. Unlike AgeBackend, the thin store can
// both store and (via List, below) enumerate what it holds.
func (b *StoreBackend) Capabilities() Capabilities {
	return Capabilities{CanStore: true, CanList: true}
}

// resolvePath maps a store:// handle to a file path under Dir, rejecting
// handles that would escape Dir (path traversal). Mirrors
// AgeBackend.resolvePath exactly (same layout, different scheme name);
// duplicated rather than shared so each backend's traversal guard stays
// simple and independently auditable.
func (b *StoreBackend) resolvePath(h Handle) (string, error) {
	raw := string(h)
	if raw == "" {
		return "", errors.New("vault: empty handle")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("vault: invalid handle %q: %w", raw, err)
	}
	if u.Scheme != "store" {
		return "", fmt.Errorf("vault: handle %q has scheme %q, expected \"store\"", raw, u.Scheme)
	}
	rel := strings.TrimPrefix(u.Host+u.Path, "/")
	if rel == "" {
		return "", fmt.Errorf("vault: handle %q has no path", raw)
	}
	if b.Dir == "" {
		return "", errors.New("vault: store backend has no dir configured")
	}

	full := filepath.Join(b.Dir, rel)
	dirAbs, err := filepath.Abs(b.Dir)
	if err != nil {
		return "", err
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	rel2, err := filepath.Rel(dirAbs, fullAbs)
	if err != nil || rel2 == ".." || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("vault: handle %q resolves outside the store dir", raw)
	}
	return fullAbs, nil
}

// ResolvedPath is the exported form of resolvePath, for `credroute store
// remove` (cmd/credroute), which needs the on-disk path to delete without
// duplicating the traversal guard.
func (b *StoreBackend) ResolvedPath(h Handle) (string, error) {
	return b.resolvePath(h)
}

// Exists implements Backend via a file stat, no decryption.
func (b *StoreBackend) Exists(_ context.Context, h Handle) (bool, error) {
	p, err := b.resolvePath(h)
	if err != nil {
		return false, err
	}
	_, statErr := os.Stat(p)
	if statErr == nil {
		return true, nil
	}
	if errors.Is(statErr, os.ErrNotExist) {
		return false, nil
	}
	return false, statErr
}

// Retrieve implements Backend by shelling out to `age -d -i <identity> <file>`,
// exactly like AgeBackend.Retrieve.
func (b *StoreBackend) Retrieve(ctx context.Context, h Handle) (*Secret, error) {
	path, err := b.resolvePath(h)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("vault: no secret at %s (handle %s)", path, h)
		}
		return nil, fmt.Errorf("vault: stat %s: %w", path, err)
	}
	if b.IdentityFile == "" {
		return nil, errors.New("vault: no age identity_file configured")
	}
	if _, err := exec.LookPath(b.bin()); err != nil {
		return nil, fmt.Errorf("vault: %q binary not found on PATH: %w", b.bin(), err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, b.bin(), "-d", "-i", b.IdentityFile, path)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("vault: age decrypt failed for handle %s: %s", h, msg)
	}
	return NewSecret(stdout.Bytes()), nil
}

// Fingerprint implements Backend, identically to AgeBackend.Fingerprint.
func (b *StoreBackend) Fingerprint(ctx context.Context, h Handle) (string, error) {
	secret, err := b.Retrieve(ctx, h)
	if err != nil {
		return "", err
	}
	defer secret.Zero()

	var fp string
	err = secret.WithBytes(func(raw []byte) error {
		fp = fingerprintBytes(raw)
		return nil
	})
	if err != nil {
		return "", err
	}
	return fp, nil
}

// recipient derives the age recipient (public key) matching IdentityFile
// via `age-keygen -y`, so the operator configures only the private
// identity file and never has to separately track or paste a public key
// for self-encryption.
func (b *StoreBackend) recipient(ctx context.Context) (string, error) {
	if b.IdentityFile == "" {
		return "", errors.New("vault: no age identity_file configured")
	}
	if _, err := exec.LookPath(b.keygenBin()); err != nil {
		return "", fmt.Errorf("vault: %q binary not found on PATH: %w", b.keygenBin(), err)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, b.keygenBin(), "-y", b.IdentityFile)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("vault: derive recipient from %s failed: %s", b.IdentityFile, msg)
	}
	recipient := strings.TrimSpace(stdout.String())
	if recipient == "" {
		return "", fmt.Errorf("vault: %q -y %s produced no recipient", b.keygenBin(), b.IdentityFile)
	}
	return recipient, nil
}

// Store implements Backend: age-encrypts s to the operator's own
// recipient and writes it under Dir at h's path, atomically (temp file +
// rename) and 0600. The secret is piped to age's stdin, never passed as
// an argv value or environment variable, so it never appears in a
// process listing.
func (b *StoreBackend) Store(ctx context.Context, h Handle, s *Secret) error {
	path, err := b.resolvePath(h)
	if err != nil {
		return err
	}
	if _, err := exec.LookPath(b.bin()); err != nil {
		return fmt.Errorf("vault: %q binary not found on PATH: %w", b.bin(), err)
	}
	recipient, err := b.recipient(ctx)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vault: create store dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("vault: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// M3 (Fable 5 review v2): age writes its ciphertext to this fd
	// directly (via "-o tmpPath" below), so unlike fsutil.WriteFileAtomic
	// (which writes bytes it already has in memory) the temp file must
	// stay open until age has run and produced output, then be fsynced
	// before rename. Without this, a crash shortly after `store add`
	// reports success could leave a truncated or zero-length ciphertext
	// durable at the final path (fails closed on later Retrieve, but the
	// secret is lost).
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()

	var encryptErr error
	err = s.WithBytes(func(raw []byte) error {
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, b.bin(), "-r", recipient, "-o", tmpPath)
		cmd.Stdin = bytes.NewReader(raw)
		cmd.Stderr = &stderr
		if runErr := cmd.Run(); runErr != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = runErr.Error()
			}
			encryptErr = fmt.Errorf("vault: age encrypt failed: %s", msg)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("vault: read secret to encrypt: %w", err)
	}
	if encryptErr != nil {
		return encryptErr
	}

	// age wrote its output via "-o tmpPath", a separate open of the same
	// file, so tmp's own fd must be re-synced (its in-kernel view of the
	// file is the same inode) before rename to guarantee the ciphertext
	// survives a crash.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("vault: fsync temp file %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("vault: chmod temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("vault: rename %s to %s: %w", tmpPath, path, err)
	}
	ok = true
	return nil
}

// List returns every handle currently stored under Dir, as store://
// relative paths, sorted by filepath.WalkDir's lexical directory-then-file
// order. Not part of the Backend interface (age has no meaningful list
// operation and the interface is deliberately kept small); used directly
// by `credroute store ls`. An absent Dir is reported as an empty list,
// not an error, since "not enabled yet" is caught earlier by config
// validation.
func (b *StoreBackend) List(_ context.Context) ([]string, error) {
	if b.Dir == "" {
		return nil, errors.New("vault: store backend has no dir configured")
	}
	var handles []string
	err := filepath.WalkDir(b.Dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if isStoreTempResidue(d.Name()) {
			// L7 (Fable 5 review v2): a crashed `store add` between
			// CreateTemp and rename can leave one of these behind;
			// `store ls` must never surface it as a real handle.
			return nil
		}
		rel, relErr := filepath.Rel(b.Dir, path)
		if relErr != nil {
			return relErr
		}
		handles = append(handles, "store://"+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("vault: list %s: %w", b.Dir, err)
	}
	return handles, nil
}

// isStoreTempResidue reports whether name looks like a crash-orphaned
// atomic-write temp file: Store's own temp files are named
// ".<base>.tmp-<random>" (matching fsutil.WriteFileAtomic's own naming
// scheme), and a crash between CreateTemp and rename can leave one behind
// (L7, Fable 5 review v2).
func isStoreTempResidue(name string) bool {
	return strings.HasPrefix(name, ".") && strings.Contains(name, ".tmp-")
}
