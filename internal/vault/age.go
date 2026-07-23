// allow-claude-code: see internal/rules/glob.go header.
package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AgeBackend is the age(1) vault backend (D8/7.2 in the spec). It shells
// out to the user's installed `age` binary rather than linking an age
// library, per this milestone's dependency constraint. It only reads:
// Store always returns ErrReadOnlyBackend, matching the spec's worked
// example ("store_dir ... credroute only reads").
type AgeBackend struct {
	StoreDir     string // absolute path; "~" already expanded by the caller
	IdentityFile string // absolute path; "~" already expanded by the caller

	// ageBin overrides the binary name/path used for exec.LookPath and
	// exec.Command. Empty means "age". Only used by tests.
	ageBin string
}

// NewAgeBackend constructs an AgeBackend. storeDir and identityFile are
// expanded ("~") here so callers can pass raw config values.
func NewAgeBackend(storeDir, identityFile string) (*AgeBackend, error) {
	sd, err := expandHome(storeDir)
	if err != nil {
		return nil, fmt.Errorf("vault: expand store_dir: %w", err)
	}
	idf, err := expandHome(identityFile)
	if err != nil {
		return nil, fmt.Errorf("vault: expand identity_file: %w", err)
	}
	return &AgeBackend{StoreDir: sd, IdentityFile: idf}, nil
}

func (b *AgeBackend) bin() string {
	if b.ageBin != "" {
		return b.ageBin
	}
	return "age"
}

// Name implements Backend.
func (b *AgeBackend) Name() string { return "age" }

// Capabilities implements Backend. The age backend is read-only in v1:
// credroute routes to an existing vault, it does not manage it.
func (b *AgeBackend) Capabilities() Capabilities {
	return Capabilities{CanStore: false, CanList: false}
}

// resolvePath maps an age:// handle to a file path under StoreDir,
// rejecting handles that would escape StoreDir (path traversal).
func (b *AgeBackend) resolvePath(h Handle) (string, error) {
	raw := string(h)
	if raw == "" {
		return "", errors.New("vault: empty handle")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("vault: invalid handle %q: %w", raw, err)
	}
	if u.Scheme != "age" {
		return "", fmt.Errorf("vault: handle %q has scheme %q, expected \"age\"", raw, u.Scheme)
	}
	rel := strings.TrimPrefix(u.Host+u.Path, "/")
	if rel == "" {
		return "", fmt.Errorf("vault: handle %q has no path", raw)
	}
	if b.StoreDir == "" {
		return "", errors.New("vault: age backend has no store_dir configured")
	}

	full := filepath.Join(b.StoreDir, rel)
	storeAbs, err := filepath.Abs(b.StoreDir)
	if err != nil {
		return "", err
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	rel2, err := filepath.Rel(storeAbs, fullAbs)
	if err != nil || rel2 == ".." || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("vault: handle %q resolves outside the vault store", raw)
	}
	return fullAbs, nil
}

// Exists implements Backend via a file stat, no decryption.
func (b *AgeBackend) Exists(_ context.Context, h Handle) (bool, error) {
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

// Retrieve implements Backend by shelling out to `age -d -i <identity> <file>`.
func (b *AgeBackend) Retrieve(ctx context.Context, h Handle) (*Secret, error) {
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
	if _, err := os.Stat(b.IdentityFile); err != nil {
		return nil, fmt.Errorf("vault: age identity file %s: %w", b.IdentityFile, err)
	}
	if _, err := exec.LookPath(b.bin()); err != nil {
		return nil, fmt.Errorf("vault: %q binary not found on PATH: %w", b.bin(), err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, b.bin(), "-d", "-i", b.IdentityFile, path)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// stderr from age describes the failure (e.g. "no identity
		// matched", "bad header"); it never contains our plaintext
		// since age writes that to stdout only on success.
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("vault: age decrypt failed for handle %s: %s", h, msg)
	}
	return NewSecret(stdout.Bytes()), nil
}

// Fingerprint implements Backend per spec 5.3:
// hex(sha256("credroute-fp-v1" || secret))[0:32].
func (b *AgeBackend) Fingerprint(ctx context.Context, h Handle) (string, error) {
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

// FingerprintBytes is the exported form of the spec 5.3 fingerprint
// formula (hex(sha256("credroute-fp-v1" || secret))[0:32]), for use by
// verification code outside this package that already holds decrypted
// secret bytes (internal/verify) and should not duplicate the formula.
func FingerprintBytes(secret []byte) string {
	return fingerprintBytes(secret)
}

// fingerprintBytes implements the fingerprint formula on raw bytes,
// separated from Fingerprint so it can be unit tested without a live age
// decrypt.
func fingerprintBytes(secret []byte) string {
	h := sha256.New()
	h.Write([]byte("credroute-fp-v1"))
	h.Write(secret)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:32]
}

// Store implements Backend. The age backend is read-only: credroute
// routes to the maintainer's existing vault and never writes to it.
func (b *AgeBackend) Store(_ context.Context, _ Handle, _ *Secret) error {
	return ErrReadOnlyBackend
}

func expandHome(p string) (string, error) {
	if p == "" {
		return p, nil
	}
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if p == "~" {
		return home, nil
	}
	return filepath.Join(home, p[2:]), nil
}
