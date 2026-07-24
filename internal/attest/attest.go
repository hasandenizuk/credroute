// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 5) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
//
// Package attest implements the attestation sidecar (spec 5.4): a
// tamper-evident JSON record of the identity actually observed in a slot,
// written on every path that observes or changes what a slot holds
// (spec 5.2, "record reality on every path"). Sidecars are protected by an
// HMAC keyed with a machine-local key so a hand-edited or foreign-machine
// sidecar is detected on read and treated as unreadable, never as proof.
package attest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hasandenizuk/credroute/internal/fsutil"
)

// Status is the observed outcome recorded for one attestation. Spec 5.2:
// every observation records exactly one of these, and there is no code
// path that observes a slot and does not record.
type Status string

const (
	// StatusVerified is reserved for a prober that actually named the
	// account and it matched the expected identity (F2): the only status
	// that represents real identity confirmation.
	StatusVerified Status = "verified"
	// StatusUnconfirmed is a fingerprint-only baseline or unchanged
	// fingerprint (F2): the secret bytes are unchanged since the last
	// attestation (or there is nothing yet to compare against), but no
	// prober named the account, so identity itself was never confirmed.
	// Reported honestly instead of collapsing into StatusVerified.
	StatusUnconfirmed Status = "unconfirmed"
	StatusMismatch    Status = "mismatch"
	StatusUnreadable  Status = "unreadable"
)

// Record is the sidecar document (spec 5.4). One file per slot, or per
// slotless credential keyed by vault handle.
type Record struct {
	Version          int    `json:"version"`
	Slot             string `json:"slot,omitempty"`
	VaultHandle      string `json:"vault_handle"`
	ExpectedIdentity string `json:"expected_identity"`
	ObservedIdentity string `json:"observed_identity,omitempty"`
	Status           Status `json:"status"`
	// IdentityConfirmed is true only when a prober actually named the
	// account and it matched (F2): the honest "was identity itself
	// checked" signal, independent of Status, so a caller can tell a
	// probe-confirmed StatusVerified apart from a merely-unchanged
	// fingerprint baseline.
	IdentityConfirmed bool      `json:"identity_confirmed"`
	Method            string    `json:"method"`
	Fingerprint       string    `json:"fingerprint,omitempty"`
	ObservedScopes    []string  `json:"observed_scopes,omitempty"`
	CheckedAt         time.Time `json:"checked_at"`
	CheckedBy         string    `json:"checked_by,omitempty"`
	HMAC              string    `json:"hmac,omitempty"`
}

// ErrNotFound is returned by Read/ReadPath when no sidecar exists yet for
// the given key. Callers should treat this the same as "unverified", not
// as an error worth surfacing to the user.
var ErrNotFound = errors.New("attest: no sidecar recorded yet")

// ErrTampered is returned by Read/ReadPath when a sidecar exists but fails
// its HMAC check: a hand edit, a copy from another machine, or corruption.
// Spec 5.4: this is treated as unreadable, forcing re-verification; a
// sidecar minted elsewhere is evidence to re-verify, never proof.
var ErrTampered = errors.New("attest: sidecar failed integrity check (edited, foreign-machine, or corrupt)")

// IsNotFound reports whether err is (or wraps) ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// IsTampered reports whether err is (or wraps) ErrTampered.
func IsTampered(err error) bool { return errors.Is(err, ErrTampered) }

// KeyFor returns the identifier a sidecar is keyed by: the slot path when
// the credential has one, otherwise the vault handle. This matches spec
// 5.4 ("one file per slot, or per slotless credential, keyed by handle").
func KeyFor(slot, vaultHandle string) string {
	if slot != "" {
		return slot
	}
	return "handle:" + vaultHandle
}

// StateDir returns the credroute state directory, normally
// ~/.local/state/credroute. Set CREDROUTE_STATE_DIR to override (used by
// tests so they never touch a real home directory).
func StateDir() (string, error) {
	if v := os.Getenv("CREDROUTE_STATE_DIR"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("attest: determine home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "credroute"), nil
}

// AttestDir returns the directory sidecars are stored in.
func AttestDir() (string, error) {
	sd, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(sd, "attest"), nil
}

// MachineKeyPath returns the path to the machine-local HMAC key. Spec 5.4:
// 0600, never synced.
func MachineKeyPath() (string, error) {
	sd, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(sd, "machine.key"), nil
}

// SidecarPath returns the on-disk path for the sidecar identified by key
// (see KeyFor). Slot paths and vault handles both contain characters that
// are not safe file-name components, so the path is a hash of key rather
// than key itself; the record's own Slot/VaultHandle fields carry the
// human-readable identity.
func SidecarPath(key string) (string, error) {
	dir, err := AttestDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json"), nil
}

// machineKeyLen is the expected byte length of the HMAC machine key.
const machineKeyLen = 32

// loadOrCreateMachineKey reads the machine-local HMAC key, generating and
// persisting a fresh key on first use. F15: a key that exists but is not
// exactly machineKeyLen bytes, or whose permissions have drifted from
// 0600, is untrustworthy and is repaired/regenerated rather than trusted
// as-is: a world/group-readable key defeats the sidecar's whole tamper
// model, and a truncated/corrupt key would HMAC everything with
// predictable garbage. Regeneration is not silent to the caller in the
// sense that it changes behavior deliberately: every existing sidecar's
// HMAC becomes unverifiable (reads as tampered, i.e. ErrTampered) after a
// regeneration, which is the correct fail-closed outcome for a key that
// should never have been in that state, and callers already treat a
// tampered sidecar as "re-establish the baseline", never as evidence.
func loadOrCreateMachineKey() ([]byte, error) {
	path, err := MachineKeyPath()
	if err != nil {
		return nil, err
	}

	info, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		if info.Mode().Perm() != 0o600 {
			if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
				return nil, fmt.Errorf("attest: fix machine key permissions %s: %w", path, chmodErr)
			}
		}
		if info.Size() != machineKeyLen {
			return regenerateMachineKey(path)
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("attest: read machine key %s: %w", path, readErr)
		}
		if len(b) != machineKeyLen {
			return regenerateMachineKey(path)
		}
		return b, nil
	case errors.Is(statErr, os.ErrNotExist):
		return regenerateMachineKey(path)
	default:
		return nil, fmt.Errorf("attest: stat machine key %s: %w", path, statErr)
	}
}

// regenerateMachineKey writes a fresh random machineKeyLen-byte key to
// path, creating its parent directory if needed.
func regenerateMachineKey(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("attest: create state dir: %w", err)
	}
	key := make([]byte, machineKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("attest: generate machine key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("attest: write machine key %s: %w", path, err)
	}
	return key, nil
}

// EnsureMachineKey generates the machine-local HMAC key if it does not
// already exist. Exposed for `credroute init` (milestone 3) so first-run
// setup can prepare the key before any verify/resolve call needs it.
func EnsureMachineKey() error {
	_, err := loadOrCreateMachineKey()
	return err
}

// computeHMAC returns the "b64:..." HMAC-SHA256 of rec's canonical JSON
// (its HMAC field always excluded) keyed by key. rec is passed by value so
// clearing HMAC here never mutates the caller's copy.
func computeHMAC(rec Record, key []byte) (string, error) {
	rec.HMAC = ""
	b, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("attest: marshal for hmac: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return "b64:" + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Write records rec to its sidecar, computing and attaching the HMAC.
// Version defaults to 1 and CheckedAt defaults to now if unset. This is
// the single write path; every caller that observes a slot (verify,
// resolve's own read is separate, exec) goes through it, so a stale label
// can never survive a fresh contradictory observation.
func Write(rec *Record) error {
	if rec.Version == 0 {
		rec.Version = 1
	}
	if rec.CheckedAt.IsZero() {
		rec.CheckedAt = time.Now().UTC()
	}

	path, err := SidecarPath(KeyFor(rec.Slot, rec.VaultHandle))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("attest: create attest dir: %w", err)
	}

	key, err := loadOrCreateMachineKey()
	if err != nil {
		return err
	}
	mac, err := computeHMAC(*rec, key)
	if err != nil {
		return err
	}
	rec.HMAC = mac

	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("attest: marshal sidecar: %w", err)
	}

	if err := fsutil.WriteFileAtomic(path, b, 0o600); err != nil {
		return fmt.Errorf("attest: write sidecar: %w", err)
	}

	// Best-effort mirror next to the slot for tool visibility (spec 5.4)
	// when the slot is a directory that already exists. Failure here is
	// never fatal: the state-dir copy above is the record of truth.
	if rec.Slot != "" {
		if info, statErr := os.Stat(rec.Slot); statErr == nil && info.IsDir() {
			_ = fsutil.WriteFileAtomic(filepath.Join(rec.Slot, ".credroute-attest.json"), b, 0o600)
		}
	}
	return nil
}

// ReadPath reads and HMAC-verifies the sidecar at path directly. Doctor
// uses this to scan every sidecar in AttestDir without needing to
// reconstruct each one's key first.
func ReadPath(path string) (*Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("attest: read %s: %w", path, err)
	}

	var rec Record
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("attest: parse %s: %w", path, err)
	}

	key, err := loadOrCreateMachineKey()
	if err != nil {
		return nil, err
	}
	want, err := computeHMAC(rec, key)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(want), []byte(rec.HMAC)) {
		return nil, ErrTampered
	}
	return &rec, nil
}

// Read looks up the sidecar for the credential identified by slot/
// vaultHandle (see KeyFor) and HMAC-verifies it. Returns ErrNotFound if no
// sidecar has ever been written for this key, ErrTampered if one exists
// but fails integrity.
func Read(slot, vaultHandle string) (*Record, error) {
	path, err := SidecarPath(KeyFor(slot, vaultHandle))
	if err != nil {
		return nil, err
	}
	return ReadPath(path)
}

// ListPaths returns every sidecar file currently in AttestDir. Used by
// doctor to sweep all recorded attestations without prior knowledge of
// their keys.
func ListPaths() ([]string, error) {
	dir, err := AttestDir()
	if err != nil {
		return nil, err
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("attest: list %s: %w", dir, err)
	}
	return matches, nil
}

// DefaultCheckedBy builds the sidecar's checked_by field in the form
// "credroute/<version> host=<hostname>" (spec 5.4 example).
func DefaultCheckedBy(version string) string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("credroute/%s host=%s", version, host)
}
