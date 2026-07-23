// allow-claude-code: see internal/rules/glob.go header.
//
// Package vault defines the backend interface credroute uses to
// dereference a vault handle to a secret, plus the Secret type that
// guarantees secret bytes never leak through Printf/log/error paths.
package vault

import (
	"context"
	"errors"
)

// Handle is an opaque vault URI, e.g. "age://github/me/pat.age".
type Handle string

// ErrReadOnlyBackend is returned by Store when a backend does not support
// writing (Capabilities().CanStore == false).
var ErrReadOnlyBackend = errors.New("vault: backend is read-only, Store is not supported")

// Secret holds decrypted secret bytes. The byte slice is unexported so the
// only way to read it is WithBytes, and the only sanctioned exits are:
// (a) injection into a child process environment (see exec), and
// (b) an explicit, gated handle-get path. String()/GoString() always
// redact so accidental fmt/log/error-wrap calls never print the value.
type Secret struct {
	bytes []byte
}

// NewSecret wraps b in a Secret. The caller must not retain b after this
// call; Secret takes ownership and Zero() will wipe it.
func NewSecret(b []byte) *Secret {
	return &Secret{bytes: b}
}

// WithBytes calls f with the secret's raw bytes. The slice passed to f
// must not be retained beyond the call.
func (s *Secret) WithBytes(f func([]byte) error) error {
	if s == nil {
		return errors.New("vault: WithBytes on nil Secret")
	}
	return f(s.bytes)
}

// Zero overwrites the secret bytes with zeros. Safe to call multiple
// times and on a nil Secret.
func (s *Secret) Zero() {
	if s == nil {
		return
	}
	for i := range s.bytes {
		s.bytes[i] = 0
	}
	s.bytes = nil
}

// String implements fmt.Stringer with a redacted placeholder. This is the
// primary defense against a Secret accidentally reaching a log line.
func (s *Secret) String() string {
	return "<redacted secret>"
}

// GoString implements fmt.GoStringer with the same redaction as String,
// so %#v does not leak bytes either.
func (s *Secret) GoString() string {
	return "vault.Secret{<redacted>}"
}

// Capabilities describes what a backend supports beyond read.
type Capabilities struct {
	CanStore bool
	CanList  bool
}

// Backend is the interface every vault implementation (age, and future
// SOPS/Bitwarden backends) satisfies.
type Backend interface {
	// Name is the backend's registered name, e.g. "age".
	Name() string

	Capabilities() Capabilities

	// Retrieve decrypts/fetches the secret for h. Callers MUST call
	// secret.Zero() when done (typically via defer).
	Retrieve(ctx context.Context, h Handle) (*Secret, error)

	// Exists reports whether h resolves to something, without decrypting
	// where the backend allows a cheap existence check.
	Exists(ctx context.Context, h Handle) (bool, error)

	// Fingerprint returns the attestation fingerprint of the secret at h.
	// Implementations may decrypt internally but must not retain
	// plaintext beyond the call.
	Fingerprint(ctx context.Context, h Handle) (string, error)

	// Store writes s to h. Backends without CanStore return
	// ErrReadOnlyBackend.
	Store(ctx context.Context, h Handle, s *Secret) error
}
