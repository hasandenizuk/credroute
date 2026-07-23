// allow-claude-code: see internal/rules/glob.go header.
package vault

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgeBackend_ResolvePath(t *testing.T) {
	b := &AgeBackend{StoreDir: "/vault/store"}

	cases := []struct {
		name    string
		handle  Handle
		want    string
		wantErr bool
	}{
		{"simple", "age://google/alex/ro.age", "/vault/store/google/alex/ro.age", false},
		{"single-segment", "age://secret.age", "/vault/store/secret.age", false},
		{"empty-handle", "", "", true},
		{"wrong-scheme", "sops://google/ro.age", "", true},
		{"no-path", "age://", "", true},
		{"path-traversal", "age://../../etc/passwd", "", true},
		{"path-traversal-encoded-segments", "age://google/../../etc/passwd", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := b.resolvePath(tc.handle)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolvePath(%q) = %q, want an error", tc.handle, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePath(%q) unexpected error: %v", tc.handle, err)
			}
			if got != tc.want {
				t.Errorf("resolvePath(%q) = %q, want %q", tc.handle, got, tc.want)
			}
		})
	}
}

func TestAgeBackend_Exists(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "google"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "google", "present.age"), []byte("cipher"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &AgeBackend{StoreDir: dir}

	ok, err := b.Exists(context.Background(), Handle("age://google/present.age"))
	if err != nil || !ok {
		t.Fatalf("Exists(present) = %v, %v, want true, nil", ok, err)
	}

	ok, err = b.Exists(context.Background(), Handle("age://google/absent.age"))
	if err != nil || ok {
		t.Fatalf("Exists(absent) = %v, %v, want false, nil", ok, err)
	}
}

func TestAgeBackend_RetrieveErrors(t *testing.T) {
	dir := t.TempDir()
	b := &AgeBackend{StoreDir: dir, IdentityFile: filepath.Join(dir, "identity.txt")}

	if _, err := b.Retrieve(context.Background(), Handle("age://google/missing.age")); err == nil {
		t.Fatal("expected an error retrieving a nonexistent handle")
	}
}

func TestFingerprintBytes_Deterministic(t *testing.T) {
	a := fingerprintBytes([]byte("same-secret"))
	b := fingerprintBytes([]byte("same-secret"))
	if a != b {
		t.Fatalf("fingerprintBytes is not deterministic: %q != %q", a, b)
	}
	c := fingerprintBytes([]byte("different-secret"))
	if a == c {
		t.Fatalf("fingerprintBytes produced the same value for different input")
	}
	if len(a) != 32 {
		t.Fatalf("fingerprintBytes length = %d, want 32 (per spec: hex(sha256(...))[0:32])", len(a))
	}
}

func TestSecret_NeverPrintsBytes(t *testing.T) {
	s := NewSecret([]byte("do-not-leak-me"))
	defer s.Zero()

	if got := s.String(); strings.Contains(got, "do-not-leak-me") {
		t.Fatalf("Secret.String() leaked the secret: %q", got)
	}
	if got := s.GoString(); strings.Contains(got, "do-not-leak-me") {
		t.Fatalf("Secret.GoString() leaked the secret: %q", got)
	}
}

func TestSecret_ZeroWipesBytes(t *testing.T) {
	var captured []byte
	s := NewSecret([]byte("wipe-me-please"))
	_ = s.WithBytes(func(b []byte) error {
		captured = b // same backing array as s.bytes
		return nil
	})
	s.Zero()
	for i, c := range captured {
		if c != 0 {
			t.Fatalf("byte %d not zeroed after Zero(): %v", i, captured)
		}
	}
}

func TestAgeBackend_Store_IsReadOnly(t *testing.T) {
	b := &AgeBackend{StoreDir: t.TempDir()}
	err := b.Store(context.Background(), Handle("age://google/x.age"), NewSecret([]byte("x")))
	if err != ErrReadOnlyBackend {
		t.Fatalf("Store error = %v, want ErrReadOnlyBackend", err)
	}
}

// TestAgeBackend_LiveRoundTrip exercises the real `age` binary: generate a
// keypair, encrypt a known secret into the store, decrypt it back through
// AgeBackend, and check the fingerprint formula against the plaintext.
// Skips if age/age-keygen are not on PATH.
func TestAgeBackend_LiveRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age binary not on PATH, skipping live round-trip test")
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen binary not on PATH, skipping live round-trip test")
	}

	dir := t.TempDir()
	identityFile := filepath.Join(dir, "identity.txt")
	storeDir := filepath.Join(dir, "store")
	if err := os.MkdirAll(filepath.Join(storeDir, "google"), 0o755); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("age-keygen", "-o", identityFile).CombinedOutput(); err != nil {
		t.Fatalf("age-keygen -o failed: %v: %s", err, out)
	}

	pubOut, err := exec.Command("age-keygen", "-y", identityFile).Output()
	if err != nil {
		t.Fatalf("age-keygen -y failed: %v", err)
	}
	recipient := strings.TrimSpace(string(pubOut))
	if recipient == "" {
		t.Fatal("age-keygen -y produced no recipient")
	}

	plaintext := []byte("test-plaintext-credential-value-12345")
	secretPath := filepath.Join(storeDir, "google", "test.age")
	encryptCmd := exec.Command("age", "-r", recipient, "-o", secretPath)
	encryptCmd.Stdin = bytes.NewReader(plaintext)
	if out, err := encryptCmd.CombinedOutput(); err != nil {
		t.Fatalf("age encrypt failed: %v: %s", err, out)
	}

	backend := &AgeBackend{StoreDir: storeDir, IdentityFile: identityFile}
	ctx := context.Background()
	handle := Handle("age://google/test.age")

	secret, err := backend.Retrieve(ctx, handle)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	defer secret.Zero()

	err = secret.WithBytes(func(b []byte) error {
		if !bytes.Equal(b, plaintext) {
			t.Errorf("decrypted bytes = %q, want %q", b, plaintext)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytes error: %v", err)
	}

	fp, err := backend.Fingerprint(ctx, handle)
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}
	want := fingerprintBytes(plaintext)
	if fp != want {
		t.Errorf("Fingerprint = %q, want %q", fp, want)
	}
}
