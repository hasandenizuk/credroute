// allow-claude-code: see store.go header.
package vault

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStoreBackend_ResolvePath(t *testing.T) {
	b := &StoreBackend{Dir: "/vault/store"}

	p, err := b.resolvePath(Handle("store://github/me/pat"))
	if err != nil {
		t.Fatalf("resolvePath: %v", err)
	}
	if p != filepath.Join("/vault/store", "github/me/pat") {
		t.Errorf("resolvePath = %q", p)
	}

	if _, err := b.resolvePath(Handle("age://github/me/pat")); err == nil {
		t.Error("expected an error for a non-store scheme, got nil")
	}
	if _, err := b.resolvePath(Handle("store://../../etc/passwd")); err == nil {
		t.Error("expected an error for a path-traversal handle, got nil")
	}
	if _, err := b.resolvePath(Handle("")); err == nil {
		t.Error("expected an error for an empty handle, got nil")
	}
}

func TestStoreBackend_Exists(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "github", "pat.age"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &StoreBackend{Dir: dir}

	exists, err := b.Exists(context.Background(), Handle("store://github/pat.age"))
	if err != nil || !exists {
		t.Errorf("Exists = %v, %v, want true, nil", exists, err)
	}
	exists, err = b.Exists(context.Background(), Handle("store://github/missing.age"))
	if err != nil || exists {
		t.Errorf("Exists = %v, %v, want false, nil", exists, err)
	}
}

// TestStoreBackend_List_SkipsTempResidue guards L7 (Fable 5 review v2): a
// crashed `store add` between CreateTemp and rename can leave a
// ".<name>.tmp-<random>" file behind; List must never surface it as a
// real handle.
func TestStoreBackend_List_SkipsTempResidue(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "github", "pat.age"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "github", ".pat.age.tmp-12345"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &StoreBackend{Dir: dir}

	handles, err := b.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range handles {
		if h == "store://github/.pat.age.tmp-12345" {
			t.Errorf("List surfaced a crash-orphaned temp file as a handle: %v", handles)
		}
	}
	if len(handles) != 1 || handles[0] != "store://github/pat.age" {
		t.Errorf("List = %v, want only [store://github/pat.age]", handles)
	}
}

func TestStoreBackend_Capabilities(t *testing.T) {
	b := &StoreBackend{}
	caps := b.Capabilities()
	if !caps.CanStore || !caps.CanList {
		t.Errorf("Capabilities = %+v, want CanStore and CanList both true", caps)
	}
}

// TestStoreBackend_LiveRoundTrip exercises the real age/age-keygen
// binaries: generate a keypair, Store a secret, Retrieve it back,
// Fingerprint it, and List it. Skips if age/age-keygen are not on PATH
// (matches internal/vault's existing AgeBackend live-round-trip test).
func TestStoreBackend_LiveRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age binary not on PATH, skipping live round-trip test")
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen binary not on PATH, skipping live round-trip test")
	}

	dir := t.TempDir()
	identityFile := filepath.Join(dir, "identity.txt")
	storeDir := filepath.Join(dir, "store")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("age-keygen", "-o", identityFile).CombinedOutput(); err != nil {
		t.Fatalf("age-keygen -o failed: %v: %s", err, out)
	}

	backend := &StoreBackend{Dir: storeDir, IdentityFile: identityFile}
	ctx := context.Background()
	handle := Handle("store://github/me/pat")
	plaintext := []byte("ghp_test-round-trip-secret-value")

	if err := backend.Store(ctx, handle, NewSecret(append([]byte(nil), plaintext...))); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	exists, err := backend.Exists(ctx, handle)
	if err != nil || !exists {
		t.Fatalf("Exists after Store = %v, %v, want true, nil", exists, err)
	}

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
	if want := fingerprintBytes(plaintext); fp != want {
		t.Errorf("Fingerprint = %q, want %q", fp, want)
	}

	handles, err := backend.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	found := false
	for _, h := range handles {
		if h == string(handle) {
			found = true
		}
	}
	if !found {
		t.Errorf("List = %v, want to contain %q", handles, handle)
	}

	// Overwrite (Store again at the same handle) round-trips to the new
	// value, proving Store is a real write path, not append-only.
	updated := []byte("ghp_updated-secret-value")
	if err := backend.Store(ctx, handle, NewSecret(append([]byte(nil), updated...))); err != nil {
		t.Fatalf("second Store failed: %v", err)
	}
	secret2, err := backend.Retrieve(ctx, handle)
	if err != nil {
		t.Fatalf("Retrieve after overwrite failed: %v", err)
	}
	defer secret2.Zero()
	err = secret2.WithBytes(func(b []byte) error {
		if !bytes.Equal(b, updated) {
			t.Errorf("decrypted bytes after overwrite = %q, want %q", b, updated)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytes error: %v", err)
	}
}

func TestStoreBackend_Retrieve_MissingSecret(t *testing.T) {
	dir := t.TempDir()
	b := &StoreBackend{Dir: dir, IdentityFile: filepath.Join(dir, "identity.txt")}
	_, err := b.Retrieve(context.Background(), Handle("store://missing.age"))
	if err == nil {
		t.Error("expected an error retrieving a missing secret, got nil")
	}
}

func TestStoreBackend_List_EmptyDirIsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	b := &StoreBackend{Dir: dir}
	handles, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(handles) != 0 {
		t.Errorf("List of empty dir = %v, want empty", handles)
	}
}

func TestStoreBackend_List_NoDirConfigured(t *testing.T) {
	b := &StoreBackend{}
	if _, err := b.List(context.Background()); err == nil {
		t.Error("expected an error with no Dir configured, got nil")
	}
}
