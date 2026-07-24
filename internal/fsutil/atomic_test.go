// allow-claude-code: see atomic.go header.
package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic_WritesContentAndPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := WriteFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("content = %q, want %q", b, "hello")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %v, want 0600", info.Mode().Perm())
	}
}

func TestWriteFileAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := WriteFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(b) != "second" {
		t.Errorf("content = %q, want %q", b, "second")
	}

	// No leftover temp files in dir.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (leftover temp file?): %v", len(entries), entries)
	}
}

func TestWriteFileAtomic_NoDirIsError(t *testing.T) {
	if err := WriteFileAtomic(filepath.Join(t.TempDir(), "missing-subdir", "out.txt"), []byte("x"), 0o600); err == nil {
		t.Error("expected an error writing into a missing directory, got nil")
	}
}
