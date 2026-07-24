// allow-claude-code: mechanical extraction of the existing atomic-write
// helper (previously a private copy in internal/attest, Fable 5 review
// F13) into a shared package, so every write path that needs a
// crash-safe file write (attestation sidecars, machine key, and the new
// config.yaml editing commands) uses the exact same implementation
// instead of a second hand-copy.
//
// Package fsutil holds small filesystem helpers shared across credroute's
// internal packages.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes b to path atomically: a uniquely-named temp file
// in the same directory (never a fixed "path+.tmp" name, so two
// concurrent writers can never collide on it), fsynced before rename so
// the write survives a crash between write and rename, then renamed into
// place. The temp file is always cleaned up on any failure path. The
// parent directory of path must already exist; callers that may be
// writing a fresh state directory create it first (matching the
// pre-existing behavior this replaces).
func WriteFileAtomic(path string, b []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("fsutil: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsutil: chmod temp file %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsutil: write temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsutil: fsync temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fsutil: close temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("fsutil: rename %s to %s: %w", tmpPath, path, err)
	}
	ok = true
	return nil
}
