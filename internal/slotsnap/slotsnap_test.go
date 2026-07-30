package slotsnap

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotRestoreCleansTempCopyWhenSwapFails(t *testing.T) {
	parent := t.TempDir()
	slot := filepath.Join(parent, "slot")
	if err := os.WriteFile(slot, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(t.TempDir(), "slot")
	if err := os.WriteFile(snapshotPath, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Slot: slot, Target: slot, Path: snapshotPath}
	renamePath = func(oldpath, newpath string) error {
		if oldpath == slot {
			return errors.New("forced rename failure")
		}
		return os.Rename(oldpath, newpath)
	}
	defer func() { renamePath = os.Rename }()

	err := snap.Restore()
	if err == nil {
		t.Fatal("Restore succeeded, want failure")
	}
	entries, readErr := os.ReadDir(parent)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".credroute-restore-") {
			t.Fatalf("restore temp copy was left behind: %s", entry.Name())
		}
	}
}

func TestTakeRefusesSymlinkInsideDirectorySlot(t *testing.T) {
	stateDir := t.TempDir()
	parent := t.TempDir()
	realDir := filepath.Join(parent, "real")
	slot := filepath.Join(parent, "slot")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(slot, 0o700); err != nil {
		t.Fatal(err)
	}
	realToken := filepath.Join(realDir, "token.json")
	if err := os.WriteFile(realToken, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realToken, filepath.Join(slot, "token.json")); err != nil {
		t.Fatal(err)
	}

	snap, err := Take(stateDir, slot)
	if err == nil {
		t.Fatalf("Take succeeded with symlinked entry, snapshot=%+v", snap)
	}
	if !strings.Contains(err.Error(), "symlink inside slot is unsafe") {
		t.Fatalf("Take error = %q, want unsafe symlink refusal", err)
	}
	got, readErr := os.ReadFile(realToken)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "before" {
		t.Fatalf("real credential changed to %q, want before", got)
	}
	entries, readErr := os.ReadDir(filepath.Join(stateDir, "login-snapshots"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed snapshot left plaintext copy dirs behind: %d", len(entries))
	}
}
