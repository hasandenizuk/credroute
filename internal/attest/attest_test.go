// allow-claude-code: see attest.go header.
package attest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteRead_RoundTrip(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	rec := &Record{
		Slot:             "/home/h/.config/gws/profiles/acme-gsc",
		VaultHandle:      "age://google/reports-acme-corp-com/gsc-ro.json.age",
		ExpectedIdentity: "reports@acme-corp.com",
		ObservedIdentity: "reports@acme-corp.com",
		Status:           StatusVerified,
		Method:           "oauth_probe",
		Fingerprint:      "deadbeef",
		ObservedScopes:   []string{"https://www.googleapis.com/auth/webmasters.readonly"},
		CheckedBy:        "credroute/test",
	}
	if err := Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rec.HMAC == "" {
		t.Fatal("Write did not attach an HMAC")
	}

	got, err := Read(rec.Slot, rec.VaultHandle)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.ExpectedIdentity != rec.ExpectedIdentity || got.ObservedIdentity != rec.ObservedIdentity {
		t.Fatalf("round trip mismatch: got %+v", got)
	}
	if got.Status != StatusVerified {
		t.Fatalf("Status = %q, want verified", got.Status)
	}
	if got.CheckedAt.IsZero() {
		t.Fatal("CheckedAt was not persisted")
	}
}

func TestRead_NotFound(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	_, err := Read("/no/such/slot", "age://google/x.age")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read on missing sidecar = %v, want ErrNotFound", err)
	}
}

func TestRead_TamperDetected(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	rec := &Record{
		VaultHandle:      "age://github/alex/pat.age",
		ExpectedIdentity: "alex",
		ObservedIdentity: "alex",
		Status:           StatusVerified,
		Method:           "fingerprint",
		Fingerprint:      "abc123",
	}
	if err := Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	path, err := SidecarPath(KeyFor(rec.Slot, rec.VaultHandle))
	if err != nil {
		t.Fatalf("SidecarPath: %v", err)
	}

	// Hand-edit the sidecar on disk without recomputing the HMAC: this is
	// exactly the "stale correct label survives a wrong re-login" failure
	// mode the sidecar exists to close.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	var onDisk map[string]interface{}
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatalf("unmarshal sidecar: %v", err)
	}
	onDisk["observed_identity"] = "someone-else@example.com"
	tampered, err := json.Marshal(onDisk)
	if err != nil {
		t.Fatalf("marshal tampered sidecar: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered sidecar: %v", err)
	}

	_, err = Read(rec.Slot, rec.VaultHandle)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("Read on tampered sidecar = %v, want ErrTampered", err)
	}

	// ReadPath (the doctor sweep entry point) must detect the same thing.
	_, err = ReadPath(path)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("ReadPath on tampered sidecar = %v, want ErrTampered", err)
	}
}

func TestKeyFor_PrefersSlotOverHandle(t *testing.T) {
	if got := KeyFor("/some/slot", "age://x.age"); got != "/some/slot" {
		t.Fatalf("KeyFor with slot = %q, want the slot", got)
	}
	if got := KeyFor("", "age://x.age"); got != "handle:age://x.age" {
		t.Fatalf("KeyFor without slot = %q, want handle-prefixed", got)
	}
}

func TestListPaths_FindsWrittenSidecars(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	for i := 0; i < 3; i++ {
		rec := &Record{
			VaultHandle:      "age://x/" + string(rune('a'+i)) + ".age",
			ExpectedIdentity: "id",
			ObservedIdentity: "id",
			Status:           StatusVerified,
			Method:           "fingerprint",
		}
		if err := Write(rec); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	paths, err := ListPaths()
	if err != nil {
		t.Fatalf("ListPaths: %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("ListPaths returned %d paths, want 3: %v", len(paths), paths)
	}
	for _, p := range paths {
		if filepath.Ext(p) != ".json" {
			t.Errorf("unexpected non-json sidecar path %q", p)
		}
	}
}

func TestWrite_MirrorsToSlotDirectory(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	slotDir := t.TempDir()

	rec := &Record{
		Slot:             slotDir,
		VaultHandle:      "age://google/x.age",
		ExpectedIdentity: "alex@example.com",
		ObservedIdentity: "alex@example.com",
		Status:           StatusVerified,
		Method:           "oauth_probe",
	}
	if err := Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	mirrored := filepath.Join(slotDir, ".credroute-attest.json")
	if _, err := os.Stat(mirrored); err != nil {
		t.Fatalf("expected mirrored sidecar at %s: %v", mirrored, err)
	}
	b, err := os.ReadFile(mirrored)
	if err != nil {
		t.Fatalf("read mirrored sidecar: %v", err)
	}
	if contains(string(b), "age://google/x.age") || contains(string(b), "alex@example.com") || contains(string(b), slotDir) {
		t.Fatalf("mirrored sidecar leaked routing metadata: %s", b)
	}
}

func TestDefaultCheckedBy_IncludesVersionAndHost(t *testing.T) {
	got := DefaultCheckedBy("0.2.0")
	if got == "" {
		t.Fatal("DefaultCheckedBy returned empty string")
	}
	if !contains(got, "0.2.0") {
		t.Fatalf("DefaultCheckedBy(%q) missing version", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

func TestWrite_DefaultsVersionAndTimestamp(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	before := time.Now().Add(-time.Second)
	rec := &Record{
		VaultHandle:      "age://x/y.age",
		ExpectedIdentity: "id",
		Status:           StatusUnreadable,
		Method:           "fingerprint",
	}
	if err := Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if rec.Version != 1 {
		t.Fatalf("Version = %d, want 1", rec.Version)
	}
	if rec.CheckedAt.Before(before) {
		t.Fatalf("CheckedAt not defaulted to now: %v", rec.CheckedAt)
	}
}
