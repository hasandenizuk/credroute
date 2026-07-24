// allow-claude-code: see audit.go header.
package audit

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAppendAndReadAll(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())

	e1 := Entry{Op: "resolve", Dir: "/home/h/project", Platform: "google", Identity: "a@example.com", Access: "read-only", Rule: "acme-gsc", Verification: "verified", Exit: 0, Decision: "allow", Caller: "test"}
	if err := Append(e1); err != nil {
		t.Fatalf("Append e1: %v", err)
	}
	e2 := Entry{Op: "resolve", Platform: "github", Identity: "b@example.com", Access: "read-write", Exit: 2, Decision: "refuse", Caller: "test"}
	if err := Append(e2); err != nil {
		t.Fatalf("Append e2: %v", err)
	}

	all, err := ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(all), all)
	}
	if all[0].ID == "" || all[1].ID == "" {
		t.Fatal("Append did not assign an ID")
	}
	if all[0].ID == all[1].ID {
		t.Fatal("two entries got the same ID")
	}
	if all[0].TS.IsZero() {
		t.Fatal("Append did not stamp a timestamp")
	}
	if all[0].Platform != "google" || all[1].Platform != "github" {
		t.Fatalf("unexpected entries: %+v", all)
	}
}

func TestReadAll_MissingFileIsNotAnError(t *testing.T) {
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	entries, err := ReadAll()
	if err != nil {
		t.Fatalf("ReadAll on empty state dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}
}

func TestQuery_Filters(t *testing.T) {
	now := time.Now().UTC()
	entries := []Entry{
		{ID: "1", TS: now.Add(-48 * time.Hour), Platform: "google", Identity: "a@example.com", Exit: 0},
		{ID: "2", TS: now.Add(-1 * time.Hour), Platform: "google", Identity: "b@example.com", Exit: 3},
		{ID: "3", TS: now, Platform: "github", Identity: "a@example.com", Exit: 0},
	}

	byPlatform := Query(entries, Filter{Platform: "google"})
	if len(byPlatform) != 2 {
		t.Fatalf("platform filter: got %d, want 2", len(byPlatform))
	}

	byIdentity := Query(entries, Filter{Identity: "a@example.com"})
	if len(byIdentity) != 2 {
		t.Fatalf("identity filter: got %d, want 2", len(byIdentity))
	}

	failuresOnly := Query(entries, Filter{FailuresOnly: true})
	if len(failuresOnly) != 1 || failuresOnly[0].ID != "2" {
		t.Fatalf("failures filter: got %+v", failuresOnly)
	}

	sinceRecent := Query(entries, Filter{Since: now.Add(-2 * time.Hour)})
	if len(sinceRecent) != 2 {
		t.Fatalf("since filter: got %d, want 2", len(sinceRecent))
	}

	combined := Query(entries, Filter{Platform: "google", Since: now.Add(-2 * time.Hour)})
	want := []Entry{entries[1]}
	if !reflect.DeepEqual(combined, want) {
		t.Fatalf("combined filter: got %+v, want %+v", combined, want)
	}
}

// TestEntry_NeverHoldsASecret is a structural guarantee: audit.Entry must
// never gain a field shaped like a place to put secret bytes, since it is
// marshaled to a plaintext, machine-local file (spec 9.1 never-print-secret).
func TestEntry_NeverHoldsASecret(t *testing.T) {
	typ := reflect.TypeOf(Entry{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		if strings.Contains(name, "secret") || strings.Contains(name, "token") || strings.Contains(name, "password") || strings.Contains(name, "vault") {
			t.Fatalf("audit.Entry has a secret-shaped field: %s", typ.Field(i).Name)
		}
	}
}
