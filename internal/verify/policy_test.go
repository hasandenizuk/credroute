// allow-claude-code: see prober.go header.
package verify

import (
	"testing"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
)

func TestEffectiveVerifyMode_TightenOnlyNeverLoosens(t *testing.T) {
	cases := []struct {
		name     string
		cli      string
		rule     string
		defaults string
		want     string
	}{
		{"no override, default required", "", "", "required", "required"},
		{"no override, default advisory", "", "", "advisory", "advisory"},
		{"empty everything falls back to required", "", "", "", "required"},
		{"rule overrides default", "", "advisory", "required", "advisory"},
		{"cli tightens advisory to required", "required", "", "advisory", "required"},
		{"cli cannot loosen required to advisory", "advisory", "", "required", "required"},
		{"cli cannot loosen required to off", "off", "", "required", "required"},
		{"cli tightens off to advisory", "advisory", "", "off", "advisory"},
		{"cli equal to base is a no-op", "required", "", "required", "required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveVerifyMode(tc.cli, tc.rule, tc.defaults)
			if got != tc.want {
				t.Errorf("EffectiveVerifyMode(%q, %q, %q) = %q, want %q", tc.cli, tc.rule, tc.defaults, got, tc.want)
			}
		})
	}
}

func TestClassifyForResolve(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	maxAge := 24 * time.Hour

	t.Run("no sidecar is unverified", func(t *testing.T) {
		got := ClassifyForResolve(nil, attest.ErrNotFound, maxAge, now, "", "", "", "")
		if got != ResolveUnverified {
			t.Fatalf("got %q, want %q", got, ResolveUnverified)
		}
	})

	t.Run("tampered sidecar is unverified", func(t *testing.T) {
		got := ClassifyForResolve(nil, attest.ErrTampered, maxAge, now, "", "", "", "")
		if got != ResolveUnverified {
			t.Fatalf("got %q, want %q", got, ResolveUnverified)
		}
	})

	t.Run("fresh verified stays verified", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusVerified, CheckedAt: now.Add(-time.Hour)}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "", "", "")
		if got != ResolveVerified {
			t.Fatalf("got %q, want %q", got, ResolveVerified)
		}
	})

	t.Run("old verified becomes stale", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusVerified, CheckedAt: now.Add(-48 * time.Hour)}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "", "", "")
		if got != ResolveStale {
			t.Fatalf("got %q, want %q", got, ResolveStale)
		}
	})

	t.Run("maxAge zero disables staleness", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusVerified, CheckedAt: now.Add(-1000 * time.Hour)}
		got := ClassifyForResolve(rec, nil, 0, now, "", "", "", "")
		if got != ResolveVerified {
			t.Fatalf("got %q, want %q", got, ResolveVerified)
		}
	})

	t.Run("mismatch stays mismatch regardless of age", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusMismatch, CheckedAt: now.Add(-1000 * time.Hour)}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "", "", "")
		if got != ResolveMismatch {
			t.Fatalf("got %q, want %q", got, ResolveMismatch)
		}
	})

	t.Run("unreadable status maps to unverified", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusUnreadable, CheckedAt: now}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "", "", "")
		if got != ResolveUnverified {
			t.Fatalf("got %q, want %q", got, ResolveUnverified)
		}
	})

	t.Run("unconfirmed status maps to unconfirmed, distinct from verified", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusUnconfirmed, CheckedAt: now}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "", "", "")
		if got != ResolveUnconfirmed {
			t.Fatalf("got %q, want %q", got, ResolveUnconfirmed)
		}
	})

	t.Run("accepted baseline satisfies resolve", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusAcceptedBaseline, CheckedAt: now}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "", "", "")
		if got != ResolveAcceptedBaseline {
			t.Fatalf("got %q, want %q", got, ResolveAcceptedBaseline)
		}
	})

	// H2 (Fable 5 review v2): sidecars for slot-carrying credentials are
	// keyed by slot only, so a fresh "verified" sidecar earned by one
	// vault handle must not be readable as endorsing a DIFFERENT handle
	// now sitting behind the same slot.
	t.Run("verified sidecar for a re-pointed vault handle reads as unverified", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusVerified, CheckedAt: now, VaultHandle: "age://old-handle.age"}
		got := ClassifyForResolve(rec, nil, maxAge, now, "age://new-handle.age", "", "", "")
		if got != ResolveUnverified {
			t.Fatalf("got %q, want %q (handle mismatch must not read as verified)", got, ResolveUnverified)
		}
	})

	t.Run("verified sidecar for the same current vault handle still verifies", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusVerified, CheckedAt: now, VaultHandle: "age://same-handle.age"}
		got := ClassifyForResolve(rec, nil, maxAge, now, "age://same-handle.age", "", "", "")
		if got != ResolveVerified {
			t.Fatalf("got %q, want %q", got, ResolveVerified)
		}
	})

	t.Run("verified sidecar for another identity reads as unverified", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusVerified, CheckedAt: now, ExpectedIdentity: "a@example.com"}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "b@example.com", "", "")
		if got != ResolveUnverified {
			t.Fatalf("got %q, want %q (identity mismatch must not read as verified)", got, ResolveUnverified)
		}
	})

	t.Run("verified sidecar for another platform reads as unverified", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusVerified, CheckedAt: now, Platform: "github"}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "", "stripe", "")
		if got != ResolveUnverified {
			t.Fatalf("got %q, want %q (platform mismatch must not read as verified)", got, ResolveUnverified)
		}
	})

	t.Run("verified sidecar for another access level reads as unverified", func(t *testing.T) {
		rec := &attest.Record{Status: attest.StatusVerified, CheckedAt: now, AccessLevel: "read-only"}
		got := ClassifyForResolve(rec, nil, maxAge, now, "", "", "", "read-write")
		if got != ResolveUnverified {
			t.Fatalf("got %q, want %q (access mismatch must not read as verified)", got, ResolveUnverified)
		}
	})
}

func TestResolveStatusForAttest(t *testing.T) {
	cases := []struct {
		in   attest.Status
		want string
	}{
		{attest.StatusVerified, ResolveVerified},
		{attest.StatusAcceptedBaseline, ResolveAcceptedBaseline},
		{attest.StatusUnconfirmed, ResolveUnconfirmed},
		{attest.StatusMismatch, ResolveMismatch},
		{attest.StatusUnreadable, ResolveUnverified},
	}
	for _, tc := range cases {
		if got := ResolveStatusForAttest(tc.in); got != tc.want {
			t.Errorf("ResolveStatusForAttest(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestShouldRefuse(t *testing.T) {
	cases := []struct {
		mode   string
		status string
		want   bool
	}{
		{"required", ResolveMismatch, true},
		{"required", ResolveUnverified, true},
		{"required", ResolveStale, true},
		{"required", ResolveUnconfirmed, true},
		{"required", ResolveAcceptedBaseline, false},
		{"required", ResolveVerified, false},
		{"advisory", ResolveMismatch, false},
		{"advisory", ResolveUnconfirmed, false},
		{"advisory", ResolveUnverified, false},
		{"off", ResolveMismatch, false},
	}
	for _, tc := range cases {
		got := ShouldRefuse(tc.mode, tc.status)
		if got != tc.want {
			t.Errorf("ShouldRefuse(%q, %q) = %v, want %v", tc.mode, tc.status, got, tc.want)
		}
	}
}
