// allow-claude-code: see prober.go header.
package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hasandenizuk/credroute/internal/vault"
)

func TestFingerprintProber_NeverNamesIdentity(t *testing.T) {
	p := FingerprintProber{}
	identity, scopes, err := p.Probe(context.Background(), vault.NewSecret([]byte("anything")), "google")
	if err != nil {
		t.Fatalf("Probe returned an error: %v", err)
	}
	if identity != "" {
		t.Fatalf("identity = %q, want empty (fingerprint prober cannot name an account)", identity)
	}
	if scopes != nil {
		t.Fatalf("scopes = %v, want nil", scopes)
	}
	if p.Method() != "fingerprint" {
		t.Fatalf("Method() = %q, want fingerprint", p.Method())
	}
}

// TestGoogleOAuthProber_LiveNetwork_NeverCalled documents (and enforces via
// go vet's unused-import-free build) that the CLI never registers a
// GoogleOAuthProber unless the operator explicitly opts in via
// NewRegistry(true). Every other test in this file points Endpoint at a
// local httptest server, so no test here ever reaches a real network
// endpoint.
func TestRegistry_DefaultHasNoLiveGoogleProber(t *testing.T) {
	reg := NewRegistry(false)
	p := reg.Best("google")
	if _, ok := p.(*GoogleOAuthProber); ok {
		t.Fatal("NewRegistry(false) registered a live GoogleOAuthProber; the gate is broken")
	}
	if p.Method() != "fingerprint" {
		t.Fatalf("default google prober method = %q, want fingerprint fallback", p.Method())
	}
}

func TestRegistry_LiveEnabledUsesGoogleProber(t *testing.T) {
	reg := NewRegistry(true)
	p := reg.Best("google")
	if _, ok := p.(*GoogleOAuthProber); !ok {
		t.Fatalf("NewRegistry(true) did not register a GoogleOAuthProber for google, got %T", p)
	}
	// A platform with no dedicated prober still falls back.
	other := reg.Best("github")
	if other.Method() != "fingerprint" {
		t.Fatalf("github (no dedicated prober) method = %q, want fingerprint fallback", other.Method())
	}
}

func TestGoogleOAuthProber_Probe_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-access-token" {
			t.Errorf("Authorization header = %q, want Bearer test-access-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"email": "reports@acme-corp.com"})
	}))
	defer srv.Close()

	prober := &GoogleOAuthProber{Endpoint: srv.URL, HTTPClient: srv.Client()}
	secret := vault.NewSecret([]byte(`{"access_token":"test-access-token","scope":"scope-a scope-b"}`))
	defer secret.Zero()

	identity, scopes, err := prober.Probe(context.Background(), secret, "google")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if identity != "reports@acme-corp.com" {
		t.Fatalf("identity = %q, want reports@acme-corp.com", identity)
	}
	if len(scopes) != 2 || scopes[0] != "scope-a" || scopes[1] != "scope-b" {
		t.Fatalf("scopes = %v, want [scope-a scope-b]", scopes)
	}
}

func TestGoogleOAuthProber_Probe_WrongPlatform(t *testing.T) {
	prober := &GoogleOAuthProber{Endpoint: "http://127.0.0.1:0"}
	secret := vault.NewSecret([]byte(`{"access_token":"x"}`))
	defer secret.Zero()

	if _, _, err := prober.Probe(context.Background(), secret, "github"); err == nil {
		t.Fatal("expected an error for a non-google platform")
	}
}

func TestGoogleOAuthProber_Probe_UpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	prober := &GoogleOAuthProber{Endpoint: srv.URL, HTTPClient: srv.Client()}
	secret := vault.NewSecret([]byte(`{"access_token":"expired"}`))
	defer secret.Zero()

	identity, _, err := prober.Probe(context.Background(), secret, "google")
	if err == nil {
		t.Fatal("expected an error on a non-200 userinfo response")
	}
	if identity != "" {
		t.Fatalf("identity = %q, want empty on error", identity)
	}
}

func TestGoogleOAuthProber_Probe_NoAccessToken(t *testing.T) {
	prober := &GoogleOAuthProber{Endpoint: "http://127.0.0.1:0"}
	secret := vault.NewSecret([]byte(`{"scope":"a"}`))
	defer secret.Zero()

	if _, _, err := prober.Probe(context.Background(), secret, "google"); err == nil {
		t.Fatal("expected an error when the credential has no access_token")
	}
}
