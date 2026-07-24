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

// TestRegistry_DisabledHasNoLiveProbers documents (and enforces via
// go vet's unused-import-free build) that a registry built with
// enableLiveProbes=false never touches the real network. Every other test
// in this file that wants a live-shaped prober points Endpoint at a local
// httptest server instead of relying on this registry.
func TestRegistry_DisabledHasNoLiveProbers(t *testing.T) {
	reg := NewRegistry(false)
	if p := reg.Best("google"); p.Method() != "fingerprint" {
		if _, ok := p.(*GoogleOAuthProber); ok {
			t.Fatal("NewRegistry(false) registered a live GoogleOAuthProber; the gate is broken")
		}
	}
	if p := reg.Best("github"); p.Method() != "fingerprint" {
		if _, ok := p.(*GitHubPATProber); ok {
			t.Fatal("NewRegistry(false) registered a live GitHubPATProber; the gate is broken")
		}
	}
}

func TestRegistry_LiveEnabledUsesRealProbers(t *testing.T) {
	reg := NewRegistry(true)
	if p := reg.Best("google"); func() bool { _, ok := p.(*GoogleOAuthProber); return !ok }() {
		t.Fatalf("NewRegistry(true) did not register a GoogleOAuthProber for google, got %T", p)
	}
	if p := reg.Best("github"); func() bool { _, ok := p.(*GitHubPATProber); return !ok }() {
		t.Fatalf("NewRegistry(true) did not register a GitHubPATProber for github, got %T", p)
	}
	// A platform with no dedicated prober still falls back.
	other := reg.Best("stripe")
	if other.Method() != "fingerprint" {
		t.Fatalf("stripe (no dedicated prober) method = %q, want fingerprint fallback", other.Method())
	}
}

// TestLiveProbesEnabled_NoNetworkSwitch is F2/F5's test-safety mechanism:
// CREDROUTE_NO_NETWORK=1 must disable live probes; unset (the real-usage
// default) must enable them. Every other test in this package that
// exercises Run/cmdVerify-shaped flows sets CREDROUTE_NO_NETWORK=1 so
// `go test` never reaches a real endpoint.
func TestLiveProbesEnabled_NoNetworkSwitch(t *testing.T) {
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	if LiveProbesEnabled() {
		t.Fatal("LiveProbesEnabled() = true with CREDROUTE_NO_NETWORK=1, want false")
	}
	t.Setenv("CREDROUTE_NO_NETWORK", "")
	if !LiveProbesEnabled() {
		t.Fatal("LiveProbesEnabled() = false with CREDROUTE_NO_NETWORK unset, want true (default on)")
	}
}

func TestGitHubPATProber_Probe_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghp_test_token" {
			t.Errorf("Authorization header = %q, want Bearer ghp_test_token", got)
		}
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "alex"})
	}))
	defer srv.Close()

	prober := &GitHubPATProber{Endpoint: srv.URL, HTTPClient: srv.Client()}
	secret := vault.NewSecret([]byte("ghp_test_token\n"))
	defer secret.Zero()

	identity, scopes, err := prober.Probe(context.Background(), secret, "github")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if identity != "alex" {
		t.Fatalf("identity = %q, want alex", identity)
	}
	if len(scopes) != 2 || scopes[0] != "repo" || scopes[1] != "read:org" {
		t.Fatalf("scopes = %v, want [repo read:org]", scopes)
	}
}

func TestGitHubPATProber_Probe_WrongPlatform(t *testing.T) {
	prober := &GitHubPATProber{Endpoint: "http://127.0.0.1:0"}
	secret := vault.NewSecret([]byte("ghp_test_token"))
	defer secret.Zero()

	if _, _, err := prober.Probe(context.Background(), secret, "google"); err == nil {
		t.Fatal("expected an error for a non-github platform")
	}
}

func TestGitHubPATProber_Probe_UpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	prober := &GitHubPATProber{Endpoint: srv.URL, HTTPClient: srv.Client()}
	secret := vault.NewSecret([]byte("bad-token"))
	defer secret.Zero()

	if _, _, err := prober.Probe(context.Background(), secret, "github"); err == nil {
		t.Fatal("expected an error on a non-200 /user response")
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
