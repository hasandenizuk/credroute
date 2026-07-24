// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 5) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
//
// Package verify implements verify-identity-in-slot (spec section 5): the
// probers that observe what identity a slot actually holds, the
// comparison-and-record flow that turns an observation into an
// attestation, and the small policy functions resolve/exec use to decide
// whether a verification result is good enough to proceed.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hasandenizuk/credroute/internal/vault"
)

// Prober observes the identity actually present in a credential's secret
// bytes. Not every prober can name an identity: the generic fingerprint
// prober always returns an empty identity (it can only detect change, per
// spec 5.3), and callers must treat that as "identity unconfirmed", never
// as a match.
type Prober interface {
	// Probe returns the identity and (where available) scopes it observed
	// for secret on platform. An empty identity with a nil error is a
	// legitimate "cannot name this identity" answer, not a failure. A
	// non-nil error means the probe itself failed (e.g. a live HTTP call
	// errored) and must never be treated as a successful identity match.
	Probe(ctx context.Context, secret *vault.Secret, platform string) (identity string, scopes []string, err error)

	// Method names the technique for the sidecar's "method" field, e.g.
	// "fingerprint" or "oauth_probe" (spec 5.3/5.4).
	Method() string
}

// FingerprintProber is the generic, always-available fallback (spec 5.3):
// it never names an account, so Probe always returns an empty identity and
// a nil error. Callers pair it with a fingerprint comparison against the
// prior attestation to detect a swapped or edited secret.
type FingerprintProber struct{}

// Method implements Prober.
func (FingerprintProber) Method() string { return "fingerprint" }

// Probe implements Prober. It deliberately does nothing with secret: the
// fingerprint comparison happens one level up in Run, using
// vault.FingerprintBytes on the same decrypted bytes.
func (FingerprintProber) Probe(_ context.Context, _ *vault.Secret, _ string) (string, []string, error) {
	return "", nil, nil
}

// defaultGoogleUserinfoEndpoint is Google's OpenID Connect userinfo
// endpoint (spec 5.3 table: OAuth -> live probe, field "email").
const defaultGoogleUserinfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo"

// GoogleOAuthProber probes a Google OAuth credential's live identity by
// calling the userinfo endpoint with the credential's access token. It
// makes a real network call; unit tests exercise it against an httptest
// server via Endpoint/HTTPClient, and every test run sets
// CREDROUTE_NO_NETWORK=1 so LiveProbesEnabled() never registers this
// prober against the real endpoint during `go test`.
type GoogleOAuthProber struct {
	// Endpoint overrides the userinfo URL. Empty uses the real Google
	// endpoint; tests point this at an httptest.Server.
	Endpoint string
	// HTTPClient overrides the client used for the request. Nil uses a
	// client with a short timeout.
	HTTPClient *http.Client
}

// NewGoogleOAuthProber returns a prober configured against the real Google
// endpoint with a bounded timeout.
func NewGoogleOAuthProber() *GoogleOAuthProber {
	return &GoogleOAuthProber{
		Endpoint:   defaultGoogleUserinfoEndpoint,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Method implements Prober.
func (p *GoogleOAuthProber) Method() string { return "oauth_probe" }

func (p *GoogleOAuthProber) endpoint() string {
	if p.Endpoint != "" {
		return p.Endpoint
	}
	return defaultGoogleUserinfoEndpoint
}

func (p *GoogleOAuthProber) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// oauthCredential is the shape credroute's OAuth vault secrets are stored
// in: a JSON document with at least an access token and, where the
// platform reports it, a space-separated scope string (the gws/Google
// convention this prober targets).
type oauthCredential struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

// Probe implements Prober by calling the Google userinfo endpoint. platform
// must be "google"; any other value is a caller error, not an identity
// mismatch, so it is returned as err.
func (p *GoogleOAuthProber) Probe(ctx context.Context, secret *vault.Secret, platform string) (string, []string, error) {
	if platform != "google" {
		return "", nil, fmt.Errorf("verify: google oauth prober does not support platform %q", platform)
	}
	if secret == nil {
		return "", nil, errors.New("verify: google oauth prober got a nil secret")
	}

	var cred oauthCredential
	err := secret.WithBytes(func(b []byte) error {
		return json.Unmarshal(b, &cred)
	})
	if err != nil {
		return "", nil, fmt.Errorf("verify: parse oauth credential json: %w", err)
	}
	if cred.AccessToken == "" {
		return "", nil, errors.New("verify: oauth credential has no access_token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint(), nil)
	if err != nil {
		return "", nil, fmt.Errorf("verify: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)

	resp, err := p.client().Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("verify: userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("verify: userinfo returned status %d", resp.StatusCode)
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", nil, fmt.Errorf("verify: parse userinfo response: %w", err)
	}
	if body.Email == "" {
		return "", nil, errors.New("verify: userinfo response has no email field")
	}

	var scopes []string
	if cred.Scope != "" {
		scopes = strings.Fields(cred.Scope)
	}
	return body.Email, scopes, nil
}

// defaultGitHubUserEndpoint is GitHub's whoami endpoint (spec 5.3 table:
// PAT -> live probe, GET /user -> login, X-OAuth-Scopes header).
const defaultGitHubUserEndpoint = "https://api.github.com/user"

// GitHubPATProber probes a GitHub PAT (or OAuth token used PAT-style) by
// calling GET /user with it as a bearer token (spec 6.1 profile:
// auth_header "Authorization: Bearer {secret}"). The vault secret for a
// github pat/bearer_token credential is the raw token, not a JSON
// document (unlike GoogleOAuthProber's oauth JSON blob), so Probe treats
// the whole decrypted secret as the token string. It makes a real network
// call; like GoogleOAuthProber it is only ever registered when
// LiveProbesEnabled() is true, and every test sets CREDROUTE_NO_NETWORK=1.
type GitHubPATProber struct {
	Endpoint   string
	HTTPClient *http.Client
}

// NewGitHubPATProber returns a prober configured against the real GitHub
// endpoint with a bounded timeout.
func NewGitHubPATProber() *GitHubPATProber {
	return &GitHubPATProber{
		Endpoint:   defaultGitHubUserEndpoint,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Method implements Prober.
func (p *GitHubPATProber) Method() string { return "http_whoami" }

func (p *GitHubPATProber) endpoint() string {
	if p.Endpoint != "" {
		return p.Endpoint
	}
	return defaultGitHubUserEndpoint
}

func (p *GitHubPATProber) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Probe implements Prober by calling GitHub's /user endpoint. platform
// must be "github"; any other value is a caller error, returned as err.
// Scopes are read from the X-OAuth-Scopes response header (spec 6.1
// scopes_header) when GitHub reports it; a PAT with no visible scope
// header (e.g. a fine-grained PAT) returns a nil scope list rather than an
// error, since scope observation is optional per spec 5.3/6.2.
func (p *GitHubPATProber) Probe(ctx context.Context, secret *vault.Secret, platform string) (string, []string, error) {
	if platform != "github" {
		return "", nil, fmt.Errorf("verify: github pat prober does not support platform %q", platform)
	}
	if secret == nil {
		return "", nil, errors.New("verify: github pat prober got a nil secret")
	}

	var token string
	err := secret.WithBytes(func(b []byte) error {
		token = strings.TrimSpace(string(b))
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("verify: read github pat secret: %w", err)
	}
	if token == "" {
		return "", nil, errors.New("verify: github credential secret is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint(), nil)
	if err != nil {
		return "", nil, fmt.Errorf("verify: build github /user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.client().Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("verify: github /user request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("verify: github /user returned status %d", resp.StatusCode)
	}

	var body struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", nil, fmt.Errorf("verify: parse github /user response: %w", err)
	}
	if body.Login == "" {
		return "", nil, errors.New("verify: github /user response has no login field")
	}

	var scopes []string
	if raw := resp.Header.Get("X-OAuth-Scopes"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				scopes = append(scopes, s)
			}
		}
	}
	return body.Login, scopes, nil
}

// Registry picks the best available prober for a platform, falling back to
// the generic fingerprint prober when nothing more specific is registered
// (spec 5.3: "Registry that picks the best prober for a platform, falling
// back to the generic one").
type Registry struct {
	byPlatform map[string]Prober
	fallback   Prober
}

// LiveProbesEnabled reports whether live, network-touching identity
// probers should be registered. F2: `verify:required` runs the live probe
// by default whenever a platform has one, so this defaults to true.
// Set CREDROUTE_NO_NETWORK=1 to force every platform back to the generic
// fingerprint prober; this is the switch every test that could otherwise
// reach a real network endpoint sets via t.Setenv, replacing the old
// opt-in CREDROUTE_LIVE_PROBE=1 gate.
func LiveProbesEnabled() bool {
	return os.Getenv("CREDROUTE_NO_NETWORK") != "1"
}

// NewRegistry builds a registry. When enableLiveProbes is false, no
// live-network prober is registered for any platform and every platform
// falls back to the fingerprint prober. Callers in cmd/credroute pass
// LiveProbesEnabled(); tests that want a specific prober without touching
// the real network register one directly via Register, or construct a
// prober pointed at an httptest server.
func NewRegistry(enableLiveProbes bool) *Registry {
	r := &Registry{
		byPlatform: map[string]Prober{},
		fallback:   FingerprintProber{},
	}
	if enableLiveProbes {
		r.byPlatform["google"] = NewGoogleOAuthProber()
		r.byPlatform["github"] = NewGitHubPATProber()
	}
	return r
}

// Register installs prober as the best prober for platform, overriding any
// default. Exposed mainly for tests that need to inject a prober pointed
// at a local httptest server without going through the live-probe gate.
func (r *Registry) Register(platform string, prober Prober) {
	if r.byPlatform == nil {
		r.byPlatform = map[string]Prober{}
	}
	r.byPlatform[platform] = prober
}

// Best returns the registered prober for platform, or the generic
// fingerprint prober if none is registered.
func (r *Registry) Best(platform string) Prober {
	if p, ok := r.byPlatform[platform]; ok {
		return p
	}
	return r.fallback
}
