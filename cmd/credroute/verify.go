// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 5) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/scope"
	"github.com/hasandenizuk/credroute/internal/vault"
	"github.com/hasandenizuk/credroute/internal/verify"
)

// verifyResponse is the JSON contract for `credroute verify`. Like
// resolve, it never carries a secret.
type verifyResponse struct {
	Version          int    `json:"version"`
	Status           string `json:"status"` // verified | unconfirmed | mismatch | unreadable | error
	Platform         string `json:"platform,omitempty"`
	AccessLevel      string `json:"access_level,omitempty"`
	ExpectedIdentity string `json:"expected_identity,omitempty"`
	// IdentityConfirmed (F2) is true only when a prober actually named
	// the account and it matched; Status "verified" is reserved for
	// exactly that case, so this is mostly a convenience mirror of it,
	// but is always present so a caller never has to special-case status
	// strings to answer "was identity itself checked".
	IdentityConfirmed bool     `json:"identity_confirmed"`
	ObservedIdentity  string   `json:"observed_identity,omitempty"`
	Method            string   `json:"method,omitempty"`
	Fingerprint       string   `json:"fingerprint,omitempty"`
	ObservedScopes    []string `json:"observed_scopes,omitempty"`
	// ScopeWarning (F4) flags scopes observed on the credential that are
	// not in the access level's expected scope set (over-privilege): a
	// warning, not a refusal - `resolve`/`exec` still enforce identity
	// verification; this is advisory extra information surfaced here and
	// in `doctor`.
	ScopeWarning string `json:"scope_warning,omitempty"`
	Slot         string `json:"slot,omitempty"`
	VaultHandle  string `json:"vault_handle,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	slotFlag := fs.String("slot", "", "verify the credential whose configured slot matches this path")
	platform := fs.String("platform", "", "verify the credential resolve would pick for this platform")
	task := fs.String("task", "", "task tag, used with --platform")
	dir := fs.String("dir", "", "directory to resolve for, used with --platform (default: cwd)")
	afterLogin := fs.Bool("after-login", false, "this run follows a fresh login into the slot (spec 5.3 login guard)")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}

	if *slotFlag == "" && *platform == "" {
		fmt.Fprintln(os.Stderr, "credroute verify: one of --slot or --platform is required")
		return 1
	}
	if *afterLogin && *slotFlag == "" && *platform == "" {
		fmt.Fprintln(os.Stderr, "credroute verify: --after-login requires --slot or --platform")
		return 1
	}

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		return emitVerifyOutcome(g, verifyResponse{Version: 1, Status: "error", Detail: err.Error()}, 5)
	}

	var (
		identityID   string
		platformName string
		access       string
		cred         config.Credential
	)

	if *slotFlag != "" {
		expandedSlot, expErr := rules.ExpandHome(*slotFlag)
		if expErr != nil {
			return emitVerifyOutcome(g, verifyResponse{Version: 1, Status: "error", Detail: expErr.Error()}, 1)
		}
		id, plat, acc, c, findErr := findCredentialBySlot(cfg, expandedSlot)
		if findErr != nil {
			return emitVerifyOutcome(g, verifyResponse{
				Version: 1, Status: "error", Slot: expandedSlot,
				Detail: findErr.Error(),
			}, 5)
		}
		identityID, platformName, access, cred = id, plat, acc, c
	} else {
		queryDir, qErr := resolveQueryDir(*dir)
		if qErr != nil {
			fmt.Fprintln(os.Stderr, "credroute verify:", qErr)
			return 1
		}
		result, evalErr := rules.Evaluate(cfg, rules.Query{Dir: queryDir, Platform: *platform, Task: *task})
		if evalErr != nil {
			return emitVerifyOutcome(g, verifyResponse{Version: 1, Status: "error", Platform: *platform, Detail: evalErr.Error()}, 5)
		}
		if result.Resolution == nil {
			return emitVerifyOutcome(g, verifyResponse{
				Version: 1, Status: "error", Platform: *platform,
				Detail: "no rule matched this context; nothing to verify",
			}, 2)
		}
		res := result.Resolution
		if !res.CredentialFound {
			return emitVerifyOutcome(g, verifyResponse{
				Version: 1, Status: "error", Platform: *platform,
				Detail: fmt.Sprintf("identity %q has no %q credential for platform %q", res.Identity, res.Access, *platform),
			}, 5)
		}
		identityID, platformName, access = res.Identity, *platform, res.Access
		cred = res.Credential
	}

	backend, err := buildVaultBackend(cfg)
	if err != nil {
		return emitVerifyOutcome(g, verifyResponse{Version: 1, Status: "error", Platform: platformName, AccessLevel: access, Detail: err.Error()}, 4)
	}

	ctx := context.Background()
	secret, err := backend.Retrieve(ctx, vault.Handle(cred.Vault))
	if err != nil {
		return emitVerifyOutcome(g, verifyResponse{Version: 1, Status: "error", Platform: platformName, AccessLevel: access, VaultHandle: cred.Vault, Detail: err.Error()}, 4)
	}
	defer secret.Zero()

	slot := expandSlot(cred.Slot)

	// F2: the live probe now runs by default whenever a prober exists for
	// the platform; CREDROUTE_NO_NETWORK=1 is the switch that disables it
	// (used by every test that could otherwise reach a real endpoint).
	registry := verify.NewRegistry(verify.LiveProbesEnabled())

	req := verify.Request{
		Platform:         platformName,
		CredentialType:   cred.Type,
		ExpectedIdentity: identityID,
		VaultHandle:      cred.Vault,
		Slot:             slot,
		Secret:           secret,
		CheckedBy:        attest.DefaultCheckedBy(buildVersion),
	}

	outcome, runErr := verify.Run(ctx, req, registry)
	if runErr != nil {
		return emitVerifyOutcome(g, verifyResponse{
			Version: 1, Status: "error", Platform: platformName, AccessLevel: access, ExpectedIdentity: identityID,
			Slot: slot, VaultHandle: cred.Vault, Detail: runErr.Error(),
		}, 1)
	}

	resp := verifyResponse{
		Version:           1,
		Status:            string(outcome.Status),
		Platform:          platformName,
		AccessLevel:       access,
		ExpectedIdentity:  identityID,
		IdentityConfirmed: outcome.IdentityConfirmed,
		ObservedIdentity:  outcome.ObservedIdentity,
		Method:            outcome.Method,
		Fingerprint:       outcome.Fingerprint,
		ObservedScopes:    outcome.ObservedScopes,
		Slot:              slot,
		VaultHandle:       cred.Vault,
		Detail:            outcome.Detail,
	}
	// allow-claude-code: see file header.
	resp.ScopeWarning = scopeOverPrivilegeWarning(platformName, access, *task, outcome.ObservedScopes)

	exitCode := 1
	switch outcome.Status {
	case attest.StatusVerified, attest.StatusUnconfirmed:
		exitCode = 0
	case attest.StatusMismatch:
		exitCode = 3
	case attest.StatusUnreadable:
		exitCode = 4
	}
	return emitVerifyOutcome(g, resp, exitCode)
}

// scopeOverPrivilegeWarning is F4: when the prober reported observed
// scopes, compare them against the access level's expected scope set (via
// the same scope profile registry resolve/exec use) and describe any
// scope present on the credential but not implied by the requested access
// level. This is advisory only (spec 6.2 calls a genuine "scope_mismatch"
// a refusal under verify:required for the routing decision itself, which
// is out of scope for this surface); here it is purely a warning surfaced
// in `verify`/`doctor` output so an operator can see over-privilege
// without resolve/exec blocking on it.
func scopeOverPrivilegeWarning(platform, access, task string, observedScopes []string) string {
	if len(observedScopes) == 0 {
		return ""
	}
	reg, err := scope.LoadDefaultRegistry()
	if err != nil {
		return ""
	}
	result := reg.Resolve(platform, access, task)
	if result.Enforcement != "scope-derived" {
		return ""
	}
	expected := map[string]bool{}
	for _, s := range result.Scopes {
		expected[s] = true
	}
	var extra []string
	for _, s := range observedScopes {
		if !expected[s] {
			extra = append(extra, s)
		}
	}
	if len(extra) == 0 {
		return ""
	}
	sort.Strings(extra)
	return fmt.Sprintf("credential carries %d scope(s) beyond what access=%s implies: %s", len(extra), access, strings.Join(extra, ", "))
}

func emitVerifyOutcome(g *globalFlags, resp verifyResponse, exitCode int) int {
	logVerifyAudit(resp, exitCode)

	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return exitCode
	}

	if resp.Status == "error" {
		fmt.Fprintf(os.Stderr, "credroute verify: %s\n", resp.Detail)
		return exitCode
	}

	if g.quiet {
		return exitCode
	}
	fmt.Printf("status            %s\n", resp.Status)
	if resp.Platform != "" {
		fmt.Printf("platform          %s\n", resp.Platform)
	}
	fmt.Printf("expected_identity %s\n", resp.ExpectedIdentity)
	if resp.ObservedIdentity != "" {
		fmt.Printf("observed_identity %s\n", resp.ObservedIdentity)
	}
	fmt.Printf("identity_confirmed %v\n", resp.IdentityConfirmed)
	fmt.Printf("method            %s\n", resp.Method)
	if resp.Slot != "" {
		fmt.Printf("slot              %s\n", resp.Slot)
	}
	fmt.Printf("vault_handle      %s\n", resp.VaultHandle)
	if resp.ScopeWarning != "" {
		fmt.Printf("scope_warning     %s\n", resp.ScopeWarning)
	}
	if resp.Detail != "" {
		fmt.Printf("detail            %s\n", resp.Detail)
	}
	return exitCode
}

// logVerifyAudit appends one audit entry (spec 9.3) for every verify
// call, success or refusal alike. Best-effort: a failure to write the
// audit log never changes verify's own exit code.
func logVerifyAudit(resp verifyResponse, exitCode int) {
	e := audit.Entry{
		Op:           "verify",
		Platform:     resp.Platform,
		Identity:     resp.ExpectedIdentity,
		Access:       resp.AccessLevel,
		Verification: resp.Status,
		Exit:         exitCode,
		Decision:     decisionFor(exitCode),
		Caller:       auditCaller,
	}
	_ = audit.Append(e)
}
