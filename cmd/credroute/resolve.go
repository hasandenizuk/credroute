// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/scope"
	"github.com/hasandenizuk/credroute/internal/verify"
)

// resolveResponse is the JSON contract for `credroute resolve`. It never
// carries a secret: only a vault handle (a pointer the vault backend can
// later dereference).
type resolveResponse struct {
	Version       int         `json:"version"`
	Status        string      `json:"status"` // ok | no_match | mismatch | config_error
	Request       requestInfo `json:"request"`
	Identity      string      `json:"identity,omitempty"`
	IdentityLabel string      `json:"identity_label,omitempty"`
	AccessLevel   string      `json:"access_level,omitempty"`
	// Client is the client name (match.client) the matched rule named, if
	// any (F17: feeds `credroute audit --client`).
	Client         string           `json:"client,omitempty"`
	Scopes         []string         `json:"scopes"`
	CredentialType string           `json:"credential_type,omitempty"`
	VaultHandle    string           `json:"vault_handle,omitempty"`
	Slot           string           `json:"slot,omitempty"`
	Verification   verificationInfo `json:"verification"`
	MatchedRule    *matchedRuleInfo `json:"matched_rule,omitempty"`
	// Enforcement reports whether Scopes is scope-derived (a scope
	// profile exists for this platform, spec D7/D10) or advisory
	// (generic passthrough, spec 6.3: no scope profile, nothing
	// over-claimed).
	Enforcement string `json:"enforcement,omitempty"`
	AuditID     string `json:"audit_id,omitempty"`
	StateDir    string `json:"state_dir,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// verificationInfo is the spec 4.2 "verification" object: what resolve
// found when it consulted the attestation sidecar for this credential
// (milestone 2). resolve only ever reads a sidecar; it never probes or
// decrypts, so a live probe (spec 5.3) is always a separate `credroute
// verify` call.
type verificationInfo struct {
	Status string `json:"status"` // verified | unconfirmed | stale | mismatch | unverified
	// IdentityConfirmed (F2) is honest about whether a prober actually
	// named and matched the account, as opposed to Status "verified"
	// meaning nothing more than "the sidecar's bytes-fingerprint hasn't
	// changed". Only ever true when the sidecar was written by a probe
	// that confirmed the identity.
	IdentityConfirmed bool   `json:"identity_confirmed"`
	ObservedIdentity  string `json:"observed_identity,omitempty"`
	Method            string `json:"method,omitempty"`
	CheckedAt         string `json:"checked_at,omitempty"`
	SidecarAgeSeconds int64  `json:"sidecar_age_seconds,omitempty"`
}

type requestInfo struct {
	Platform string `json:"platform"`
	Dir      string `json:"dir"`
	Task     string `json:"task,omitempty"`
}

type matchedRuleInfo struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
}

func cmdResolve(args []string) int {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	platform := fs.String("platform", "", "platform to resolve (required)")
	task := fs.String("task", "", "task tag")
	dir := fs.String("dir", "", "directory to resolve for (default: cwd)")
	verifyFlag := fs.String("verify", "", "override verify mode for this call: required|advisory|off (tighten only, cannot loosen config)")
	access := fs.String("access", "", "request an access level (read-only|read-write); refuses if the matched rule resolves to a different level")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if *platform == "" {
		fmt.Fprintln(os.Stderr, "credroute resolve: --platform is required")
		return 1
	}
	if *verifyFlag != "" && *verifyFlag != "required" && *verifyFlag != "advisory" && *verifyFlag != "off" {
		fmt.Fprintf(os.Stderr, "credroute resolve: --verify must be required, advisory, or off (got %q)\n", *verifyFlag)
		return 1
	}
	if *access != "" && *access != "read-only" && *access != "read-write" {
		fmt.Fprintf(os.Stderr, "credroute resolve: --access must be read-only or read-write (got %q)\n", *access)
		return 1
	}

	resp, exitCode := doResolve(g.configPath, *platform, *task, *dir, *verifyFlag, *access)
	return emitResolveOutcome(g, resp, exitCode)
}

// doResolve is cmdResolve's pure decision logic, separated out so other
// callers (the `credroute hook claude-code` PreToolUse decision, F6) can
// reuse exactly the same resolve+verify path without going through flags,
// stdout, or process exit.
func doResolve(configPath, platform, task, dirFlag, verifyFlag, accessFlag string) (resolveResponse, int) {
	auditID := audit.NewID()

	queryDir, err := resolveQueryDir(dirFlag)
	if err != nil {
		return resolveResponse{
			Version: 1, Status: "config_error", AuditID: auditID,
			Request:      requestInfo{Platform: platform, Dir: dirFlag, Task: task},
			Verification: verificationInfo{Status: verify.ResolveUnverified},
			Detail:       err.Error(),
		}, 1
	}

	cfg, err := loadAndValidate(configPath)
	if err != nil {
		return resolveResponse{
			Version: 1, Status: "config_error", AuditID: auditID,
			Request:      requestInfo{Platform: platform, Dir: queryDir, Task: task},
			Verification: verificationInfo{Status: verify.ResolveUnverified},
			Detail:       err.Error(),
		}, 5
	}

	result, err := rules.Evaluate(cfg, rules.Query{Dir: queryDir, Platform: platform, Task: task})
	if err != nil {
		return resolveResponse{
			Version: 1, Status: "config_error", AuditID: auditID,
			Request:      requestInfo{Platform: platform, Dir: queryDir, Task: task},
			Verification: verificationInfo{Status: verify.ResolveUnverified},
			Detail:       err.Error(),
		}, 5
	}

	if result.Resolution == nil {
		return resolveResponse{
			Version: 1, Status: "no_match", AuditID: auditID,
			Request:      requestInfo{Platform: platform, Dir: queryDir, Task: task},
			Verification: verificationInfo{Status: verify.ResolveUnverified},
			Detail:       "no rule matched this context; refusing (fail closed)",
		}, 2
	}

	res := result.Resolution
	resp := resolveResponse{
		Version:       1,
		Status:        "ok",
		AuditID:       auditID,
		StateDir:      stateDirForOutput(),
		Request:       requestInfo{Platform: platform, Dir: queryDir, Task: task},
		Identity:      res.Identity,
		IdentityLabel: res.IdentityLabel,
		AccessLevel:   res.Access,
		Client:        res.Rule.Match.Client,
		Verification:  verificationInfo{Status: verify.ResolveUnverified},
		MatchedRule:   &matchedRuleInfo{ID: res.Rule.ID, Index: res.Index},
	}

	// F12: the caller can request a minimum/expected access level; a
	// mismatch against what the rule actually resolves to is an error,
	// never a silent substitution.
	if accessFlag != "" && accessFlag != res.Access {
		resp.Status = "config_error"
		resp.Detail = fmt.Sprintf("requested access %q but matched rule %q resolves to access %q", accessFlag, res.Rule.ID, res.Access)
		return resp, 5
	}

	// Scope resolution (D7/D10, spec 6): scope-derived when a profile
	// exists for this platform, advisory generic passthrough otherwise.
	// This only needs platform+access, so it applies whether or not the
	// identity actually has a matching credential below.
	scopeReg, scopeErr := scope.LoadDefaultRegistry()
	if scopeErr == nil {
		scopeResult := scopeReg.Resolve(platform, res.Access, task)
		resp.Scopes = scopeResult.Scopes
		resp.Enforcement = scopeResult.Enforcement
	}

	if !res.CredentialFound {
		resp.Status = "config_error"
		resp.Detail = fmt.Sprintf("identity %q has no %q credential for platform %q", res.Identity, res.Access, platform)
		return resp, 5
	}

	resp.CredentialType = res.Credential.Type
	resp.VaultHandle = res.Credential.Vault
	slot := expandSlot(res.Credential.Slot)
	resp.Slot = slot

	pre := runVerifyPrecheck(verifyFlag, res.Rule.Use.Verify, cfg.Defaults.Verify, cfg.Defaults.SidecarMaxAge, slot, res.Credential.Vault, res.Identity, platform, res.Access)
	resp.Verification.Status = pre.Status
	if pre.Mode == "required" && scopeErr != nil {
		resp.Status = "config_error"
		resp.Detail = fmt.Sprintf("could not load scope profiles under verify=required: %v", scopeErr)
		return resp, 5
	}
	if rec, readErr := attest.Read(slot, res.Credential.Vault); readErr == nil && rec != nil {
		resp.Verification.IdentityConfirmed = rec.IdentityConfirmed
		resp.Verification.ObservedIdentity = rec.ObservedIdentity
		resp.Verification.Method = rec.Method
		resp.Verification.CheckedAt = rec.CheckedAt.Format(time.RFC3339)
		resp.Verification.SidecarAgeSeconds = int64(time.Since(rec.CheckedAt).Seconds())
		if detail := scopeExcessDetail(platform, res.Access, task, rec.ObservedScopes); detail != "" && pre.Mode == "required" {
			resp.Status = "mismatch"
			resp.Detail = detail
			return resp, 3
		}
	}

	if pre.Refuse() {
		resp.Status = "mismatch"
		resp.Detail = fmt.Sprintf("verification status %q under verify=%s; refusing (run `credroute verify --platform %s` to re-attest)", pre.Status, pre.Mode, platform)
		return resp, 3
	}

	return resp, 0
}

func emitResolveOutcome(g *globalFlags, resp resolveResponse, exitCode int) int {
	logResolveAudit(resp, exitCode)

	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return exitCode
	}

	if resp.Status != "ok" && resp.Status != "mismatch" {
		fmt.Fprintf(os.Stderr, "credroute resolve: %s: %s\n", resp.Status, resp.Detail)
		return exitCode
	}
	if resp.Status == "mismatch" {
		fmt.Fprintf(os.Stderr, "credroute resolve: refused: %s\n", resp.Detail)
		return exitCode
	}

	if g.quiet {
		return exitCode
	}
	fmt.Printf("identity        %s\n", resp.Identity)
	if resp.IdentityLabel != "" {
		fmt.Printf("label           %s\n", resp.IdentityLabel)
	}
	fmt.Printf("access_level    %s\n", resp.AccessLevel)
	if len(resp.Scopes) > 0 {
		fmt.Printf("scopes          %v\n", resp.Scopes)
	}
	if resp.Enforcement != "" {
		fmt.Printf("enforcement     %s\n", resp.Enforcement)
	}
	if resp.StateDir != "" {
		fmt.Printf("state_dir       %s\n", resp.StateDir)
	}
	fmt.Printf("credential_type %s\n", resp.CredentialType)
	fmt.Printf("vault_handle    %s\n", resp.VaultHandle)
	if resp.Slot != "" {
		fmt.Printf("slot            %s\n", resp.Slot)
	}
	fmt.Printf("verification    %s\n", resp.Verification.Status)
	if resp.MatchedRule != nil {
		fmt.Printf("matched_rule    %s (index %d)\n", resp.MatchedRule.ID, resp.MatchedRule.Index)
	}
	return exitCode
}

// logResolveAudit appends one audit entry (spec 9.3) for every resolve
// call, success or refusal alike. Best-effort: a failure to write the
// audit log never changes resolve's own exit code.
func logResolveAudit(resp resolveResponse, exitCode int) {
	e := audit.Entry{
		ID:           resp.AuditID,
		Op:           "resolve",
		Dir:          resp.Request.Dir,
		Platform:     resp.Request.Platform,
		Task:         resp.Request.Task,
		Client:       resp.Client,
		Identity:     resp.Identity,
		Access:       resp.AccessLevel,
		Verification: resp.Verification.Status,
		Exit:         exitCode,
		Decision:     decisionFor(exitCode),
		Caller:       auditCaller,
	}
	if resp.MatchedRule != nil {
		e.Rule = resp.MatchedRule.ID
	}
	_ = appendAuditOrWarn(e)
}
