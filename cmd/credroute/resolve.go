// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/verify"
)

// resolveResponse is the JSON contract for `credroute resolve`. It never
// carries a secret: only a vault handle (a pointer the vault backend can
// later dereference).
type resolveResponse struct {
	Version        int              `json:"version"`
	Status         string           `json:"status"` // ok | no_match | mismatch | config_error
	Request        requestInfo      `json:"request"`
	Identity       string           `json:"identity,omitempty"`
	IdentityLabel  string           `json:"identity_label,omitempty"`
	AccessLevel    string           `json:"access_level,omitempty"`
	CredentialType string           `json:"credential_type,omitempty"`
	VaultHandle    string           `json:"vault_handle,omitempty"`
	Slot           string           `json:"slot,omitempty"`
	Verification   verificationInfo `json:"verification"`
	MatchedRule    *matchedRuleInfo `json:"matched_rule,omitempty"`
	Detail         string           `json:"detail,omitempty"`
}

// verificationInfo is the spec 4.2 "verification" object: what resolve
// found when it consulted the attestation sidecar for this credential
// (milestone 2). resolve only ever reads a sidecar; it never probes or
// decrypts, so a live probe (spec 5.3) is always a separate `credroute
// verify` call.
type verificationInfo struct {
	Status            string `json:"status"` // verified | stale | mismatch | unverified
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
	if err := fs.Parse(args); err != nil {
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

	queryDir, err := resolveQueryDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute resolve:", err)
		return 1
	}

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		return emitResolveOutcome(g, resolveResponse{
			Version: 1, Status: "config_error",
			Request:      requestInfo{Platform: *platform, Dir: queryDir, Task: *task},
			Verification: verificationInfo{Status: verify.ResolveUnverified},
			Detail:       err.Error(),
		}, 5)
	}

	result, err := rules.Evaluate(cfg, rules.Query{Dir: queryDir, Platform: *platform, Task: *task})
	if err != nil {
		return emitResolveOutcome(g, resolveResponse{
			Version: 1, Status: "config_error",
			Request:      requestInfo{Platform: *platform, Dir: queryDir, Task: *task},
			Verification: verificationInfo{Status: verify.ResolveUnverified},
			Detail:       err.Error(),
		}, 5)
	}

	if result.Resolution == nil {
		return emitResolveOutcome(g, resolveResponse{
			Version: 1, Status: "no_match",
			Request:      requestInfo{Platform: *platform, Dir: queryDir, Task: *task},
			Verification: verificationInfo{Status: verify.ResolveUnverified},
			Detail:       "no rule matched this context; refusing (fail closed)",
		}, 2)
	}

	res := result.Resolution
	resp := resolveResponse{
		Version:       1,
		Status:        "ok",
		Request:       requestInfo{Platform: *platform, Dir: queryDir, Task: *task},
		Identity:      res.Identity,
		IdentityLabel: res.IdentityLabel,
		AccessLevel:   res.Access,
		Verification:  verificationInfo{Status: verify.ResolveUnverified},
		MatchedRule:   &matchedRuleInfo{ID: res.Rule.ID, Index: res.Index},
	}
	if !res.CredentialFound {
		resp.Status = "config_error"
		resp.Detail = fmt.Sprintf("identity %q has no %q credential for platform %q", res.Identity, res.Access, *platform)
		return emitResolveOutcome(g, resp, 5)
	}

	resp.CredentialType = res.Credential.Type
	resp.VaultHandle = res.Credential.Vault
	slot := ""
	if expanded, expErr := rules.ExpandHome(res.Credential.Slot); expErr == nil {
		slot = expanded
	} else {
		slot = res.Credential.Slot
	}
	resp.Slot = slot

	mode := verify.EffectiveVerifyMode(*verifyFlag, res.Rule.Use.Verify, cfg.Defaults.Verify)

	var maxAge time.Duration
	if cfg.Defaults.SidecarMaxAge != "" {
		if parsed, parseErr := time.ParseDuration(cfg.Defaults.SidecarMaxAge); parseErr == nil {
			maxAge = parsed
		}
	}

	rec, readErr := attest.Read(slot, res.Credential.Vault)
	status := verify.ClassifyForResolve(rec, readErr, maxAge, time.Now().UTC())
	resp.Verification.Status = status
	if rec != nil {
		resp.Verification.ObservedIdentity = rec.ObservedIdentity
		resp.Verification.Method = rec.Method
		resp.Verification.CheckedAt = rec.CheckedAt.Format(time.RFC3339)
		resp.Verification.SidecarAgeSeconds = int64(time.Since(rec.CheckedAt).Seconds())
	}

	if verify.ShouldRefuse(mode, status) {
		resp.Status = "mismatch"
		resp.Detail = fmt.Sprintf("verification status %q under verify=%s; refusing (run `credroute verify --platform %s` to re-attest)", status, mode, *platform)
		return emitResolveOutcome(g, resp, 3)
	}

	return emitResolveOutcome(g, resp, 0)
}

func emitResolveOutcome(g *globalFlags, resp resolveResponse, exitCode int) int {
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
