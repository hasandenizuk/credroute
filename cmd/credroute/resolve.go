// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/hasandenizuk/credroute/internal/rules"
)

// resolveResponse is the JSON contract for `credroute resolve`. It never
// carries a secret: only a vault handle (a pointer the vault backend can
// later dereference).
type resolveResponse struct {
	Version            int              `json:"version"`
	Status             string           `json:"status"` // ok | no_match | config_error
	Request            requestInfo      `json:"request"`
	Identity           string           `json:"identity,omitempty"`
	IdentityLabel      string           `json:"identity_label,omitempty"`
	AccessLevel        string           `json:"access_level,omitempty"`
	CredentialType     string           `json:"credential_type,omitempty"`
	VaultHandle        string           `json:"vault_handle,omitempty"`
	Slot               string           `json:"slot,omitempty"`
	VerificationStatus string           `json:"verification_status"`
	MatchedRule        *matchedRuleInfo `json:"matched_rule,omitempty"`
	Detail             string           `json:"detail,omitempty"`
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
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *platform == "" {
		fmt.Fprintln(os.Stderr, "credroute resolve: --platform is required")
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
			Request:            requestInfo{Platform: *platform, Dir: queryDir, Task: *task},
			VerificationStatus: "unverified",
			Detail:             err.Error(),
		}, 5)
	}

	result, err := rules.Evaluate(cfg, rules.Query{Dir: queryDir, Platform: *platform, Task: *task})
	if err != nil {
		return emitResolveOutcome(g, resolveResponse{
			Version: 1, Status: "config_error",
			Request:            requestInfo{Platform: *platform, Dir: queryDir, Task: *task},
			VerificationStatus: "unverified",
			Detail:             err.Error(),
		}, 5)
	}

	if result.Resolution == nil {
		return emitResolveOutcome(g, resolveResponse{
			Version: 1, Status: "no_match",
			Request:            requestInfo{Platform: *platform, Dir: queryDir, Task: *task},
			VerificationStatus: "unverified",
			Detail:             "no rule matched this context; refusing (fail closed)",
		}, 2)
	}

	res := result.Resolution
	resp := resolveResponse{
		Version:            1,
		Status:             "ok",
		Request:            requestInfo{Platform: *platform, Dir: queryDir, Task: *task},
		Identity:           res.Identity,
		IdentityLabel:      res.IdentityLabel,
		AccessLevel:        res.Access,
		VerificationStatus: "unverified",
		MatchedRule:        &matchedRuleInfo{ID: res.Rule.ID, Index: res.Index},
	}
	exitCode := 0
	if res.CredentialFound {
		resp.CredentialType = res.Credential.Type
		resp.VaultHandle = res.Credential.Vault
		if slot, expErr := rules.ExpandHome(res.Credential.Slot); expErr == nil {
			resp.Slot = slot
		} else {
			resp.Slot = res.Credential.Slot
		}
	} else {
		resp.Status = "config_error"
		resp.Detail = fmt.Sprintf("identity %q has no %q credential for platform %q", res.Identity, res.Access, *platform)
		exitCode = 5
	}

	return emitResolveOutcome(g, resp, exitCode)
}

func emitResolveOutcome(g *globalFlags, resp resolveResponse, exitCode int) int {
	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return exitCode
	}

	if resp.Status != "ok" {
		fmt.Fprintf(os.Stderr, "credroute resolve: %s: %s\n", resp.Status, resp.Detail)
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
	fmt.Printf("verification    %s\n", resp.VerificationStatus)
	if resp.MatchedRule != nil {
		fmt.Printf("matched_rule    %s (index %d)\n", resp.MatchedRule.ID, resp.MatchedRule.Index)
	}
	return exitCode
}
