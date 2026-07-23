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

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/vault"
	"github.com/hasandenizuk/credroute/internal/verify"
)

// verifyResponse is the JSON contract for `credroute verify`. Like
// resolve, it never carries a secret.
type verifyResponse struct {
	Version          int      `json:"version"`
	Status           string   `json:"status"` // verified | mismatch | unreadable | error
	Platform         string   `json:"platform,omitempty"`
	ExpectedIdentity string   `json:"expected_identity,omitempty"`
	ObservedIdentity string   `json:"observed_identity,omitempty"`
	Method           string   `json:"method,omitempty"`
	Fingerprint      string   `json:"fingerprint,omitempty"`
	ObservedScopes   []string `json:"observed_scopes,omitempty"`
	Slot             string   `json:"slot,omitempty"`
	VaultHandle      string   `json:"vault_handle,omitempty"`
	Detail           string   `json:"detail,omitempty"`
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
	if err := fs.Parse(args); err != nil {
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
		id, plat, acc, c, found := findCredentialBySlot(cfg, expandedSlot)
		if !found {
			return emitVerifyOutcome(g, verifyResponse{
				Version: 1, Status: "error", Slot: expandedSlot,
				Detail: fmt.Sprintf("no credential in config has slot %q", expandedSlot),
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
	_ = access // access level is not itself part of the identity check; kept for future scope-derived checks (milestone 3)

	backend, err := buildVaultBackend(cfg)
	if err != nil {
		return emitVerifyOutcome(g, verifyResponse{Version: 1, Status: "error", Detail: err.Error()}, 4)
	}

	ctx := context.Background()
	secret, err := backend.Retrieve(ctx, vault.Handle(cred.Vault))
	if err != nil {
		return emitVerifyOutcome(g, verifyResponse{Version: 1, Status: "error", VaultHandle: cred.Vault, Detail: err.Error()}, 4)
	}
	defer secret.Zero()

	slot := ""
	if cred.Slot != "" {
		if expanded, expErr := rules.ExpandHome(cred.Slot); expErr == nil {
			slot = expanded
		} else {
			slot = cred.Slot
		}
	}

	// The Google OAuth prober makes a real network call. It is only ever
	// registered when the operator explicitly opts in; every other
	// platform (and every `go test` run, which never sets this) uses the
	// generic fingerprint prober.
	enableLive := os.Getenv("CREDROUTE_LIVE_PROBE") == "1"
	registry := verify.NewRegistry(enableLive)

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
			Version: 1, Status: "error", Platform: platformName, ExpectedIdentity: identityID,
			Slot: slot, VaultHandle: cred.Vault, Detail: runErr.Error(),
		}, 1)
	}

	resp := verifyResponse{
		Version:          1,
		Status:           string(outcome.Status),
		Platform:         platformName,
		ExpectedIdentity: identityID,
		ObservedIdentity: outcome.ObservedIdentity,
		Method:           outcome.Method,
		Fingerprint:      outcome.Fingerprint,
		ObservedScopes:   outcome.ObservedScopes,
		Slot:             slot,
		VaultHandle:      cred.Vault,
		Detail:           outcome.Detail,
	}

	exitCode := 1
	switch outcome.Status {
	case attest.StatusVerified:
		exitCode = 0
	case attest.StatusMismatch:
		exitCode = 3
	case attest.StatusUnreadable:
		exitCode = 4
	}
	return emitVerifyOutcome(g, resp, exitCode)
}

// findCredentialBySlot searches every identity/platform/credential in cfg
// for one whose expanded slot matches expandedSlot. Used by
// `credroute verify --slot`, which (per spec 5.3's login-guard use case)
// verifies a specific slot right after a login, without needing a
// dir/platform/task context for the rule engine.
func findCredentialBySlot(cfg *config.Config, expandedSlot string) (identityID, platform, access string, cred config.Credential, found bool) {
	for id, identity := range cfg.Identities {
		for platName, plat := range identity.Platforms {
			for acc, c := range plat.Credentials {
				if c.Slot == "" {
					continue
				}
				candidate, err := rules.ExpandHome(c.Slot)
				if err != nil {
					continue
				}
				if candidate == expandedSlot {
					return id, platName, acc, c, true
				}
			}
		}
	}
	return "", "", "", config.Credential{}, false
}

func emitVerifyOutcome(g *globalFlags, resp verifyResponse, exitCode int) int {
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
	fmt.Printf("method            %s\n", resp.Method)
	if resp.Slot != "" {
		fmt.Printf("slot              %s\n", resp.Slot)
	}
	fmt.Printf("vault_handle      %s\n", resp.VaultHandle)
	if resp.Detail != "" {
		fmt.Printf("detail            %s\n", resp.Detail)
	}
	return exitCode
}
