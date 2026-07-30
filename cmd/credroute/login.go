// allow-claude-code: implements `credroute login`, the slot-write guard
// delegated in the build brief. The command is headless: every gate is a
// deterministic equality check and no path prompts for TTY input.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/audit"
	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/rules"
	"github.com/hasandenizuk/credroute/internal/scope"
	"github.com/hasandenizuk/credroute/internal/slotsnap"
	"github.com/hasandenizuk/credroute/internal/vault"
	"github.com/hasandenizuk/credroute/internal/verify"
)

type loginResponse struct {
	Version          int      `json:"version"`
	Status           string   `json:"status"`
	Platform         string   `json:"platform,omitempty"`
	Dir              string   `json:"dir,omitempty"`
	Task             string   `json:"task,omitempty"`
	ExpectedIdentity string   `json:"expected_identity,omitempty"`
	ObservedIdentity string   `json:"observed_identity,omitempty"`
	AccessLevel      string   `json:"access_level,omitempty"`
	Slot             string   `json:"slot,omitempty"`
	SlotEnv          string   `json:"slot_env,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	MatchedRule      string   `json:"matched_rule,omitempty"`
	Verification     string   `json:"verification,omitempty"`
	ForceOverrides   []string `json:"force_overrides,omitempty"`
	RolledBack       bool     `json:"rolled_back,omitempty"`
	Detail           string   `json:"detail,omitempty"`
}

func cmdLogin(args []string) (exitCode int) {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	g := &globalFlags{}
	addGlobalFlags(fs, g)
	platform := fs.String("platform", "", "platform to log in to")
	task := fs.String("task", "", "task tag")
	dir := fs.String("dir", "", "directory to resolve for (default: cwd)")
	expect := fs.String("expect", "", "identity expected by the operator; refuses if routing resolves a different identity")
	force := fs.Bool("force", false, "audited override for login refusals that require operator acceptance")
	if err := fs.Parse(reorderArgsForFlagParse(fs, args)); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "credroute login: command arguments are not accepted; login.helper from the scope profile is used")
		return 1
	}
	if *platform == "" {
		fmt.Fprintln(os.Stderr, "credroute login: --platform is required")
		return 1
	}

	queryDir, err := resolveQueryDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "credroute login:", err)
		return 1
	}
	resp := loginResponse{Version: 1, Status: "error", Platform: *platform, Dir: queryDir, Task: *task}
	entry := audit.Entry{ID: audit.NewID(), Op: "login", Dir: queryDir, Platform: *platform, Task: *task, Caller: auditCaller}
	defer func() {
		entry.Exit = exitCode
		entry.Decision = decisionFor(exitCode)
		if entry.Verification == "" {
			entry.Verification = resp.Verification
		}
		_ = appendAuditOrWarn(entry)
	}()

	cfg, err := loadAndValidate(g.configPath)
	if err != nil {
		resp.Detail = err.Error()
		return emitLoginOutcome(g, resp, 5)
	}
	result, err := rules.Evaluate(cfg, rules.Query{Dir: queryDir, Platform: *platform, Task: *task})
	if err != nil {
		resp.Detail = err.Error()
		return emitLoginOutcome(g, resp, 5)
	}
	if result.Resolution == nil {
		resp.Status = "no_match"
		resp.Detail = "no rule matched this context; refusing (fail closed)"
		return emitLoginOutcome(g, resp, 2)
	}
	res := result.Resolution
	entry.Identity = res.Identity
	entry.Access = res.Access
	entry.Rule = res.Rule.ID
	entry.Client = res.Rule.Match.Client
	resp.ExpectedIdentity = res.Identity
	resp.AccessLevel = res.Access
	resp.MatchedRule = res.Rule.ID
	if !res.CredentialFound {
		resp.Detail = fmt.Sprintf("identity %q has no %q credential for platform %q", res.Identity, res.Access, *platform)
		return emitLoginOutcome(g, resp, 5)
	}
	slot := expandSlot(res.Credential.Slot)
	resp.Slot = slot
	entry.Target = slot
	if slot == "" {
		resp.Detail = "resolved credential has no slot; login cannot guard an unknown write destination"
		return emitLoginOutcome(g, resp, 5)
	}
	if err := ensureLoginSlotUnambiguous(cfg, slot); err != nil {
		resp.Status = "refused"
		resp.Detail = err.Error()
		return emitLoginOutcome(g, resp, 5)
	}

	if *expect != "" && *expect != res.Identity {
		resp.Status = "refused"
		resp.Detail = fmt.Sprintf("expected identity %q but matched rule %q resolves to %q", *expect, res.Rule.ID, res.Identity)
		return emitLoginOutcome(g, resp, 3)
	}

	scopeReg, err := scope.LoadDefaultRegistry()
	if err != nil {
		resp.Detail = fmt.Sprintf("could not load scope profiles: %v", err)
		return emitLoginOutcome(g, resp, 5)
	}
	profile, ok := scopeReg.Get(*platform)
	if !ok {
		resp.Detail = fmt.Sprintf("platform %q has no scope profile; login helper and destination channel are unknown", *platform)
		return emitLoginOutcome(g, resp, 5)
	}
	scopeResult := scopeReg.Resolve(*platform, res.Access, *task)
	resp.Scopes = scopeResult.Scopes
	if profile.Login.Helper == "" {
		resp.Detail = fmt.Sprintf("platform %q profile has no login.helper", *platform)
		return emitLoginOutcome(g, resp, 5)
	}
	if profile.Login.SlotEnv != "" && !strings.Contains(profile.Login.Helper, "{slot}") {
		resp.Detail = fmt.Sprintf("platform %q profile login.helper must include {slot} when login.slot_env is declared", *platform)
		return emitLoginOutcome(g, resp, 5)
	}
	if info, statErr := os.Stat(slot); statErr == nil && info.IsDir() && !strings.Contains(profile.Login.Helper, "{slot}") {
		resp.Detail = "login.helper must include {slot} for a directory credential slot"
		return emitLoginOutcome(g, resp, 5)
	}
	verifyRegistry := verify.NewRegistry(verify.LiveProbesEnabled())
	forceUnverified := *force && !verifyRegistry.HasPlatformProber(*platform)
	var forceOverrides []string

	pre := runVerifyPrecheck("", res.Rule.Use.Verify, cfg.Defaults.Verify, cfg.Defaults.SidecarMaxAge, slot, res.Credential.Vault, res.Identity, *platform, res.Access)
	resp.Verification = pre.Status
	entry.Verification = pre.Status

	childEnv := os.Environ()
	if profile.Login.SlotEnv == "" {
		if pre.Mode == "on" && !*force {
			resp.Status = "refused"
			resp.Detail = "profile declares no slot_env destination channel; use --force to audit override of missing_slot_env"
			return emitLoginOutcome(g, resp, 3)
		}
		if pre.Mode == "on" && *force {
			if err := appendLoginBreakGlassAudit(entry, "force:missing_slot_env"); err != nil {
				resp.Detail = fmt.Sprintf("audit entry was not written for --force override missing_slot_env: %v", err)
				return emitLoginOutcome(g, resp, 5)
			}
			forceOverrides = append(forceOverrides, "missing_slot_env")
			resp.ForceOverrides = append([]string(nil), forceOverrides...)
		}
	} else {
		resp.SlotEnv = profile.Login.SlotEnv
		if explicit, found := os.LookupEnv(profile.Login.SlotEnv); found {
			expanded, expErr := rules.ExpandHome(explicit)
			if expErr != nil {
				resp.Status = "refused"
				resp.Detail = fmt.Sprintf("could not expand explicit %s: %v", profile.Login.SlotEnv, expErr)
				return emitLoginOutcome(g, resp, 3)
			}
			if expanded != slot {
				resp.Status = "refused"
				resp.Detail = fmt.Sprintf("destination conflict: resolved slot %q but explicit %s=%q", slot, profile.Login.SlotEnv, explicit)
				return emitLoginOutcome(g, resp, 3)
			}
		} else {
			childEnv = append(childEnv, profile.Login.SlotEnv+"="+slot)
		}
	}

	stateDir, err := attest.StateDir()
	if err != nil {
		resp.Detail = err.Error()
		return emitLoginOutcome(g, resp, 4)
	}
	lock, err := slotsnap.AcquireLock(stateDir, slot)
	if err != nil {
		resp.Status = "refused"
		if errors.Is(err, slotsnap.ErrLocked) {
			resp.Detail = "another login already holds this slot lock; refusing instead of queueing"
			return emitLoginOutcome(g, resp, 3)
		}
		resp.Detail = err.Error()
		return emitLoginOutcome(g, resp, 4)
	}
	defer lock.Close()

	var snap *slotsnap.Snapshot
	var prior *attest.Record
	if rec, readErr := attest.Read(slot, res.Credential.Vault); readErr == nil {
		prior = rec
	}
	snap, err = slotsnap.Take(stateDir, slot)
	if err != nil {
		resp.Detail = err.Error()
		return emitLoginOutcome(g, resp, 4)
	}

	if err := attest.Write(&attest.Record{
		Slot:             slot,
		VaultHandle:      res.Credential.Vault,
		ExpectedIdentity: res.Identity,
		Platform:         *platform,
		AccessLevel:      res.Access,
		Status:           attest.StatusUnreadable,
		Method:           "login_in_flight",
		CheckedAt:        time.Now().UTC(),
		CheckedBy:        attest.DefaultCheckedBy(buildVersion),
	}); err != nil {
		resp.Detail = fmt.Sprintf("mark login in-flight: %v", err)
		return emitLoginOutcome(g, resp, 4)
	}

	if !g.quiet {
		fmt.Fprintf(os.Stderr, "credroute login: target\n  platform  %s  identity  %s  access %s\n  slot      %s  rule %s\n", *platform, res.Identity, res.Access, slot, res.Rule.ID)
	}
	argv := loginHelperArgs(profile.Login.Helper, scopeResult.Scopes, slot)
	if len(argv) == 0 {
		resp.Detail = "login.helper expands to an empty command"
		return emitLoginOutcome(g, resp, 5)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = childEnv
	if err := cmd.Run(); err != nil {
		resp.Detail = fmt.Sprintf("login helper failed: %v", err)
		return settleLoginRestoreKeepRefused(g, resp, snap, slot, res.Credential.Vault, helperExitCode(err))
	}

	currentDigest, err := snap.CurrentDigest()
	if err != nil {
		resp.Detail = fmt.Sprintf("read guarded slot after login: %v", err)
		return settleLoginRestore(g, resp, entry, snap, prior, slot, res.Credential.Vault, 4)
	}
	if currentDigest == snap.InitialDigest() {
		resp.Status = "refused"
		resp.Detail = "the login helper wrote nothing to the guarded slot"
		return settleLoginRestore(g, resp, entry, snap, prior, slot, res.Credential.Vault, 3)
	}

	secret, err := readSlotSecret(slot, profile.Login.CredentialFile)
	if err != nil {
		resp.Detail = err.Error()
		return settleLoginRestore(g, resp, entry, snap, prior, slot, res.Credential.Vault, 4)
	}
	defer secret.Zero()

	outcome, verifyErr := verify.Run(context.Background(), verify.Request{
		Platform:         *platform,
		CredentialType:   res.Credential.Type,
		ExpectedIdentity: res.Identity,
		AccessLevel:      res.Access,
		VaultHandle:      res.Credential.Vault,
		Slot:             slot,
		Secret:           secret,
		CheckedBy:        attest.DefaultCheckedBy(buildVersion),
		AcceptBaseline:   forceUnverified,
	}, verifyRegistry)
	freshStatus := verify.ResolveStatusForAttest(outcome.Status)
	if freshStatus == "" {
		freshStatus = verify.ResolveUnverified
	}
	resp.Verification = freshStatus
	entry.Verification = freshStatus
	resp.ObservedIdentity = outcome.ObservedIdentity
	if verifyErr != nil {
		resp.Detail = fmt.Sprintf("verify after login: %v", verifyErr)
		return settleLoginRestore(g, resp, entry, snap, prior, slot, res.Credential.Vault, 3)
	}
	if outcome.Status == attest.StatusVerified && outcome.IdentityConfirmed {
		resp.Status = "verified"
		resp.Detail = "attested"
		_ = snap.Remove()
		return emitLoginOutcome(g, resp, 0)
	}
	if outcome.Status == attest.StatusAcceptedBaseline && forceUnverified {
		resp.Status = "accepted_baseline"
		resp.Detail = outcome.Detail
		if err := appendLoginBreakGlassAudit(entry, "force:unverified_login"); err != nil {
			resp.Detail = fmt.Sprintf("audit entry was not written for --force override unverified_login: %v", err)
			return settleLoginRestore(g, resp, entry, snap, prior, slot, res.Credential.Vault, 5)
		}
		forceOverrides = append(forceOverrides, "unverified_login")
		resp.ForceOverrides = append([]string(nil), forceOverrides...)
		entry.Command = "force:" + strings.Join(forceOverrides, ",")
		_ = snap.Remove()
		return emitLoginOutcome(g, resp, 0)
	}
	if !verify.ShouldRefuse(pre.Mode, freshStatus) {
		resp.Status = freshStatus
		resp.Detail = outcome.Detail
		if resp.Detail == "" {
			resp.Detail = fmt.Sprintf("verification status %q after login; kept under verify=%s", outcome.Status, pre.Mode)
		}
		_ = snap.Remove()
		return emitLoginOutcome(g, resp, 0)
	}
	resp.Status = "mismatch"
	if outcome.Detail != "" {
		resp.Detail = outcome.Detail
	} else {
		resp.Detail = fmt.Sprintf("verification status %q after login", outcome.Status)
	}
	return settleLoginRestore(g, resp, entry, snap, prior, slot, res.Credential.Vault, 3)
}

func loginHelperArgs(tmpl string, scopes []string, slot string) []string {
	repl := map[string]string{
		"scopes": joinComma(scopes),
		"slot":   slot,
	}
	args, err := splitLoginHelper(tmpl, repl)
	if err != nil {
		return nil
	}
	return args
}

func joinComma(values []string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, v := range values[1:] {
		out += "," + v
	}
	return out
}

func splitLoginHelper(input string, repl map[string]string) ([]string, error) {
	var args []string
	var cur []rune
	var quote rune
	escaped := false
	flush := func() {
		if len(cur) == 0 {
			return
		}
		args = append(args, string(cur))
		cur = nil
	}
	for _, r := range input {
		if escaped {
			cur = append(cur, r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			cur = append(cur, r)
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			cur = append(cur, r)
		}
	}
	if escaped {
		cur = append(cur, '\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	for i, arg := range args {
		args[i] = expandHelperPlaceholders(arg, repl)
	}
	return args, nil
}

func expandHelperPlaceholders(arg string, repl map[string]string) string {
	out := ""
	for i := 0; i < len(arg); {
		if arg[i] != '{' {
			out += string(arg[i])
			i++
			continue
		}
		end := i + 1
		for end < len(arg) && arg[end] != '}' {
			end++
		}
		if end >= len(arg) {
			out += string(arg[i])
			i++
			continue
		}
		key := arg[i+1 : end]
		if val, ok := repl[key]; ok {
			out += val
		} else {
			out += arg[i : end+1]
		}
		i = end + 1
	}
	return out
}

func ensureLoginSlotUnambiguous(cfg *config.Config, slot string) error {
	target := slot
	if resolved, err := filepath.EvalSymlinks(slot); err == nil {
		target = resolved
	}
	matches := findCredentialMatches(cfg, func(c config.Credential) bool {
		if c.Slot == "" {
			return false
		}
		candidate, err := rules.ExpandHome(c.Slot)
		if err != nil {
			return false
		}
		if candidate == slot {
			return true
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		return err == nil && resolved == target
	})
	_, _, _, _, err := resolveUniqueIdentity(matches, fmt.Sprintf("slot %q", slot))
	if err != nil && errors.Is(err, errCredentialAmbiguous) {
		return err
	}
	return nil
}

func readSlotSecret(slot, credentialFile string) (*vault.Secret, error) {
	info, err := os.Stat(slot)
	if err != nil {
		return nil, fmt.Errorf("read post-login slot: %w", err)
	}
	path := slot
	if info.IsDir() {
		if credentialFile == "" {
			return nil, fmt.Errorf("read post-login slot: directory slot requires login.credential_file in the scope profile")
		}
		if filepath.IsAbs(credentialFile) || credentialFile != filepath.Clean(credentialFile) || credentialFile == "." || credentialFile == ".." || len(credentialFile) >= 3 && credentialFile[:3] == "../" {
			return nil, fmt.Errorf("read post-login slot: invalid login.credential_file %q", credentialFile)
		}
		path = filepath.Join(slot, credentialFile)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read post-login slot: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("read post-login slot: credential is empty")
	}
	return vault.NewSecret(b), nil
}

func settleLoginRestore(g *globalFlags, resp loginResponse, entry audit.Entry, snap *slotsnap.Snapshot, prior *attest.Record, slot, vaultHandle string, intendedExit int) int {
	if snap == nil {
		return emitLoginOutcome(g, resp, intendedExit)
	}
	if err := snap.Restore(); err != nil {
		resp.Status = "restore_failed"
		resp.Detail = resp.Detail + "; restore failed: " + err.Error()
		_ = attest.Write(&attest.Record{
			Slot:             slot,
			VaultHandle:      vaultHandle,
			ExpectedIdentity: resp.ExpectedIdentity,
			Platform:         resp.Platform,
			AccessLevel:      resp.AccessLevel,
			Status:           attest.StatusUnreadable,
			Method:           "restore_failed",
			CheckedAt:        time.Now().UTC(),
			CheckedBy:        attest.DefaultCheckedBy(buildVersion),
		})
		return emitLoginOutcome(g, resp, 4)
	}
	if err := snap.ConfirmRestored(); err != nil {
		resp.Status = "restore_failed"
		resp.Detail = resp.Detail + "; restore confirmation failed: " + err.Error()
		return emitLoginOutcome(g, resp, 4)
	}
	if prior != nil {
		if err := attest.Write(prior); err != nil {
			resp.Status = "restore_failed"
			resp.Detail = resp.Detail + "; restore sidecar write failed: " + err.Error()
			return emitLoginOutcome(g, resp, 4)
		}
		if rec, err := attest.Read(slot, vaultHandle); err != nil || rec.Status != prior.Status {
			resp.Status = "restore_failed"
			resp.Detail = resp.Detail + "; restore sidecar confirmation failed"
			return emitLoginOutcome(g, resp, 4)
		}
	} else {
		if err := attest.Invalidate(slot, vaultHandle); err != nil {
			resp.Status = "restore_failed"
			resp.Detail = resp.Detail + "; clear in-flight sidecar failed: " + err.Error()
			return emitLoginOutcome(g, resp, 4)
		}
		if _, err := attest.Read(slot, vaultHandle); !attest.IsNotFound(err) {
			resp.Status = "restore_failed"
			resp.Detail = resp.Detail + "; in-flight sidecar still readable after restore"
			return emitLoginOutcome(g, resp, 4)
		}
	}
	resp.RolledBack = true
	entry.Target = slot
	return emitLoginOutcome(g, resp, intendedExit)
}

func settleLoginRestoreKeepRefused(g *globalFlags, resp loginResponse, snap *slotsnap.Snapshot, slot, vaultHandle string, intendedExit int) int {
	if snap == nil {
		return emitLoginOutcome(g, resp, intendedExit)
	}
	if err := snap.Restore(); err != nil {
		resp.Status = "restore_failed"
		resp.Detail = resp.Detail + "; restore failed: " + err.Error()
		return emitLoginOutcome(g, resp, 4)
	}
	if err := snap.ConfirmRestored(); err != nil {
		resp.Status = "restore_failed"
		resp.Detail = resp.Detail + "; restore confirmation failed: " + err.Error()
		return emitLoginOutcome(g, resp, 4)
	}
	resp.RolledBack = true
	_ = attest.Write(&attest.Record{
		Slot:             slot,
		VaultHandle:      vaultHandle,
		ExpectedIdentity: resp.ExpectedIdentity,
		Platform:         resp.Platform,
		AccessLevel:      resp.AccessLevel,
		Status:           attest.StatusUnreadable,
		Method:           "login_in_flight",
		CheckedAt:        time.Now().UTC(),
		CheckedBy:        attest.DefaultCheckedBy(buildVersion),
	})
	return emitLoginOutcome(g, resp, intendedExit)
}

func appendLoginBreakGlassAudit(base audit.Entry, command string) error {
	base.ID = audit.NewID()
	base.Op = "login_break_glass"
	base.Command = command
	base.Decision = ""
	base.Exit = 0
	return audit.Append(base)
}

func helperExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 4
}

func emitLoginOutcome(g *globalFlags, resp loginResponse, exitCode int) int {
	if wantJSON(g) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return exitCode
	}
	if exitCode != 0 {
		fmt.Fprintf(os.Stderr, "credroute login: %s\n", resp.Detail)
		return exitCode
	}
	if !g.quiet {
		fmt.Fprintf(os.Stderr, "credroute login: verified: %s is in the slot. Attested.\n", resp.ExpectedIdentity)
		if len(resp.ForceOverrides) > 0 {
			fmt.Fprintf(os.Stderr, "credroute login: force override(s): %s\n", strings.Join(resp.ForceOverrides, ", "))
		}
	}
	return exitCode
}
