// allow-claude-code: regression tests for the slot-write login guard.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasandenizuk/credroute/internal/attest"
	"github.com/hasandenizuk/credroute/internal/config"
	"github.com/hasandenizuk/credroute/internal/slotsnap"
	"github.com/hasandenizuk/credroute/internal/vault"
)

func TestCmdLogin_IntentMismatchRefusesBeforeChildRuns(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfig(t, "required", false)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))

	code := cmdLogin([]string{"--platform", "google", "--expect", "other@example.com"})
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("login helper ran despite intent mismatch")
	}
	assertSlotContent(t, slot, "before")
}

func TestCmdLogin_DestinationConflictRefuses(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfig(t, "required", false)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))
	t.Setenv("TEST_SLOT_DIR", filepath.Join(t.TempDir(), "other-slot"))

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("login helper ran despite destination conflict")
	}
	assertSlotContent(t, slot, "before")
}

func TestCmdLogin_SnapshotFailureRefuses(t *testing.T) {
	cfgPath, _, marker := writeLoginConfig(t, "required", true)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 4 {
		t.Fatalf("exit = %d, want 4", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("login helper ran despite snapshot failure")
	}
}

func TestCmdLogin_WrongIdentityAfterLoginRollsBackAndConfirms(t *testing.T) {
	v := newTestVault(t)
	v.Encrypt(t, "google/alex.age", []byte("current-secret"))
	slot := filepath.Join(t.TempDir(), "slot")
	if err := os.MkdirAll(slot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "token.json"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeLoginConfigWithVault(t, slot, v.StoreDir, v.IdentityFile, "required")
	marker := filepath.Join(t.TempDir(), "ran")
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")
	oldFP := vault.FingerprintBytes([]byte("old-secret"))
	if err := attest.Write(&attest.Record{
		Slot:             slot,
		VaultHandle:      "age://google/alex.age",
		ExpectedIdentity: "alex@example.com",
		Platform:         "google",
		AccessLevel:      "read-only",
		Status:           attest.StatusAcceptedBaseline,
		Method:           "fingerprint",
		Fingerprint:      oldFP,
		CheckedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	assertSlotContent(t, slot, "before")
	rec, err := attest.Read(slot, "age://google/alex.age")
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if rec.Status != attest.StatusAcceptedBaseline || rec.Fingerprint != oldFP {
		t.Fatalf("sidecar not restored, status=%s fp=%s", rec.Status, rec.Fingerprint)
	}
}

func TestCmdLogin_HelperFailureLeavesSlotRefused(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfig(t, "required", false)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirWithBody(t, marker, "echo partial > \"$1/token.json\"\nexit 9\n"))

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 9 {
		t.Fatalf("exit = %d, want 9", code)
	}
	assertSlotContent(t, slot, "before")
	rec, err := attest.Read(slot, "age://google/alex.age")
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if rec.Status != attest.StatusUnreadable || rec.Method != "login_in_flight" {
		t.Fatalf("status=%s method=%s, want unreadable login_in_flight", rec.Status, rec.Method)
	}
}

func TestCmdLogin_ConcurrentLoginRefuses(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfig(t, "required", false)
	stateDir := t.TempDir()
	lock, err := slotsnap.AcquireLock(stateDir, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", stateDir)
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestCmdLogin_AcceptUnverifiedLoginRecordsBaseline(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfigForPlatform(t, "stripe", "required", false)
	stateDir := t.TempDir()
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", stateDir)
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirForPlatform(t, "stripe", marker))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")

	code := cmdLogin([]string{"--platform", "stripe", "--expect", "alex@example.com", "--force"})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	assertSlotContent(t, slot, "after")
	rec, err := attest.Read(slot, "age://stripe/alex.age")
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	if rec.Status != attest.StatusAcceptedBaseline || rec.Method != "fingerprint" {
		t.Fatalf("status=%s method=%s, want accepted_baseline fingerprint", rec.Status, rec.Method)
	}
	assertSnapshotDirEmpty(t, stateDir)
}

func TestCmdLogin_AcceptUnverifiedLoginAllowedWhenKnownProberDisabled(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfig(t, "required", false)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com", "--force"})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	assertSlotContent(t, slot, "after")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("login helper did not run with disabled live prober")
	}
}

func TestCmdLogin_SymlinkSlotRollbackRestoresRealTarget(t *testing.T) {
	base := t.TempDir()
	realSlot := filepath.Join(base, "real-slot")
	if err := os.MkdirAll(realSlot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realSlot, "token.json"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkSlot := filepath.Join(base, "slot-link")
	if err := os.Symlink(realSlot, linkSlot); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(base, "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(base, "identity.txt")
	if err := os.WriteFile(identity, []byte("test identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeLoginConfigWithVault(t, linkSlot, store, identity, "required")
	marker := filepath.Join(base, "ran")
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	assertSlotContent(t, realSlot, "before")
}

func TestCmdLogin_AcceptUnverifiedLoginFailsWhenAuditCannotBeWritten(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfigForPlatform(t, "stripe", "required", false)
	stateDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(stateDir, "audit.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", stateDir)
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirForPlatform(t, "stripe", marker))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")

	code := cmdLogin([]string{"--platform", "stripe", "--expect", "alex@example.com", "--force"})
	if code != 5 {
		t.Fatalf("exit = %d, want 5", code)
	}
	assertSlotContent(t, slot, "before")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("login helper did not run before baseline audit failed")
	}
}

func TestCmdLogin_HelperThatWritesNothingToGuardedSlotRefuses(t *testing.T) {
	base := t.TempDir()
	slot := filepath.Join(base, "slot-token")
	if err := os.WriteFile(slot, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(base, "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(base, "identity.txt")
	if err := os.WriteFile(identity, []byte("test identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeLoginConfigWithVaultForPlatform(t, "stripe", slot, store, identity, "required")
	marker := filepath.Join(base, "ran")
	elsewhere := filepath.Join(base, "elsewhere")
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirWithBodyForPlatform(t, "stripe", marker, fmt.Sprintf("echo ran > \"$2\"\nmkdir -p %q\necho after > %q\n", elsewhere, filepath.Join(elsewhere, "token.json"))))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")

	code := cmdLogin([]string{"--platform", "stripe", "--expect", "alex@example.com", "--force"})
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	b, err := os.ReadFile(slot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "before" {
		t.Fatalf("slot content = %q, want before", strings.TrimSpace(string(b)))
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "token.json")); err != nil {
		t.Fatalf("helper did not write elsewhere: %v", err)
	}
}

func TestCmdLogin_ProfileWithSlotEnvRequiresSlotPlaceholder(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfig(t, "required", false)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirWithHelperForPlatform(t, "google", marker, "login-helper"))

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 5 {
		t.Fatalf("exit = %d, want 5", code)
	}
	assertSlotContent(t, slot, "before")
}

func TestConfigValidate_ProfileWithSlotEnvRequiresSlotPlaceholder(t *testing.T) {
	cfgPath, _, marker := writeLoginConfig(t, "required", false)
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirWithHelperForPlatform(t, "google", marker, "login-helper"))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	errs := validateLoginProfilesForConfig(cfg)
	if len(errs) == 0 {
		t.Fatal("validateLoginProfilesForConfig returned no errors")
	}
	if !strings.Contains(errs[0].Message, "{slot}") {
		t.Fatalf("error = %q, want {slot}", errs[0].Message)
	}
}

func TestCmdLogin_SharedSlotRefusesBeforeChildRuns(t *testing.T) {
	cfgPath, slot, marker := writeLoginConfigWithSharedSlot(t)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 5 {
		t.Fatalf("exit = %d, want 5", code)
	}
	assertSlotContent(t, slot, "before")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("login helper ran despite shared slot ambiguity")
	}
}

func TestCmdLogin_SlotPathWithSpacesIsPassedToHelper(t *testing.T) {
	base := t.TempDir()
	slot := filepath.Join(base, "slot with spaces")
	if err := os.MkdirAll(slot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "token.json"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(base, "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(base, "identity.txt")
	if err := os.WriteFile(identity, []byte("test identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeLoginConfigWithVaultForPlatform(t, "stripe", slot, store, identity, "required")
	marker := filepath.Join(base, "ran")
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirForPlatform(t, "stripe", marker))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")

	code := cmdLogin([]string{"--platform", "stripe", "--expect", "alex@example.com", "--force"})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	assertSlotContent(t, slot, "after")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("login helper marker: %v", err)
	}
}

func TestLoginHelperArgsPreservesQuotedSlot(t *testing.T) {
	args := loginHelperArgs(`helper --slot "{slot}" --scopes '{scopes}'`, []string{"one", "two"}, "/tmp/slot with spaces")
	want := []string{"helper", "--slot", "/tmp/slot with spaces", "--scopes", "one,two"}
	if strings.Join(args, "\n") != strings.Join(want, "\n") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestCmdLogin_UnroutedIdentityRefuses(t *testing.T) {
	cfgPath, _, marker := writeLoginConfig(t, "required", false)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDir(t, marker))

	code := cmdLogin([]string{"--platform", "stripe", "--expect", "alex@example.com"})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestCmdLogin_MissingSlotEnvRequiresBreakGlass(t *testing.T) {
	cfgPath, _, marker := writeLoginConfig(t, "required", false)
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", t.TempDir())
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirWithoutSlotEnv(t, marker))

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com"})
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("login helper ran without slot_env and without break-glass")
	}
}

func TestCmdLogin_AcceptAmbientDestinationFailsWhenAuditCannotBeWritten(t *testing.T) {
	cfgPath, _, marker := writeLoginConfig(t, "required", false)
	stateFile := filepath.Join(t.TempDir(), "state-file")
	if err := os.WriteFile(stateFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", stateFile)
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirWithoutSlotEnv(t, marker))

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com", "--force"})
	if code != 5 {
		t.Fatalf("exit = %d, want 5", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("login helper ran after break-glass audit failed")
	}
}

func TestCmdLogin_AcceptAmbientDestinationAuditIsNotOutcomeAllow(t *testing.T) {
	cfgPath, _, marker := writeLoginConfig(t, "required", false)
	stateDir := t.TempDir()
	t.Setenv("CREDROUTE_CONFIG", cfgPath)
	t.Setenv("CREDROUTE_STATE_DIR", stateDir)
	t.Setenv("CREDROUTE_PROFILES_DIR", loginProfileDirWithoutSlotEnv(t, marker))
	t.Setenv("CREDROUTE_NO_NETWORK", "1")

	code := cmdLogin([]string{"--platform", "google", "--expect", "alex@example.com", "--force"})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	b, err := os.ReadFile(filepath.Join(stateDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var missingSlotSeen, unverifiedSeen, allowSeen bool
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var entry struct {
			Op       string `json:"op"`
			Decision string `json:"decision"`
			Command  string `json:"command"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Command == "force:missing_slot_env" {
			missingSlotSeen = true
			if entry.Op != "login_break_glass" || entry.Decision == "allow" {
				t.Fatalf("break-glass audit entry op=%q decision=%q, want login_break_glass without allow", entry.Op, entry.Decision)
			}
		}
		if entry.Command == "force:unverified_login" {
			unverifiedSeen = true
			if entry.Op != "login_break_glass" || entry.Decision == "allow" {
				t.Fatalf("break-glass audit entry op=%q decision=%q, want login_break_glass without allow", entry.Op, entry.Decision)
			}
		}
		if entry.Op == "login" && entry.Decision == "allow" {
			allowSeen = true
		}
	}
	if !missingSlotSeen || !unverifiedSeen || !allowSeen {
		t.Fatalf("missingSlotSeen=%v unverifiedSeen=%v allowSeen=%v, want all", missingSlotSeen, unverifiedSeen, allowSeen)
	}
}

func writeLoginConfig(t *testing.T, verifyMode string, missingSlot bool) (string, string, string) {
	t.Helper()
	return writeLoginConfigForPlatform(t, "google", verifyMode, missingSlot)
}

func writeLoginConfigForPlatform(t *testing.T, platform, verifyMode string, missingSlot bool) (string, string, string) {
	t.Helper()
	base := t.TempDir()
	slot := filepath.Join(base, "slot")
	if !missingSlot {
		if err := os.MkdirAll(slot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(slot, "token.json"), []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store := filepath.Join(base, "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(base, "identity.txt")
	if err := os.WriteFile(identity, []byte("test identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	return writeLoginConfigWithVaultForPlatform(t, platform, slot, store, identity, verifyMode), slot, filepath.Join(base, "ran")
}

func writeLoginConfigWithVault(t *testing.T, slot, store, identity, verifyMode string) string {
	t.Helper()
	return writeLoginConfigWithVaultForPlatform(t, "google", slot, store, identity, verifyMode)
}

func writeLoginConfigWithVaultForPlatform(t *testing.T, platform, slot, store, identity, verifyMode string) string {
	t.Helper()
	return writeTestConfig(t, fmt.Sprintf(`
version: 1
defaults: {on_no_match: refuse, verify: %s}
clients: {}
identities:
  alex@example.com:
    platforms:
      %s:
        credentials:
          read-only: {type: oauth, vault: age://%s/alex.age, slot: %s}
rules:
  - id: %s-default
    match: {platform: %s}
    use: {identity: alex@example.com, access: read-only}
vault:
  backend: age
  age: {store_dir: %s, identity_file: %s}
`, verifyMode, platform, platform, slot, platform, platform, store, identity))
}

func loginProfileDir(t *testing.T, marker string) string {
	t.Helper()
	return loginProfileDirForPlatform(t, "google", marker)
}

func loginProfileDirForPlatform(t *testing.T, platform, marker string) string {
	t.Helper()
	body := "echo ran > \"$2\"\necho after > \"$1/token.json\"\n"
	return loginProfileDirWithBodyForPlatform(t, platform, marker, body)
}

func loginProfileDirWithBody(t *testing.T, marker, body string) string {
	t.Helper()
	return loginProfileDirWithBodyForPlatform(t, "google", marker, body)
}

func loginProfileDirWithBodyForPlatform(t *testing.T, platform, marker, body string) string {
	t.Helper()
	dir := t.TempDir()
	helper := filepath.Join(dir, "login-helper")
	script := "#!/bin/sh\n" + body
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf(`
platform: %s
credential_types: [oauth]
access_levels:
  read-only:
    scopes:
      default: ["scope1"]
login:
  helper: "%s {slot} %s"
  slot_env: TEST_SLOT_DIR
  credential_file: token.json
`, platform, helper, marker)
	if err := os.WriteFile(filepath.Join(dir, platform+".yaml"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func loginProfileDirWithHelperForPlatform(t *testing.T, platform, marker, helperSpec string) string {
	t.Helper()
	dir := t.TempDir()
	helper := filepath.Join(dir, "login-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho ran > \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf(`
platform: %s
credential_types: [oauth]
access_levels:
  read-only:
    scopes:
      default: ["scope1"]
login:
  helper: "%s %s"
  slot_env: TEST_SLOT_DIR
  credential_file: token.json
`, platform, filepath.Join(dir, helperSpec), marker)
	if err := os.WriteFile(filepath.Join(dir, platform+".yaml"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func loginProfileDirWithoutSlotEnv(t *testing.T, marker string) string {
	t.Helper()
	dir := t.TempDir()
	helper := filepath.Join(dir, "login-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho ran > \"$2\"\necho after > \"$1/token.json\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := fmt.Sprintf(`
platform: google
credential_types: [oauth]
access_levels:
  read-only:
    scopes:
      default: ["scope1"]
login:
  helper: "%s {slot} %s"
  credential_file: token.json
`, helper, marker)
	if err := os.WriteFile(filepath.Join(dir, "google.yaml"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeLoginConfigWithSharedSlot(t *testing.T) (string, string, string) {
	t.Helper()
	base := t.TempDir()
	slot := filepath.Join(base, "slot")
	if err := os.MkdirAll(slot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "token.json"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(base, "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(base, "identity.txt")
	if err := os.WriteFile(identity, []byte("test identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
version: 1
defaults: {on_no_match: refuse, verify: required}
clients: {}
identities:
  alex@example.com:
    platforms:
      google:
        credentials:
          read-only: {type: oauth, vault: age://google/alex.age, slot: %s}
  bob@example.com:
    platforms:
      google:
        credentials:
          read-only: {type: oauth, vault: age://google/bob.age, slot: %s}
rules:
  - id: google-default
    match: {platform: google}
    use: {identity: alex@example.com, access: read-only}
vault:
  backend: age
  age: {store_dir: %s, identity_file: %s}
`, slot, slot, store, identity))
	return cfgPath, slot, filepath.Join(base, "ran")
}

func assertSlotContent(t *testing.T, slot, want string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(slot, "token.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != want {
		t.Fatalf("slot content = %q, want %q", strings.TrimSpace(string(b)), want)
	}
}

func assertSnapshotDirEmpty(t *testing.T, stateDir string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(stateDir, "login-snapshots"))
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("snapshot dir has %d entries, want 0", len(entries))
	}
}
