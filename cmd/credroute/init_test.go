// allow-claude-code: see init.go header.
//
// Regression tests for the Fable 5 review v2 H1 finding: `init` alone
// resolved an empty --config path via config.DefaultPath() only, never
// consulting $CREDROUTE_CONFIG the way every other command does, and a
// positional path silently overrode an explicit --config flag instead of
// the two conflicting outright.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCmdInit_HonorsCredrouteConfigEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(t.TempDir(), "envconfig.yaml")
	t.Setenv("CREDROUTE_CONFIG", envPath)

	if code := cmdInit([]string{"--yes"}); code != 0 {
		t.Fatalf("cmdInit exit = %d, want 0", code)
	}

	if _, err := os.Stat(envPath); err != nil {
		t.Errorf("init did not write to CREDROUTE_CONFIG path %s: %v", envPath, err)
	}
	defaultPath := filepath.Join(home, ".config", "credroute", "config.yaml")
	if _, err := os.Stat(defaultPath); err == nil {
		t.Errorf("init also wrote to the default path %s; CREDROUTE_CONFIG should have been authoritative", defaultPath)
	}
}

// TestCmdInit_ForceHonorsCredrouteConfigEnv guards the review's "worst
// branch": with CREDROUTE_CONFIG set, `init --force` must overwrite the
// env-named file, never fall back to (or worse, overwrite) the real
// default path.
func TestCmdInit_ForceHonorsCredrouteConfigEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(t.TempDir(), "envconfig.yaml")
	t.Setenv("CREDROUTE_CONFIG", envPath)

	if code := cmdInit([]string{"--yes"}); code != 0 {
		t.Fatalf("first init exit = %d, want 0", code)
	}
	if code := cmdInit([]string{"--yes", "--force"}); code != 0 {
		t.Fatalf("init --force exit = %d, want 0", code)
	}

	defaultPath := filepath.Join(home, ".config", "credroute", "config.yaml")
	if _, err := os.Stat(defaultPath); err == nil {
		t.Errorf("init --force wrote to the default path %s instead of CREDROUTE_CONFIG", defaultPath)
	}
	if _, err := os.Stat(envPath); err != nil {
		t.Errorf("init --force should have overwritten CREDROUTE_CONFIG path %s: %v", envPath, err)
	}
}

func TestCmdInit_FlagAndPositionalConflict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	flagPath := filepath.Join(dir, "flag.yaml")
	posPath := filepath.Join(dir, "positional.yaml")

	code := cmdInit([]string{"--yes", "--config", flagPath, posPath})
	if code == 0 {
		t.Fatal("expected a non-zero exit for a --config + positional path conflict, got 0")
	}
	if _, err := os.Stat(flagPath); err == nil {
		t.Error("flag path should not have been written when --config and a positional path conflict")
	}
	if _, err := os.Stat(posPath); err == nil {
		t.Error("positional path should not have been written when --config and a positional path conflict")
	}
}

// TestCmdInit_WritesAtomically guards L6: init's config write goes
// through fsutil.WriteFileAtomic (a fresh write and a --force overwrite
// alike), rather than a plain os.WriteFile.
func TestCmdInit_WritesAtomically(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(t.TempDir(), "config.yaml")

	if code := cmdInit([]string{"--yes", "--config", path}); code != 0 {
		t.Fatalf("cmdInit exit = %d, want 0", code)
	}
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("stray file %q left behind in %s; atomic write should leave only the final file", e.Name(), dir)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config not written at %s: %v", path, err)
	}
}
