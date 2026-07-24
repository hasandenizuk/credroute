// allow-claude-code: see adapter.go header.
package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseKind(t *testing.T) {
	for _, s := range []string{"claude-code", "codex", "agy"} {
		if _, err := ParseKind(s); err != nil {
			t.Fatalf("ParseKind(%q): %v", s, err)
		}
	}
	if _, err := ParseKind("nope"); err == nil {
		t.Fatal("ParseKind(\"nope\") should error")
	}
}

func TestInstall_DryRun_WritesNothing(t *testing.T) {
	dir := t.TempDir()
	result, err := Install(ClaudeCode, InstallOptions{Dir: dir, DryRun: true})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(result.Files) == 0 {
		t.Fatal("expected planned files")
	}
	for _, f := range result.Files {
		if f.Written {
			t.Fatalf("dry-run should never mark a file written: %+v", f)
		}
		if _, statErr := os.Stat(f.Path); statErr == nil {
			t.Fatalf("dry-run should never create %s", f.Path)
		}
	}
}

func TestInstall_ClaudeCode_RealInstall(t *testing.T) {
	dir := t.TempDir()
	result, err := Install(ClaudeCode, InstallOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(result.Files) != 2 {
		t.Fatalf("expected 2 files for claude-code, got %d: %+v", len(result.Files), result.Files)
	}

	foundResolve := false
	for _, f := range result.Files {
		if !f.Written {
			t.Fatalf("expected %s to be written", f.Path)
		}
		b, readErr := os.ReadFile(f.Path)
		if readErr != nil {
			t.Fatalf("read %s: %v", f.Path, readErr)
		}
		if len(b) == 0 {
			t.Fatalf("%s is empty", f.Path)
		}
		if strings.Contains(string(b), "credroute resolve") {
			foundResolve = true
		}
	}
	if !foundResolve {
		t.Fatal("no installed claude-code file contains a `credroute resolve` call")
	}

	hookPath := filepath.Join(dir, "hooks", "credroute-resolve-hook.sh")
	info, statErr := os.Stat(hookPath)
	if statErr != nil {
		t.Fatalf("stat hook: %v", statErr)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("hook script %s should be executable, mode is %v", hookPath, info.Mode())
	}
}

func TestInstall_Codex_RealInstall(t *testing.T) {
	dir := t.TempDir()
	result, err := Install(Codex, InstallOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	wantPaths := map[string]bool{
		filepath.Join(dir, "AGENTS.md"):    false,
		filepath.Join(dir, "shims", "gws"): false,
		filepath.Join(dir, "shims", "gh"):  false,
	}
	for _, f := range result.Files {
		if _, ok := wantPaths[f.Path]; ok {
			wantPaths[f.Path] = true
		}
		if !f.Written {
			t.Fatalf("expected %s to be written", f.Path)
		}
	}
	for p, found := range wantPaths {
		if !found {
			t.Fatalf("expected codex install to write %s", p)
		}
	}

	agents, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	if !strings.Contains(string(agents), "credroute resolve") {
		t.Fatal("AGENTS.md should contain a `credroute resolve` call")
	}
}

func TestInstall_Agy_RealInstall(t *testing.T) {
	dir := t.TempDir()
	result, err := Install(Agy, InstallOptions{Dir: dir})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(result.Files) != 3 {
		t.Fatalf("expected 3 files for agy, got %d", len(result.Files))
	}
	gemini, err := os.ReadFile(filepath.Join(dir, "GEMINI.md"))
	if err != nil {
		t.Fatalf("read GEMINI.md: %v", err)
	}
	if !strings.Contains(string(gemini), "credroute resolve") {
		t.Fatal("GEMINI.md should contain a `credroute resolve` call")
	}
}

func TestInstall_NeverClobbersWithoutForce(t *testing.T) {
	dir := t.TempDir()
	if _, err := Install(Codex, InstallOptions{Dir: dir}); err != nil {
		t.Fatalf("first install: %v", err)
	}

	agentsPath := filepath.Join(dir, "AGENTS.md")
	if err := os.WriteFile(agentsPath, []byte("operator's own edits"), 0o644); err != nil {
		t.Fatalf("simulate local edit: %v", err)
	}

	result, err := Install(Codex, InstallOptions{Dir: dir})
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	var sawSkip bool
	for _, f := range result.Files {
		if f.Path == agentsPath {
			if !f.Skipped || f.Written {
				t.Fatalf("expected AGENTS.md to be skipped without --force, got %+v", f)
			}
			sawSkip = true
		}
	}
	if !sawSkip {
		t.Fatal("AGENTS.md was not in the install plan")
	}
	b, _ := os.ReadFile(agentsPath)
	if string(b) != "operator's own edits" {
		t.Fatal("install clobbered an existing file without --force")
	}

	if _, err := Install(Codex, InstallOptions{Dir: dir, Force: true}); err != nil {
		t.Fatalf("forced install: %v", err)
	}
	b2, _ := os.ReadFile(agentsPath)
	if string(b2) == "operator's own edits" {
		t.Fatal("--force did not overwrite the existing file")
	}
}

func TestDefaultDir(t *testing.T) {
	for _, k := range []Kind{ClaudeCode, Codex, Agy} {
		dir, err := DefaultDir(k)
		if err != nil {
			t.Fatalf("DefaultDir(%s): %v", k, err)
		}
		if dir == "" {
			t.Fatalf("DefaultDir(%s) returned empty path", k)
		}
	}
}

// TestInstall_GeneratesCommandReferenceFromDescribe checks that every
// installed adapter's prose file (SKILL.md/AGENTS.md/GEMINI.md) has its
// "{{COMMAND_REFERENCE}}" marker replaced with a real, generated
// command list, not left as a literal placeholder, and that the list
// covers commands from every era of the command surface (a routing
// command from milestone 1 and an imperative command from this
// milestone), so a future command surface change that is not reflected
// here is visible as a content check, not just "the marker disappeared".
func TestInstall_GeneratesCommandReferenceFromDescribe(t *testing.T) {
	cases := []struct {
		kind Kind
		file string
	}{
		{ClaudeCode, filepath.Join("skills", "credroute", "SKILL.md")},
		{Codex, "AGENTS.md"},
		{Agy, "GEMINI.md"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		if _, err := Install(c.kind, InstallOptions{Dir: dir}); err != nil {
			t.Fatalf("Install(%s): %v", c.kind, err)
		}
		b, err := os.ReadFile(filepath.Join(dir, c.file))
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		content := string(b)
		if strings.Contains(content, commandReferenceMarker) {
			t.Errorf("%s: marker %q was not substituted", c.file, commandReferenceMarker)
		}
		if !strings.Contains(content, "`credroute resolve`") {
			t.Errorf("%s: generated reference missing `credroute resolve`", c.file)
		}
		if !strings.Contains(content, "`credroute identity add`") {
			t.Errorf("%s: generated reference missing `credroute identity add`", c.file)
		}
	}
}

func TestCommandReferenceBlock_OneLinePerCommand(t *testing.T) {
	block := commandReferenceBlock()
	lines := strings.Split(strings.TrimSpace(block), "\n")
	var bulletCount int
	for _, line := range lines {
		if strings.HasPrefix(line, "- `credroute ") {
			bulletCount++
			if strings.Count(line, "\n") != 0 {
				t.Errorf("bullet line contains an embedded newline: %q", line)
			}
		}
	}
	if bulletCount == 0 {
		t.Fatal("commandReferenceBlock produced no command bullets")
	}
}

func TestFirstSentence(t *testing.T) {
	cases := map[string]string{
		"One sentence only":               "One sentence only",
		"First. Second sentence follows.": "First.",
		"":                                "",
	}
	for in, want := range cases {
		if got := firstSentence(in); got != want {
			t.Errorf("firstSentence(%q) = %q, want %q", in, got, want)
		}
	}
}
