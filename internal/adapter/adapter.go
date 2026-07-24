// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md section 8) for
// this exact multi-file build; mechanical translation of spec to Go, low
// ambiguity.
//
// Package adapter generates the harness glue described in spec section 8:
// a Claude Code skill + PreToolUse hook, a Codex AGENTS.md snippet + PATH
// shims, and an agy GEMINI.md snippet + PATH shims. An adapter is glue,
// never logic (spec 8.1): every file this package writes only ever calls
// out to `credroute resolve`/`credroute exec`; no routing, verification,
// or secret handling lives here.
package adapter

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hasandenizuk/credroute/internal/config"
)

//go:embed templates
var templatesFS embed.FS

// Kind identifies which harness an adapter targets.
type Kind string

const (
	ClaudeCode Kind = "claude-code"
	Codex      Kind = "codex"
	Agy        Kind = "agy"
)

// ParseKind validates a CLI-supplied adapter name.
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case ClaudeCode, Codex, Agy:
		return Kind(s), nil
	default:
		return "", fmt.Errorf("adapter: unknown adapter %q (expected: claude-code, codex, agy)", s)
	}
}

// DefaultDir returns the conventional install location for kind when the
// caller does not pass --dir.
func DefaultDir(kind Kind) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("adapter: determine home directory: %w", err)
	}
	switch kind {
	case ClaudeCode:
		return filepath.Join(home, ".claude"), nil
	case Codex:
		return filepath.Join(home, ".codex"), nil
	case Agy:
		return filepath.Join(home, ".gemini"), nil
	default:
		return "", fmt.Errorf("adapter: unknown adapter %q", kind)
	}
}

// InstallOptions configures Install.
type InstallOptions struct {
	// Dir overrides the conventional install location (DefaultDir).
	Dir string
	// DryRun reports what would be written without touching disk.
	DryRun bool
	// Force overwrites files that already exist. Without it, Install
	// never clobbers an existing file (spec: "NEVER clobber without
	// --force").
	Force bool
}

// FileAction describes what Install did (or, under DryRun, would do) for
// one planned file.
type FileAction struct {
	Path    string `json:"path"`
	Exists  bool   `json:"exists"`
	Written bool   `json:"written"`
	Skipped bool   `json:"skipped"`
}

// InstallResult is the outcome of one Install call.
type InstallResult struct {
	Kind  Kind         `json:"kind"`
	Dir   string       `json:"dir"`
	Files []FileAction `json:"files"`
}

type plannedFile struct {
	Path       string
	Content    string
	Executable bool
}

// Install writes kind's adapter glue into dir (opts.Dir, or DefaultDir(kind)
// if empty). It never overwrites an existing file unless opts.Force is
// set, and never touches disk at all under opts.DryRun.
func Install(kind Kind, opts InstallOptions) (*InstallResult, error) {
	dir := opts.Dir
	if dir == "" {
		d, err := DefaultDir(kind)
		if err != nil {
			return nil, err
		}
		dir = d
	}
	expandedDir, err := config.ExpandHome(dir)
	if err != nil {
		return nil, fmt.Errorf("adapter: expand --dir: %w", err)
	}

	planned, err := filesFor(kind, expandedDir)
	if err != nil {
		return nil, err
	}

	result := &InstallResult{Kind: kind, Dir: expandedDir}
	for _, pf := range planned {
		action := FileAction{Path: pf.Path}
		if _, statErr := os.Stat(pf.Path); statErr == nil {
			action.Exists = true
		}

		if opts.DryRun {
			result.Files = append(result.Files, action)
			continue
		}
		if action.Exists && !opts.Force {
			action.Skipped = true
			result.Files = append(result.Files, action)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(pf.Path), 0o755); err != nil {
			return nil, fmt.Errorf("adapter: create %s: %w", filepath.Dir(pf.Path), err)
		}
		mode := os.FileMode(0o644)
		if pf.Executable {
			mode = 0o755
		}
		if err := os.WriteFile(pf.Path, []byte(pf.Content), mode); err != nil {
			return nil, fmt.Errorf("adapter: write %s: %w", pf.Path, err)
		}
		action.Written = true
		result.Files = append(result.Files, action)
	}
	return result, nil
}

// filesFor returns every file kind's adapter installs, rooted at dir.
func filesFor(kind Kind, dir string) ([]plannedFile, error) {
	switch kind {
	case ClaudeCode:
		skill, err := readTemplate("templates/claude-code/SKILL.md")
		if err != nil {
			return nil, err
		}
		hook, err := readTemplate("templates/claude-code/hook.sh")
		if err != nil {
			return nil, err
		}
		return []plannedFile{
			{Path: filepath.Join(dir, "skills", "credroute", "SKILL.md"), Content: skill},
			{Path: filepath.Join(dir, "hooks", "credroute-resolve-hook.sh"), Content: hook, Executable: true},
		}, nil

	case Codex:
		agents, err := readTemplate("templates/codex/AGENTS.md")
		if err != nil {
			return nil, err
		}
		gws, gh, err := shims()
		if err != nil {
			return nil, err
		}
		return []plannedFile{
			{Path: filepath.Join(dir, "AGENTS.md"), Content: agents},
			{Path: filepath.Join(dir, "shims", "gws"), Content: gws, Executable: true},
			{Path: filepath.Join(dir, "shims", "gh"), Content: gh, Executable: true},
		}, nil

	case Agy:
		gemini, err := readTemplate("templates/agy/GEMINI.md")
		if err != nil {
			return nil, err
		}
		gws, gh, err := shims()
		if err != nil {
			return nil, err
		}
		return []plannedFile{
			{Path: filepath.Join(dir, "GEMINI.md"), Content: gemini},
			{Path: filepath.Join(dir, "shims", "gws"), Content: gws, Executable: true},
			{Path: filepath.Join(dir, "shims", "gh"), Content: gh, Executable: true},
		}, nil

	default:
		return nil, fmt.Errorf("adapter: unknown adapter %q", kind)
	}
}

func shims() (gws, gh string, err error) {
	gws, err = readTemplate("templates/shims/gws.sh")
	if err != nil {
		return "", "", err
	}
	gh, err = readTemplate("templates/shims/gh.sh")
	if err != nil {
		return "", "", err
	}
	return gws, gh, nil
}

func readTemplate(name string) (string, error) {
	b, err := templatesFS.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("adapter: read embedded template %s: %w", name, err)
	}
	return string(b), nil
}
