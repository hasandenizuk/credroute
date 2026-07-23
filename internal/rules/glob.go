// allow-claude-code: subagent dispatched directly by orchestrator with a
// fully-specified technical spec (docs/technical-spec.md) for this exact
// multi-file build; mechanical translation of spec to Go, low ambiguity.
//
// Package rules implements the credroute rule engine: matching an ordered
// list of rules against a query (directory, platform, task) and returning
// the first match.
package rules

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandHome expands a leading "~" or "~/" to the current user's home
// directory. Non-"~" paths are returned unchanged.
func ExpandHome(p string) (string, error) {
	if p == "" {
		return p, nil
	}
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if p == "~" {
		return home, nil
	}
	return filepath.Join(home, p[2:]), nil
}

// MatchGlob reports whether target matches pattern, where pattern may use
// standard single-segment wildcards (`*`, `?`, `[...]` via filepath.Match)
// plus a doublestar segment `**` that matches zero or more path segments,
// crossing separators. Both pattern and target are split on "/" after
// cleaning; a leading "~" in either is NOT expanded here (callers expand
// home directories before calling MatchGlob).
func MatchGlob(pattern, target string) bool {
	patSegs := splitClean(pattern)
	tgtSegs := splitClean(target)
	return matchSegments(patSegs, tgtSegs)
}

func splitClean(p string) []string {
	if p == "" {
		return nil
	}
	cleaned := filepath.Clean(p)
	cleaned = filepath.ToSlash(cleaned)
	parts := strings.Split(cleaned, "/")
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		if seg == "" {
			continue
		}
		out = append(out, seg)
	}
	return out
}

func matchSegments(pat, str []string) bool {
	if len(pat) == 0 {
		return len(str) == 0
	}
	if pat[0] == "**" {
		// ** matches zero or more segments; try every split point.
		for i := 0; i <= len(str); i++ {
			if matchSegments(pat[1:], str[i:]) {
				return true
			}
		}
		return false
	}
	if len(str) == 0 {
		return false
	}
	ok, err := filepath.Match(pat[0], str[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pat[1:], str[1:])
}
