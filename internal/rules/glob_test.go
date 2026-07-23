// allow-claude-code: see glob.go header.
package rules

import "testing"

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		target  string
		want    bool
	}{
		{"exact", "/a/b/c", "/a/b/c", true},
		{"mismatch", "/a/b/c", "/a/b/d", false},
		{"single-star-segment", "/a/*/c", "/a/b/c", true},
		{"single-star-no-cross-sep", "/a/*/c", "/a/b/x/c", false},
		{"doublestar-trailing-matches-base", "/a/b/**", "/a/b", true},
		{"doublestar-trailing-one-level", "/a/b/**", "/a/b/c", true},
		{"doublestar-trailing-many-levels", "/a/b/**", "/a/b/c/d/e", true},
		{"doublestar-trailing-no-match-sibling", "/a/b/**", "/a/x/c", false},
		{"doublestar-middle", "/a/**/z", "/a/b/c/z", true},
		{"doublestar-middle-zero", "/a/**/z", "/a/z", true},
		{"question-mark", "/a/?/c", "/a/b/c", true},
		{"trailing-slash-cleaned", "/a/b/**/", "/a/b/c", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchGlob(tc.pattern, tc.target)
			if got != tc.want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.pattern, tc.target, got, tc.want)
			}
		})
	}
}

func TestExpandHome(t *testing.T) {
	t.Setenv("HOME", "/home/testuser")

	cases := []struct {
		in   string
		want string
	}{
		{"~", "/home/testuser"},
		{"~/Projects", "/home/testuser/Projects"},
		{"/absolute/path", "/absolute/path"},
		{"", ""},
		{"relative/path", "relative/path"},
	}
	for _, tc := range cases {
		got, err := ExpandHome(tc.in)
		if err != nil {
			t.Fatalf("ExpandHome(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
