// allow-claude-code: see common.go header.
package main

import (
	"flag"
	"reflect"
	"testing"
)

// newAdapterInstallLikeFlagSet mirrors adapter install's real flag shape
// (one bool, two strings) so reorderArgsForFlagParse's bool-vs-valued
// detection is exercised against realistic flags, not a toy set.
func newAdapterInstallLikeFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("adapter install", flag.ContinueOnError)
	fs.String("dir", "", "")
	fs.Bool("dry-run", false, "")
	fs.Bool("force", false, "")
	return fs
}

// TestReorderArgsForFlagParse is F13: flags must parse correctly no
// matter where they sit relative to positional arguments.
func TestReorderArgsForFlagParse(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "all flags first (already correct order)",
			args: []string{"--dry-run", "--dir", "/tmp/x", "claude-code"},
			want: []string{"--dry-run", "--dir", "/tmp/x", "claude-code"},
		},
		{
			name: "positional first, documented F13 shape",
			args: []string{"claude-code", "--dry-run", "--force"},
			want: []string{"--dry-run", "--force", "claude-code"},
		},
		{
			name: "flag with value interspersed after positional",
			args: []string{"claude-code", "--dir", "/tmp/x", "--force"},
			want: []string{"--dir", "/tmp/x", "--force", "claude-code"},
		},
		{
			name: "equals-form flag after positional",
			args: []string{"claude-code", "--dir=/tmp/x"},
			want: []string{"--dir=/tmp/x", "claude-code"},
		},
		{
			name: "double-dash boundary is preserved untouched",
			args: []string{"platformname", "--", "gws", "--profile", "x"},
			want: []string{"platformname", "--", "gws", "--profile", "x"},
		},
		{
			name: "no flags at all",
			args: []string{"claude-code"},
			want: []string{"claude-code"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newAdapterInstallLikeFlagSet()
			got := reorderArgsForFlagParse(fs, tc.args)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("reorderArgsForFlagParse(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestCmdAdapterInstall_FlagsAfterPositional is F13's documented failure
// case made concrete: `adapter install <name> --dry-run --dir <path>`
// must work exactly like `adapter install --dry-run --dir <path> <name>`.
// Before the fix, stdlib flag.Parse stopped at the first positional
// ("claude-code"), so --dry-run/--dir were never parsed as flags at all
// and fs.NArg() != 1 forced a usage error.
func TestCmdAdapterInstall_FlagsAfterPositional(t *testing.T) {
	dir := t.TempDir()
	code := cmdAdapterInstall([]string{"claude-code", "--dry-run", "--dir", dir})
	if code != 0 {
		t.Fatalf("cmdAdapterInstall with flags after the positional adapter name = exit %d, want 0", code)
	}
}
