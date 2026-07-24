// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// buildVersion and buildCommit are stamped by the release workflow with
// -ldflags "-X main.buildVersion=... -X main.buildCommit=...". They are
// empty in every other build (go build, go install, go run), where the
// values come from the module build info instead.
var (
	buildVersion = ""
	buildCommit  = ""
)

// versionInfo reports the version and commit to display, preferring the
// linker-stamped values and falling back to what the toolchain recorded.
func versionInfo() (version, commit string) {
	version, commit = buildVersion, buildCommit
	if version == "" || commit == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
				version = strings.TrimPrefix(info.Main.Version, "v")
			}
			if commit == "" {
				for _, setting := range info.Settings {
					if setting.Key != "vcs.revision" {
						continue
					}
					commit = setting.Value
					if len(commit) > 7 {
						commit = commit[:7]
					}
				}
			}
		}
	}
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "unknown"
	}
	return version, commit
}

func cmdVersion(_ []string) int {
	version, commit := versionInfo()
	fmt.Printf("credroute %s (commit %s, %s)\n", version, commit, runtime.Version())
	return 0
}
