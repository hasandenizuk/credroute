// allow-claude-code: see internal/rules/glob.go header.
package main

import (
	"fmt"
	"runtime"
)

// buildVersion and buildCommit can be overridden at build time with
// -ldflags "-X main.buildVersion=... -X main.buildCommit=...".
var (
	buildVersion = "0.1.0-milestone1"
	buildCommit  = "unknown"
)

func cmdVersion(_ []string) int {
	fmt.Printf("credroute %s (commit %s, %s)\n", buildVersion, buildCommit, runtime.Version())
	return 0
}
