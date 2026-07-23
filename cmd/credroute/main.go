// allow-claude-code: see internal/rules/glob.go header.
//
// Command credroute is a deterministic credential router for AI-agent CLI
// harnesses: given a context (directory, platform, task), it answers
// which identity, at which access level, and where its secret lives.
package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 1
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "resolve":
		return cmdResolve(rest)
	case "explain":
		return cmdExplain(rest)
	case "exec":
		return cmdExec(rest)
	case "config":
		if len(rest) == 0 || rest[0] != "validate" {
			fmt.Fprintln(os.Stderr, "credroute config: expected subcommand \"validate\"")
			return 1
		}
		return cmdConfigValidate(rest[1:])
	case "doctor":
		return cmdDoctor(rest)
	case "version":
		return cmdVersion(rest)
	case "-h", "--help", "help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "credroute: unknown command %q\n", cmd)
		printUsage()
		return 1
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `credroute - deterministic credential router for AI-agent CLI harnesses

Usage:
  credroute resolve --platform <name> [--dir <path>] [--task <tag>] [--json]
  credroute explain [--all] --platform <name> [--dir <path>] [--task <tag>] [--json]
  credroute exec [--platform <name>] [--dir <path>] [--task <tag>] -- <cmd> [args...]
  credroute config validate [path]
  credroute doctor
  credroute version

Global flags: --config <path>  --json  --quiet  -v

Exit codes: 0 ok, 1 usage error, 2 no rule matched (fail closed),
4 vault backend error, 5 config invalid.`)
}
