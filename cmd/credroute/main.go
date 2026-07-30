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
	case "login":
		return cmdLogin(rest)
	case "verify":
		return cmdVerify(rest)
	case "config":
		if len(rest) == 0 || rest[0] != "validate" {
			fmt.Fprintln(os.Stderr, "credroute config: expected subcommand \"validate\"")
			return 1
		}
		return cmdConfigValidate(rest[1:])
	case "doctor":
		return cmdDoctor(rest)
	case "init":
		return cmdInit(rest)
	case "profiles":
		return cmdProfiles(rest)
	case "adapter":
		return cmdAdapter(rest)
	case "audit":
		return cmdAudit(rest)
	case "identity":
		return cmdIdentity(rest)
	case "route":
		return cmdRoute(rest)
	case "store":
		return cmdStore(rest)
	case "describe":
		return cmdDescribe(rest)
	case "handle":
		if len(rest) == 0 || rest[0] != "get" {
			fmt.Fprintln(os.Stderr, "credroute handle: expected subcommand \"get\"")
			return 1
		}
		return cmdHandleGet(rest[1:])
	case "hook":
		return cmdHook(rest)
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
  credroute init [--yes] [--config <path>] [--vault-dir <path>] [--identity-file <path>] [--identity <id>]
  credroute resolve --platform <name> [--dir <path>] [--task <tag>] [--access <level>] [--verify=on|off] [--json]
  credroute explain [--all] --platform <name> [--dir <path>] [--task <tag>] [--json]
  credroute exec [--platform <name>] [--dir <path>] [--task <tag>] [--access <level>] [--export-generic] -- <cmd> [args...]
  credroute login --platform <name> [--dir <path>] [--task <tag>] [--expect <identity>] [--force] [--json]
  credroute verify [--slot <path> | --platform <name> [--dir <path>] [--task <tag>]] [--force] [--json]
  credroute config validate [path]
  credroute doctor
  credroute profiles ls [--json]
  credroute profiles show <platform> [--task <tag>] [--json]
  credroute adapter install <claude-code|codex|agy> [--dir <path>] [--dry-run] [--force]
  credroute audit [--since <dur>] [--platform <name>] [--identity <id>] [--client <name>] [--failures] [--json]
  credroute identity add <id> [--label <text>]
  credroute identity edit <id> [--label <text>] [--add-credential platform:access:type:vault-handle[#slot] ...]
  credroute route add <rule-id> [--client <name> | --dir <glob>] [--platform <p> ...] [--task <t> ...] --identity <id> --access <level> [--verify <mode>] [--index <n>]
  credroute route assign <rule-id> [--identity <id>] [--access <level>] [--verify <mode>]
  credroute route ls [--json]
  credroute store add <path> [--from-file <path> | --from-fd <n>] [--force]
  credroute store ls [--json]
  credroute store remove <path> [--force]
  credroute describe [--json] [<command>]
  credroute handle get <vault-handle> [--allow-unmodeled-handle] [--to-file <path> | --to-fd <n> | --force-reveal]
  credroute hook claude-code   (reads PreToolUse JSON on stdin, F6)
  credroute version

Flags may appear anywhere on the command line, before or after positional
arguments (e.g. "handle get <handle> --to-file x" and "adapter install
<name> --force" both work).

Global flags: --config <path>  --json  --quiet  -v

Environment: CREDROUTE_CONFIG overrides the default config path when
--config is not given. CREDROUTE_NO_NETWORK=1 disables every live
identity-verification probe (used by tests; never set this for real use).

Exit codes: 0 ok, 1 usage error, 2 no rule matched (fail closed),
3 identity verification mismatch or unverifiable under verify:on,
4 vault backend error, 5 config invalid.`)
}
