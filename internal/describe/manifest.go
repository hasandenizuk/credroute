// allow-claude-code: new multi-file build for the "agent-native command
// layer" milestone (roadmap.md section 4): the self-description /
// discovery half. `credroute describe` serves this manifest so an LLM
// harness discovers the command interface at runtime instead of guessing
// flag names from documentation that can go stale.
//
// Package describe is the single canonical manifest of every credroute
// command. Flag NAMES are mechanically cross-checked against the real
// flag.FlagSet each command registers (cmd/credroute/describe_test.go
// captures each real command's own --help output and diffs the flag
// names against this manifest), so a command whose flags this file
// forgets to update fails the test suite rather than silently drifting.
// Purpose text, parameter descriptions, "required"/"allowed values",
// examples, and exit codes are documentation the flag package has no way
// to express and are NOT mechanically checked; they are maintained here
// by hand and reviewed alongside the command they describe.
package describe

// Param describes one flag or positional argument.
type Param struct {
	// Name is the flag name without leading dashes (e.g. "platform"), or
	// a short label for a positional argument (e.g. "id").
	Name string `json:"name"`
	// Kind is "flag" or "positional".
	Kind string `json:"kind"`
	// Type is a hint for the value shape: string, bool, int,
	// repeated-string, or command (the "-- <cmd> <args...>" tail exec
	// hands to a child process).
	Type        string   `json:"type"`
	Required    bool     `json:"required"`
	Default     string   `json:"default,omitempty"`
	Allowed     []string `json:"allowed,omitempty"`
	Description string   `json:"description"`
}

// Command describes one credroute command or subcommand, addressed by
// its full invocation name (e.g. "identity add", "route ls").
type Command struct {
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	// Globals reports whether this command accepts the four global flags
	// (--config, --json, --quiet, -v; see GlobalParams). False only for
	// "hook claude-code" (its own narrower --config-only flag set),
	// "describe" (its own narrower --json-only flag set), and "version"
	// (no flags at all).
	Globals   bool              `json:"globals"`
	Params    []Param           `json:"params,omitempty"`
	Examples  []string          `json:"examples,omitempty"`
	ExitCodes map[string]string `json:"exit_codes,omitempty"`
}

// GlobalParams describes the four flags every Globals-true command
// accepts, documented once here instead of on every Command.
func GlobalParams() []Param {
	return []Param{
		{Name: "config", Kind: "flag", Type: "string", Description: "path to config.yaml (default: $CREDROUTE_CONFIG, else ~/.config/credroute/config.yaml)"},
		{Name: "json", Kind: "flag", Type: "bool", Description: "emit machine-readable JSON (default when stdout is not a terminal)"},
		{Name: "quiet", Kind: "flag", Type: "bool", Description: "suppress non-essential output"},
		{Name: "v", Kind: "flag", Type: "bool", Description: "verbose output"},
	}
}

// exitCodesRouting is the shared exit-code table for resolve and exec,
// spec section 4.3.
var exitCodesRouting = map[string]string{
	"0": "resolved (and verified, if verification is required)",
	"1": "usage or flag error",
	"2": "no rule matched: fail closed, there is no fallback identity",
	"3": "identity verification mismatch, or unverifiable under verify:on",
	"4": "vault backend error (missing handle, decrypt failure)",
	"5": "config invalid (schema, shadowed rules as hard errors, unknown identity referenced by a rule)",
}

var exitCodesLogin = map[string]string{
	"0":      "login completed and the guarded slot was verified or intentionally accepted",
	"1":      "usage or flag error",
	"2":      "no rule matched: fail closed, there is no fallback identity",
	"3":      "post-login identity mismatch, unverifiable under verify:on, or no write to the guarded slot",
	"4":      "vault, snapshot, restore, or login-slot filesystem error",
	"5":      "config invalid, unsafe login profile, ambiguous slot identity, or unauditable break-glass",
	"helper": "if the login helper exits non-zero, credroute login returns that same helper exit code",
}

var exitCodesUsageOnly = map[string]string{
	"0": "ok",
	"1": "usage or flag error",
}

var exitCodesUsageAndConfig = map[string]string{
	"0": "ok",
	"1": "usage or flag error",
	"5": "config invalid",
}

// Manifest returns every command in a stable, documented order (roughly
// the order in main.go's printUsage: setup, routing, introspection,
// editing, plumbing).
func Manifest() []Command {
	return manifest
}

// Lookup returns the command whose Name exactly matches name (e.g.
// "identity add"), and whether it was found.
func Lookup(name string) (Command, bool) {
	for _, c := range manifest {
		if c.Name == name {
			return c, true
		}
	}
	return Command{}, false
}

var manifest = []Command{
	{
		Name:    "init",
		Purpose: "First-run wizard: detect an existing vault directory, write a config.yaml skeleton, and prepare the machine key. Prompts interactively unless --yes is given.",
		Globals: true,
		Params: []Param{
			{Name: "yes", Kind: "flag", Type: "bool", Description: "non-interactive: scaffold from flags/env only, never prompt (required when stdin is not a terminal)"},
			{Name: "force", Kind: "flag", Type: "bool", Description: "overwrite an existing config file"},
			{Name: "vault-dir", Kind: "flag", Type: "string", Default: "~/vault", Description: "vault.age.store_dir"},
			{Name: "identity-file", Kind: "flag", Type: "string", Default: "~/.config/credroute/age-identity.txt", Description: "vault.age.identity_file"},
			{Name: "identity", Kind: "flag", Type: "string", Description: "optional: scaffold one identity, keyed by this id (usually an email)"},
			{Name: "identity-label", Kind: "flag", Type: "string", Description: "label for --identity"},
			{Name: "path", Kind: "positional", Type: "string", Description: "config file path (default: the usual resolution)"},
		},
		Examples: []string{"credroute init --yes --vault-dir ~/vault"},
		ExitCodes: map[string]string{
			"0": "wrote the config skeleton",
			"1": "usage error, or stdin is not a terminal without --yes, or the config already exists without --force",
		},
	},
	{
		Name:    "resolve",
		Purpose: "Answer which identity, access level, and vault handle apply for a platform in the current (or given) context, and whether the credential actually present has been verified. Metadata only; never touches a secret.",
		Globals: true,
		Params: []Param{
			{Name: "platform", Kind: "flag", Type: "string", Required: true, Description: "platform to resolve, e.g. google, github"},
			{Name: "task", Kind: "flag", Type: "string", Description: "task tag, e.g. gsc"},
			{Name: "dir", Kind: "flag", Type: "string", Description: "directory to resolve for (default: cwd)"},
			{Name: "verify", Kind: "flag", Type: "string", Allowed: []string{"on", "off"}, Description: "override verify mode for this call; tightens only, cannot loosen config"},
			{Name: "access", Kind: "flag", Type: "string", Allowed: []string{"read-only", "read-write"}, Description: "request an access level; refuses if the matched rule resolves to a different level"},
		},
		Examples:  []string{"credroute resolve --platform google --task gsc"},
		ExitCodes: exitCodesRouting,
	},
	{
		Name:    "explain",
		Purpose: "Dry-run trace of the rule engine for a context: which rule matched and why, or why each rule missed. Never touches the vault or verifies anything.",
		Globals: true,
		Params: []Param{
			{Name: "all", Kind: "flag", Type: "bool", Description: "show every rule, including ones after the winning match, with a MATCH/MISS reason per condition"},
			{Name: "platform", Kind: "flag", Type: "string", Required: true, Description: "platform to resolve"},
			{Name: "task", Kind: "flag", Type: "string", Description: "task tag"},
			{Name: "dir", Kind: "flag", Type: "string", Description: "directory to resolve for (default: cwd)"},
		},
		Examples:  []string{"credroute explain --all --platform google --dir ~/Projects/client.acme/project.audit --task gsc"},
		ExitCodes: exitCodesUsageAndConfig,
	},
	{
		Name:    "exec",
		Purpose: "Resolve, verify, decrypt, and run a command with the credential injected into its environment (or materialized at its slot). The secret never appears in argv, stdout, or the audit log.",
		Globals: true,
		Params: []Param{
			{Name: "platform", Kind: "flag", Type: "string", Description: "platform to resolve"},
			{Name: "task", Kind: "flag", Type: "string", Description: "task tag"},
			{Name: "dir", Kind: "flag", Type: "string", Description: "directory to resolve for (default: cwd)"},
			{Name: "access", Kind: "flag", Type: "string", Allowed: []string{"read-only", "read-write"}, Description: "request an access level; refuses if the matched rule resolves to a different level"},
			{Name: "export-generic", Kind: "flag", Type: "bool", Description: "also export the secret as the generic CREDROUTE_SECRET env var, even when a platform-specific var already carries it"},
			{Name: "check", Kind: "flag", Type: "bool", Description: "resolve and verify the credential without running a child command"},
			{Name: "cmd", Kind: "positional", Type: "command", Required: true, Description: "the command to run, after a literal --, e.g. \"-- gws gmail search ...\""},
		},
		Examples:  []string{"credroute exec --platform github --task deploy -- gh api user"},
		ExitCodes: exitCodesRouting,
	},
	{
		Name:    "login",
		Purpose: "Resolve the target identity, pin the platform login destination, snapshot the slot, run the profile login helper, then verify and roll back on unsafe outcomes.",
		Globals: true,
		Params: []Param{
			{Name: "platform", Kind: "flag", Type: "string", Required: true, Description: "platform to log in to, e.g. google"},
			{Name: "task", Kind: "flag", Type: "string", Description: "task tag used to choose scope set"},
			{Name: "dir", Kind: "flag", Type: "string", Description: "directory to resolve for (default: cwd)"},
			{Name: "expect", Kind: "flag", Type: "string", Description: "identity the operator expects; refuses if routing resolves a different identity"},
			{Name: "force", Kind: "flag", Type: "bool", Description: "audited override for login refusals that require operator acceptance"},
		},
		Examples:  []string{"credroute login --platform google --expect alex@example.com"},
		ExitCodes: exitCodesLogin,
	},
	{
		Name:    "verify",
		Purpose: "Probe (or re-check) the identity actually present in a credential slot right now, and record the observation to its attestation sidecar.",
		Globals: true,
		Params: []Param{
			{Name: "slot", Kind: "flag", Type: "string", Description: "verify the credential whose configured slot matches this path"},
			{Name: "platform", Kind: "flag", Type: "string", Description: "verify the credential resolve would pick for this platform (one of --slot or --platform is required)"},
			{Name: "task", Kind: "flag", Type: "string", Description: "task tag, used with --platform"},
			{Name: "dir", Kind: "flag", Type: "string", Description: "directory to resolve for, used with --platform (default: cwd)"},
			{Name: "accept-baseline", Kind: "flag", Type: "bool", Description: "deprecated alias for --force"},
			{Name: "force", Kind: "flag", Type: "bool", Description: "audited override for accepting a fingerprint-only baseline"},
		},
		Examples:  []string{"credroute verify --platform google", "credroute verify --platform stripe --force"},
		ExitCodes: map[string]string{"0": "verified or accepted baseline", "1": "usage error", "3": "mismatch, unconfirmed, or unreadable under a required check", "4": "vault backend error"},
	},
	{
		Name:    "config validate",
		Purpose: "Strict schema check plus semantic checks: enum values, dangling references, shadowed-rule detection, catch-all placement.",
		Globals: true,
		Params: []Param{
			{Name: "path", Kind: "positional", Type: "string", Description: "config file path (default: the usual resolution)"},
		},
		Examples:  []string{"credroute config validate"},
		ExitCodes: exitCodesUsageAndConfig,
	},
	{
		Name:      "doctor",
		Purpose:   "Environment health check: config validates, vault reachable, sidecar HMACs intact, sync conflicts, advisory (unprofiled) platforms, adapter installs.",
		Globals:   true,
		Examples:  []string{"credroute doctor"},
		ExitCodes: map[string]string{"0": "all checks green", "1": "one or more checks failed"},
	},
	{
		Name:      "profiles ls",
		Purpose:   "List every scope profile (built-in and user-supplied), with source, aliases, credential types, and access levels.",
		Globals:   true,
		Examples:  []string{"credroute profiles ls --json"},
		ExitCodes: exitCodesUsageOnly,
	},
	{
		Name:    "profiles show",
		Purpose: "Show one platform's full scope profile: identity probe, access levels and their scopes, exec_env, login helper.",
		Globals: true,
		Params: []Param{
			{Name: "task", Kind: "flag", Type: "string", Description: "show the scope set for this task/alias instead of the union"},
			{Name: "platform", Kind: "positional", Type: "string", Required: true, Description: "platform name, e.g. google, github"},
		},
		Examples:  []string{"credroute profiles show google --task gsc"},
		ExitCodes: exitCodesUsageOnly,
	},
	{
		Name:    "adapter install",
		Purpose: "Write the harness glue for one adapter: Claude Code (skill + PreToolUse hook), Codex (AGENTS.md + PATH shims), or agy (GEMINI.md + PATH shims). Never overwrites an existing file unless --force is given.",
		Globals: true,
		Params: []Param{
			{Name: "dir", Kind: "flag", Type: "string", Description: "target directory (default: the adapter's conventional location)"},
			{Name: "dry-run", Kind: "flag", Type: "bool", Description: "print what would be written without writing"},
			{Name: "force", Kind: "flag", Type: "bool", Description: "overwrite files that already exist"},
			{Name: "name", Kind: "positional", Type: "string", Required: true, Allowed: []string{"claude-code", "codex", "agy"}, Description: "which adapter to install"},
		},
		Examples:  []string{"credroute adapter install claude-code"},
		ExitCodes: exitCodesUsageOnly,
	},
	{
		Name:    "audit",
		Purpose: "Query the append-only audit log: every resolve/exec/verify/store operation, including refusals.",
		Globals: true,
		Params: []Param{
			{Name: "since", Kind: "flag", Type: "string", Description: "only show entries within this duration of now, e.g. 24h"},
			{Name: "platform", Kind: "flag", Type: "string", Description: "filter by platform"},
			{Name: "identity", Kind: "flag", Type: "string", Description: "filter by identity"},
			{Name: "client", Kind: "flag", Type: "string", Description: "filter by client"},
			{Name: "failures", Kind: "flag", Type: "bool", Description: "only show refused / non-zero-exit entries"},
		},
		Examples:  []string{"credroute audit --since 24h --failures"},
		ExitCodes: exitCodesUsageOnly,
	},
	{
		Name:    "identity add",
		Purpose: "Add a new identity to config.yaml (no platforms/credentials yet; add those with identity edit --add-credential). Validates and saves atomically; never persists an invalid config.",
		Globals: true,
		Params: []Param{
			{Name: "label", Kind: "flag", Type: "string", Description: "human-readable label for this identity"},
			{Name: "id", Kind: "positional", Type: "string", Required: true, Description: "identity id, usually an email"},
		},
		Examples:  []string{"credroute identity add alex@example.com --label 'Alex personal'"},
		ExitCodes: map[string]string{"0": "saved", "1": "usage error, or the identity already exists", "5": "the edited config would be invalid, nothing was saved"},
	},
	{
		Name:    "identity edit",
		Purpose: "Change an existing identity's label and/or add or replace one of its platform credentials.",
		Globals: true,
		Params: []Param{
			{Name: "label", Kind: "flag", Type: "string", Description: "replace this identity's label"},
			{Name: "add-credential", Kind: "flag", Type: "repeated-string", Description: "add or replace a credential: platform:access:type:vault-handle[#slot] (repeatable)"},
			{Name: "id", Kind: "positional", Type: "string", Required: true, Description: "identity id to edit"},
		},
		Examples:  []string{"credroute identity edit alex@example.com --add-credential google:read-only:oauth:age://google/alex/oauth-ro.json.age#~/.config/gws/profiles/personal-view"},
		ExitCodes: map[string]string{"0": "saved", "1": "usage error, unknown identity, or nothing to do", "5": "the edited config would be invalid, nothing was saved"},
	},
	{
		Name:    "route add",
		Purpose: "Append a new rule to rules[]. Inserted before a trailing catch-all rule by default, since a catch-all is only legal as the final rule.",
		Globals: true,
		Params: []Param{
			{Name: "client", Kind: "flag", Type: "string", Description: "match.client"},
			{Name: "dir", Kind: "flag", Type: "string", Description: "match.dir glob"},
			{Name: "platform", Kind: "flag", Type: "repeated-string", Description: "match.platform (repeatable for a list)"},
			{Name: "task", Kind: "flag", Type: "repeated-string", Description: "match.task (repeatable for a list)"},
			{Name: "identity", Kind: "flag", Type: "string", Required: true, Description: "use.identity"},
			{Name: "access", Kind: "flag", Type: "string", Required: true, Allowed: []string{"read-only", "read-write"}, Description: "use.access"},
			{Name: "verify", Kind: "flag", Type: "string", Allowed: []string{"on", "off"}, Description: "use.verify override (default: inherit defaults.verify)"},
			{Name: "index", Kind: "flag", Type: "int", Default: "-1", Description: "0-based insert position; -1 means the smart default described above"},
			{Name: "id", Kind: "positional", Type: "string", Required: true, Description: "rule id"},
		},
		Examples:  []string{"credroute route add acme-gsc --client acme --platform google --task gsc --identity reports@acme-corp.com --access read-only"},
		ExitCodes: map[string]string{"0": "saved", "1": "usage error, or --identity/--access missing", "5": "the edited config would be invalid, nothing was saved"},
	},
	{
		Name:    "route assign",
		Purpose: "Change an existing rule's use{} block: identity, access level, and/or verify override.",
		Globals: true,
		Params: []Param{
			{Name: "identity", Kind: "flag", Type: "string", Description: "new use.identity"},
			{Name: "access", Kind: "flag", Type: "string", Allowed: []string{"read-only", "read-write"}, Description: "new use.access"},
			{Name: "verify", Kind: "flag", Type: "string", Allowed: []string{"on", "off", ""}, Description: "new use.verify; pass an empty value to clear the override back to defaults.verify"},
			{Name: "id", Kind: "positional", Type: "string", Required: true, Description: "rule id to edit"},
		},
		Examples:  []string{"credroute route assign acme-gsc --access read-write"},
		ExitCodes: map[string]string{"0": "saved", "1": "usage error, unknown rule id, or nothing to do", "5": "the edited config would be invalid, nothing was saved"},
	},
	{
		Name:      "route ls",
		Purpose:   "List every rule in order, with its match summary and use{} outcome.",
		Globals:   true,
		Examples:  []string{"credroute route ls --json"},
		ExitCodes: exitCodesUsageAndConfig,
	},
	{
		Name:    "store add",
		Purpose: "Encrypt a secret into the optional thin store (must be enabled in config.yaml) and print the resulting store:// handle. The secret is read from --from-file, --from-fd, a pipe, or a prompt, never from argv.",
		Globals: true,
		Params: []Param{
			{Name: "from-file", Kind: "flag", Type: "string", Description: "read the secret from this file instead of stdin/prompt"},
			{Name: "from-fd", Kind: "flag", Type: "int", Description: "read the secret from this already-open file descriptor instead of stdin/prompt"},
			{Name: "force", Kind: "flag", Type: "bool", Description: "overwrite if a secret already exists at this path"},
			{Name: "path", Kind: "positional", Type: "string", Required: true, Description: "relative path under the store, e.g. github/me/pat"},
		},
		Examples:  []string{"credroute store add github/me/pat --from-file ./pat.txt"},
		ExitCodes: map[string]string{"0": "stored", "1": "usage error, the store is not enabled, or the path already has a secret without --force", "4": "vault backend error", "5": "config invalid"},
	},
	{
		Name:      "store ls",
		Purpose:   "List every handle currently in the thin store.",
		Globals:   true,
		Examples:  []string{"credroute store ls --json"},
		ExitCodes: map[string]string{"0": "ok", "1": "usage error, or the store is not enabled", "4": "vault backend error", "5": "config invalid"},
	},
	{
		Name:    "store remove",
		Purpose: "Delete a secret from the thin store.",
		Globals: true,
		Params: []Param{
			{Name: "force", Kind: "flag", Type: "bool", Description: "do not error if the secret does not exist"},
			{Name: "path", Kind: "positional", Type: "string", Required: true, Description: "relative path under the store"},
		},
		Examples:  []string{"credroute store remove github/me/pat"},
		ExitCodes: map[string]string{"0": "removed", "1": "usage error, or the store is not enabled", "4": "filesystem error", "5": "config invalid"},
	},
	{
		Name:    "describe",
		Purpose: "Emit this manifest: every command's purpose, parameters, examples, and exit codes, so an agent discovers the interface at runtime instead of guessing.",
		Globals: false,
		Params: []Param{
			{Name: "json", Kind: "flag", Type: "bool", Description: "emit JSON instead of the human-readable listing"},
			{Name: "command", Kind: "positional", Type: "string", Description: "show only this command (matched by name, e.g. \"identity add\")"},
		},
		Examples:  []string{"credroute describe --json", "credroute describe \"route add\""},
		ExitCodes: map[string]string{"0": "ok", "1": "named command not found"},
	},
	{
		Name:    "handle get",
		Purpose: "Plumbing secret retrieval for adapters that must place a secret themselves. Deliberately hard to misuse: printing to stdout requires --force-reveal AND a real terminal.",
		Globals: true,
		Params: []Param{
			{Name: "to-file", Kind: "flag", Type: "string", Description: "write the secret to this path (0600 perms), instead of stdout"},
			{Name: "to-fd", Kind: "flag", Type: "int", Description: "write the secret to this open file descriptor, instead of stdout"},
			{Name: "force-reveal", Kind: "flag", Type: "bool", Description: "allow printing the secret to stdout; still refused without a real terminal and an interactive \"yes\""},
			{Name: "allow-unmodeled-handle", Kind: "flag", Type: "bool", Description: "break-glass: retrieve a vault handle that is not modeled in config"},
			{Name: "handle", Kind: "positional", Type: "string", Required: true, Description: "vault handle, e.g. age://google/me/oauth-ro.json.age"},
		},
		Examples:  []string{"credroute handle get age://github/me/pat.age --to-fd 3"},
		ExitCodes: map[string]string{"0": "ok", "1": "usage error, or reveal refused", "3": "verification refusal, ambiguous handle, or unmodeled handle without break-glass", "4": "vault backend error", "5": "config invalid"},
	},
	{
		Name:    "hook claude-code",
		Purpose: "Reads a Claude Code PreToolUse hook payload as JSON on stdin, extracts a Bash command, and decides allow/deny by calling the same resolve logic exec/resolve use. Installed by `adapter install claude-code`.",
		Globals: false,
		Params: []Param{
			{Name: "config", Kind: "flag", Type: "string", Description: "path to config.yaml (default: $CREDROUTE_CONFIG, else ~/.config/credroute/config.yaml)"},
		},
		Examples:  []string{"echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"gws gmail search\"}}' | credroute hook claude-code"},
		ExitCodes: map[string]string{"0": "decision printed on stdout (allow or deny; the JSON payload itself carries the verdict, not the process exit code)"},
	},
	{
		Name:      "version",
		Purpose:   "Print the build version, commit, and Go runtime version.",
		Globals:   false,
		Examples:  []string{"credroute version"},
		ExitCodes: map[string]string{"0": "ok"},
	},
}
