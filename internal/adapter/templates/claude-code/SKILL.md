---
name: credroute
description: Route the correct credential identity and access level before any credentialed action (Google, GitHub, or any other configured platform). Use before OAuth, API-key, PAT, or token-based operations.
---

# credroute

Before any credentialed action, resolve the correct identity first:

    credroute resolve --platform <name> [--task <tag>] [--dir <path>]

Exit code 0 means proceed; act only then. Any non-zero exit means refuse:
do not fall back to the raw platform command with credentials found some
other way. Read the JSON `detail` field for the remediation hint:

- exit 2 = no route configured for this context; add a rule
- exit 3 = wrong identity in the slot; re-login needed
- exit 4 = vault backend error
- exit 5 = config invalid

To actually run a credentialed tool, wrap it instead of calling it
directly:

    credroute exec --platform <name> [--task <tag>] -- <command> [args...]

`credroute exec` resolves, decrypts, injects the secret into the child's
environment, runs the command, and scrubs. The secret never appears in
this conversation, in argv, or in any log; never print or repeat back a
value credroute hands you.

Before acting on a credentialed command, announce the identity so the
operator can see which account is about to be used, in the form:
`<identity> (<platform>, <access level>) via rule <rule id>`.

{{COMMAND_REFERENCE}}
