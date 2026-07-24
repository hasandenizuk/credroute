## Credential routing (credroute)

agy reads this file as default context. Every credentialed command
(Google, GitHub, or any other platform credroute has a route configured
for) must go through credroute, never the raw platform binary called
directly with a credential obtained some other way.

Before acting, check the route:

    credroute resolve --platform <name> [--task <tag>]

Exit 0 means proceed. Any non-zero exit means stop and report the
refusal to the operator; never work around it.

To actually run a credentialed tool:

    credroute exec --platform <name> [--task <tag>] -- <command> [args...]

Shims installed alongside this file under `shims/` already route common
tools (`gws`, `gh`) through `credroute exec` automatically when `shims/`
is earlier in PATH than the real binaries; prefer them over calling the
platform binary by an unshimmed path. credroute never prints a secret to
stdout by itself; do not repeat back or log any value it hands you.
