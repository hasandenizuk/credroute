#!/usr/bin/env bash
# credroute PreToolUse hook (spec 8.2): detects credential-shaped Bash
# commands and runs `credroute resolve --quiet` before allowing them
# through. Exit 2 or 3 from credroute denies the tool call with a
# remediation hint; exit 0 allows it. This adapter is glue only, never
# logic: all routing and verification stay in the credroute binary.
#
# Wire this into .claude/settings.json as a PreToolUse hook on the Bash
# matcher. It reads the attempted command as $1 (or on stdin, harness
# dependent) and infers a platform from a short detection list; unknown
# commands are allowed through untouched (fail open outside a route the
# operator has actually configured).
set -euo pipefail

COMMAND="${1:-${TOOL_INPUT_COMMAND:-}}"
PLATFORM=""

case "$COMMAND" in
  *gws*|*gmail*|*gdrive*|*google*|*gtm-ga4*) PLATFORM="google" ;;
  *"gh "*|*"git push"*|*github*) PLATFORM="github" ;;
esac

if [ -z "$PLATFORM" ]; then
  # Not a credentialed command credroute knows about: allow through.
  exit 0
fi

if ! command -v credroute >/dev/null 2>&1; then
  # credroute not installed/on PATH: fail open rather than block every
  # credentialed command in a session where the router isn't set up yet.
  exit 0
fi

credroute resolve --platform "$PLATFORM" --quiet
status=$?
if [ "$status" -eq 0 ]; then
  exit 0
fi

echo "credroute: refused ($PLATFORM, exit $status). Run \`credroute resolve --platform $PLATFORM\` for the remediation detail." >&2
exit "$status"
