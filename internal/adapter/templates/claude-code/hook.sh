#!/usr/bin/env bash
# credroute PreToolUse hook (spec 8.2, F6 fix). This file is glue only,
# never logic (spec 8.1): Claude Code delivers the PreToolUse payload as
# JSON on stdin, and this script's only job is to pipe that straight into
# `credroute hook claude-code`, which does all the parsing, platform
# detection, and resolve/verify decision, then writes Claude Code's
# allow/deny decision JSON back to stdout with the matching exit code.
#
# The previous version of this file tried to read the command from $1 or
# $TOOL_INPUT_COMMAND; Claude Code never populates either for a PreToolUse
# hook, so it always saw an empty command and allowed everything through.
# Piping stdin through unchanged is what actually works.
#
# Wire this into .claude/settings.json as a PreToolUse hook on the Bash
# matcher.
set -euo pipefail

if ! command -v credroute >/dev/null 2>&1; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"credroute is not on PATH; refusing because the credential hook cannot verify this tool call"}}'
  exit 2
fi

exec credroute hook claude-code
