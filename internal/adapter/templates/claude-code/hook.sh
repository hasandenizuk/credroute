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
  # credroute not installed/on PATH: fail open rather than block every
  # tool call in a session where the router isn't set up yet.
  exit 0
fi

exec credroute hook claude-code
