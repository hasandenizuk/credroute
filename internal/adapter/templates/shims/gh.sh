#!/usr/bin/env bash
# credroute shim (spec 8.3/8.4): routes `gh` calls through
# `credroute exec` so a credentialed GitHub command cannot bypass the
# router just because an agent called `gh` directly. Install this
# earlier in PATH than the real `gh` binary. Glue only: all routing,
# verification, and secret handling stay in credroute itself.
set -euo pipefail
exec credroute exec --platform github -- gh "$@"
