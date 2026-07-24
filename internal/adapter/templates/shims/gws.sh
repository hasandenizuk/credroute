#!/usr/bin/env bash
# credroute shim (spec 8.3/8.4): routes `gws` calls through
# `credroute exec` so a credentialed Google command cannot bypass the
# router just because an agent called `gws` directly. Install this
# earlier in PATH than the real `gws` binary. Glue only: all routing,
# verification, and secret handling stay in credroute itself.
set -euo pipefail
exec credroute exec --platform google -- gws "$@"
