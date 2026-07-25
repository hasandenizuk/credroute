#!/usr/bin/env bash
#
# scan-private-data.sh - refuse to publish personal paths or secret material.
#
# credroute exists so that a credential never reaches somewhere it was not meant
# to go. A public repository is one of those places, and it is a one-way door:
# once a tagged version is fetched by a module proxy or cloned by anyone, that
# copy is permanent. Deleting a release, a tag, or the history afterwards does
# not recall it. So the check has to run before the push.
#
# How it decides. Rules below match the SHAPE of a leak: a home directory, a
# path into someone's own document tree, an API key, a mailbox. A repository
# like this one legitimately contains many such strings as examples, so a match
# alone is not a finding. A match is a finding when it is not listed in the
# baseline file, scripts/private-data-baseline.txt. That inverts the usual
# problem: the scanner does not have to guess which paths are real, it only has
# to notice that a string nobody has accepted before is about to be published.
# Accepting a new one is a deliberate, reviewable edit to a tracked file.
#
# Site-specific identifiers - your username, machine names, employer or client
# names - must NOT be written into this repository, because that publishes the
# thing they protect. Put them one regex per line in a file outside the repo and
# point CREDROUTE_PRIVACY_PATTERNS at it. Those patterns have no baseline: any
# match is a finding.
#
# What it does not catch. This is a guardrail, not a cage, and it is worth being
# plain about the edges: a secret split across two lines is invisible to it,
# because the search is line by line. A path that names a real client or employer
# but has no ~/ or /home prefix is only caught if you have set up the private
# pattern file. Anyone can pass --no-verify. It raises the floor; it does not
# make a leak impossible.
#
# Modes:
#   --tree             every tracked file (default; used by CI)
#   --staged           what is staged for commit
#   --range A..B       lines added between two commits
#   --pre-push         read the push plan on stdin, scan each commit being sent
#   --baseline         print the findings as a baseline file, for seeding
#   --install-hook     write .git/hooks/pre-push in this repository
#
# Exit codes: 0 clean, 1 findings, 2 usage or environment error.

set -uo pipefail

PRIVATE_PATTERNS_FILE="${CREDROUTE_PRIVACY_PATTERNS:-$HOME/.config/credroute/privacy-patterns.txt}"
BASELINE_NAME="scripts/private-data-baseline.txt"

# --- leak shapes --------------------------------------------------------------
#
# "name|regex". Each regex is written so it cannot match its own source text,
# otherwise this file reports itself.

RULES=(
  "home-directory|/(home|Users)/[A-Za-z0-9._-]+"
  "windows-home|C:\\\\+Users\\\\+[A-Za-z0-9._-]+"
  "personal-path|~/[A-Za-z0-9._/-]+"
  "age-secret-key|AGE-SECRET-KEY-1[0-9A-Za-z]{20,}"
  "private-key-block|BEGIN[A-Z ]*PRIVATE KEY"
  "github-token|gh[pousr]_[A-Za-z0-9]{36,}"
  "github-fine-grained-token|github_pat_[A-Za-z0-9_]{50,}"
  "slack-token|xox[abposr]-[A-Za-z0-9-]{10,}"
  "anthropic-key|sk-ant-[A-Za-z0-9_-]{20,}"
  "openai-key|sk-[A-Za-z0-9]{40,}"
  "stripe-live-key|[sr]k_live_[A-Za-z0-9]{20,}"
  "google-api-key|AIza[A-Za-z0-9_-]{30,}"
  "aws-access-key|AKIA[0-9A-Z]{16}"
  "gitlab-token|glpat-[A-Za-z0-9_-]{20,}"
  "slack-webhook|hooks[.]slack[.]com/services/[A-Za-z0-9/]+"
)

# Secret material is never baselined: a real key in the tree is a finding even if
# somebody added it to the baseline by mistake.
NEVER_BASELINE='^(age-secret-key|private-key-block|github-token|github-fine-grained-token|slack-token|anthropic-key|openai-key|stripe-live-key|google-api-key|aws-access-key|gitlab-token|slack-webhook)$'

# Only this scanner's own baseline is exempt by name. Nothing else is skipped on
# the strength of its filename: an extension list is trivially defeated by naming
# a text file notes.png, and the tree scan is the mode CI and the release gate
# rely on. Binary files are recognised by their content instead, in scan_tree.
SKIP_PATHS="^(${BASELINE_NAME})$"

usage() {
  cat >&2 <<'USAGE'
usage: scan-private-data.sh [--tree | --staged | --range A..B | --pre-push | --baseline | --install-hook]
Refuses to publish personal paths or secret material. See the comments at the
top of this script for how the baseline works.
USAGE
  exit 2
}

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || {
    echo "scan-private-data: not inside a git repository" >&2
    exit 2
  }
}

# Findings are printed masked. This runs in CI, and CI logs on a public
# repository are public: a scanner that echoed the key it just found would leak
# it further than the commit did.
mask() {
  local s="$1"
  local n=${#s}
  if (( n <= 8 )); then
    printf '%s<masked>' "${s:0:2}"
  else
    printf '%s<masked:%d chars>' "${s:0:4}" "$n"
  fi
}

# Held as newline-delimited text rather than an associative array: macOS still
# ships bash 3.2, which has no associative arrays, and the pre-push hook has to
# work on whatever bash the contributor has.
BASELINE_ENTRIES=""
load_baseline() {
  local root file line
  root="$(repo_root)"
  file="$root/$BASELINE_NAME"
  [[ -r "$file" ]] || return 0
  while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    BASELINE_ENTRIES="$BASELINE_ENTRIES$line"$'\n'
  done < "$file"
}

is_baselined() {
  [[ -n "$BASELINE_ENTRIES" ]] || return 1
  printf '%s' "$BASELINE_ENTRIES" | grep -Fxq -- "$1"
}

PRIVATE_PATTERNS=()
load_private_patterns() {
  [[ -r "$PRIVATE_PATTERNS_FILE" ]] || return 0
  local line
  while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    PRIVATE_PATTERNS+=("$line")
  done < "$PRIVATE_PATTERNS_FILE"
}

FINDINGS=0
EMIT_BASELINE=0
OMITTED=0

report() {
  local label="$1" name="$2" match="$3"
  FINDINGS=$((FINDINGS + 1))
  if (( EMIT_BASELINE )); then
    # Secret material is never a baseline candidate, so it is never printed in
    # the clear here either: this mode's output is meant to be pasted into a
    # tracked file, and it lands in a terminal's scrollback on the way.
    if printf '%s' "$name" | grep -qE -- "$NEVER_BASELINE"; then
      OMITTED=$((OMITTED + 1))
      return
    fi
    printf '%s\n' "$match"
  else
    printf '  %s: %s -> %s\n' "$label" "$name" "$(mask "$match")" >&2
  fi
}

# scan_text <label>, text on stdin
scan_text() {
  local label="$1" text rule name regex match
  text="$(cat)"
  [[ -n "$text" ]] || return 0

  for rule in "${RULES[@]}"; do
    name="${rule%%|*}"
    regex="${rule#*|}"
    while IFS= read -r match; do
      [[ -n "$match" ]] || continue
      if ! is_baselined "$match" || printf '%s' "$name" | grep -qE -- "$NEVER_BASELINE"; then
        report "$label" "$name" "$match"
      fi
    done < <(printf '%s\n' "$text" | grep -oE -- "$regex" | sort -u)
  done

  for regex in ${PRIVATE_PATTERNS[@]+"${PRIVATE_PATTERNS[@]}"}; do
    while IFS= read -r match; do
      [[ -n "$match" ]] || continue
      report "$label" "site-private-pattern" "$match"
    done < <(printf '%s\n' "$text" | grep -oE -- "$regex" | sort -u)
  done
}

scan_tree() {
  local root file
  root="$(repo_root)"
  # -z, and a NUL-delimited read, so a pathname containing a space or a newline
  # arrives intact rather than being quoted by git and then silently skipped.
  while IFS= read -r -d '' file; do
    printf '%s' "$file" | grep -qE -- "$SKIP_PATHS" && continue
    [[ -f "$root/$file" ]] || continue
    # Skip genuine binaries by looking at their bytes, not their name.
    grep -Iq . "$root/$file" 2>/dev/null || continue
    scan_text "$file" < "$root/$file"
  done < <(git -C "$root" ls-files -z)
}

added_lines() { grep '^+' | grep -v '^+++'; }

# scan_text must never sit on the right-hand side of a pipe: bash would run it in
# a subshell and the finding count would be discarded when that subshell exits,
# so a leak would be printed and the push would still succeed. Feed it with
# process substitution instead, which keeps it in this shell.
scan_staged() {
  scan_text "staged" < <(git diff --cached --unified=0 --no-color -- . | added_lines)
}

scan_range() {
  scan_text "$1" < <(git diff --unified=0 --no-color "$1" -- . | added_lines)
}

# git supplies the push plan on stdin: <local-ref> <local-sha> <remote-ref> <remote-sha>
scan_pre_push() {
  local zero="0000000000000000000000000000000000000000"
  local local_ref local_sha remote_ref remote_sha scanned=0 delta
  while read -r local_ref local_sha remote_ref remote_sha; do
    [[ "$local_sha" == "$zero" ]] && continue      # ref being withdrawn
    scanned=1
    if [[ "$remote_sha" == "$zero" ]]; then
      # New branch or tag: every commit the remote has not seen. Tags usually
      # point at already-pushed commits, which leaves nothing here, so the tree
      # is scanned as well - a tag is exactly what a module proxy keeps forever.
      if delta="$(git log -p --unified=0 --no-color "$local_sha" --not --remotes -- . 2>/dev/null)"; then
        scan_text "${local_ref#refs/}" < <(printf '%s\n' "$delta" | added_lines)
      fi
      scan_tree
    else
      # If the delta cannot be computed - the remote sha is a commit this clone
      # does not have, after a force-push or a collected ref - git writes nothing
      # to stdout. Treating that silence as "clean" would let the push through
      # unscanned, so fall back to reading the whole tree instead.
      if delta="$(git diff --unified=0 --no-color "$remote_sha..$local_sha" -- . 2>/dev/null)"; then
        scan_text "${local_ref#refs/}" < <(printf '%s\n' "$delta" | added_lines)
      else
        echo "scan-private-data: cannot diff against $remote_sha; scanning the whole tree instead" >&2
        scan_tree
      fi
    fi
  done
  (( scanned == 0 )) && scan_tree
  return 0
}

install_hook() {
  local root hook
  root="$(repo_root)"
  hook="$root/.git/hooks/pre-push"
  if [[ -e "$hook" ]] && ! grep -q 'scan-private-data.sh' "$hook"; then
    echo "scan-private-data: $hook exists and is not ours; leaving it alone." >&2
    echo "Add this line to it yourself: scripts/scan-private-data.sh --pre-push" >&2
    exit 2
  fi
  cat > "$hook" <<'HOOK'
#!/usr/bin/env bash
# Installed by scripts/scan-private-data.sh --install-hook
exec "$(git rev-parse --show-toplevel)/scripts/scan-private-data.sh" --pre-push
HOOK
  chmod +x "$hook"
  echo "scan-private-data: installed $hook"
  if [[ ! -r "$PRIVATE_PATTERNS_FILE" ]]; then
    cat >&2 <<EOF

WARNING: no site-private pattern file at
  $PRIVATE_PATTERNS_FILE

Without it the hook only recognises paths starting with a tilde or a home
directory. Your
username, your machine names and your clients' names are NOT being checked for.
Put them there, one regex per line, so they are guarded without ever being
written into this repository. Set CREDROUTE_PRIVACY_PATTERNS to use another path.
EOF
  fi
  exit 0
}

main() {
  local mode="${1:---tree}"

  case "$mode" in
    --baseline) EMIT_BASELINE=1; mode="--tree" ;;
    --install-hook) load_private_patterns; install_hook ;;
    -h|--help) usage ;;
  esac

  load_baseline
  load_private_patterns

  case "$mode" in
    --tree)     scan_tree ;;
    --staged)   scan_staged ;;
    --range)    [[ $# -ge 2 ]] || usage; scan_range "$2" ;;
    --pre-push) scan_pre_push ;;
    *) usage ;;
  esac

  if (( EMIT_BASELINE )); then
    if (( OMITTED > 0 )); then
      echo "scan-private-data: $OMITTED secret-shaped match(es) withheld; those can never be baselined." >&2
    fi
    return 0
  fi

  if (( FINDINGS > 0 )); then
    cat >&2 <<EOF

scan-private-data: $FINDINGS finding(s). Push refused.

Publishing is a one-way door: a module proxy or a clone keeps its copy of a
tagged version permanently, so a personal path or a key cannot be recalled
afterwards by deleting a tag, a release, or the history.

If a finding is real, take it out of the commit. If it is another placeholder,
add the exact string to $BASELINE_NAME and say in the commit why it is safe.
Emergency override: git push --no-verify
EOF
    return 1
  fi

  echo "scan-private-data: clean"
  return 0
}

main "$@"
