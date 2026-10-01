#!/bin/bash
# Print what failed in a test log, and why: the failing tests and their panic
# messages (libtest), compile errors, Flutter `[E]` blocks, Go `--- FAIL`
# lines. The panic message is the point. A Beacon test that dies in
# `world setup` names only the line that called `.expect(..)`; the cause is in
# the message after it.
#
# Usage: failure-summary.sh <logfile> [max-lines-per-failure]   (default 40)
#
# Read the log, not a grep of it: filtering `cargo test` output down to
# "test result" lines drops every panic message, and a failure that does not
# repeat then leaves nothing to investigate.

set -uo pipefail

LOG="${1:-}"
MAX="${2:-40}"
[[ -f "$LOG" ]] || { echo "usage: $0 <logfile> [max-lines]" >&2; exit 2; }

found=0

# libtest: the failing tests, then each one's panic block.
failed="$(sed -nE 's/^test (.*) \.\.\. FAILED$/\1/p' "$LOG" | sort -u)"
if [[ -n "$failed" ]]; then
  found=1
  echo "Failed tests:"
  echo "$failed" | sed 's/^/  /'
  awk -v max="$MAX" '
    /^---- .* stdout ----$/ { name = $2; inblock = 1; want = 0; shown = 0; printf "\n--- %s\n", name; next }
    /^failures:$/           { inblock = 0 }
    inblock && /panicked at/ { want = 1 }
    inblock && want {
      if (/^note: run with `RUST_BACKTRACE/) { want = 0; next }
      if (shown < max) { print "  " $0; shown++ }
      else if (shown == max) { print "  ... (truncated; see the full log)"; shown++ }
    }
  ' "$LOG"
fi

# Compile errors.
if grep -qE '^error(\[E[0-9]+\])?:' "$LOG"; then
  found=1
  echo
  echo "Compile errors:"
  awk -v max="$MAX" '
    /^error(\[E[0-9]+\])?:/ { want = 1; shown = 0 }
    want { if (shown < max) { print "  " $0; shown++ }; if ($0 == "") want = 0 }
  ' "$LOG"
fi

# Flutter: a failing test prints `[E]` and its error below.
if grep -q '\[E\]' "$LOG"; then
  found=1
  echo
  echo "Flutter failures:"
  grep -A "$MAX" -m 5 '\[E\]' "$LOG" | sed 's/^/  /'
fi

# Go.
if grep -qE '^(--- FAIL|panic:)' "$LOG"; then
  found=1
  echo
  echo "Go failures:"
  grep -E -A 8 '^(--- FAIL|panic:)' "$LOG" | sed 's/^/  /' | head -n "$((MAX * 2))"
fi

if [[ $found -eq 0 ]]; then
  echo "No recognised failure in $LOG; last lines:"
  tail -n 30 "$LOG" | sed 's/^/  /'
fi
