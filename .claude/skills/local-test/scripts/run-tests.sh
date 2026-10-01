#!/bin/bash
# Run a test command with its full output kept, and on failure print the
# failing tests and their panic messages.
#
# Usage: run-tests.sh <label> <command...>
#   run-tests.sh beacon-smoke cargo test -p moat-beacon --test smoke --no-fail-fast
#
# The log goes to $MOAT_TEST_LOGS (default /tmp/moat-test-logs). Use this
# instead of piping a test command through grep: a filter that keeps only the
# result lines throws away every panic message, and failures that do not
# repeat then cannot be diagnosed. `--no-fail-fast` keeps one failing test
# binary from hiding the ones after it.

set -uo pipefail

LABEL="${1:?usage: run-tests.sh <label> <command...>}"
shift

DIR="${MOAT_TEST_LOGS:-/tmp/moat-test-logs}"
mkdir -p "$DIR"
LOG="$DIR/$LABEL-$(date +%Y%m%d-%H%M%S).log"

export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

"$@" > "$LOG" 2>&1
rc=$?

if [[ $rc -eq 0 ]]; then
  echo "PASS  $LABEL  (log: $LOG)"
else
  echo "FAIL  $LABEL  rc=$rc  (log: $LOG)"
  "$(dirname "$0")/failure-summary.sh" "$LOG"
fi
exit $rc
