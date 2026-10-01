#!/bin/bash
# The verification gate: five consecutive clean sweeps of every suite.
#
# Usage: verification-gate.sh [runs]        (default 5)
#
# The repeat requirement is not ceremony. This programme has repeatedly found
# defects that pass a single run -- ring-inversion.md Phase 7 records a change
# that passed all 187 moat-core tests and then failed 2-5 of 8 beacon cells per
# run. A single green sweep is evidence, not a gate.
#
# Deliberately does NOT stop on failure: the useful output is which suite failed
# in which run, and whether it repeats. Each step's log is kept.
#
# BEACON_PARALLEL is left unset on purpose (see history-sync-remaining.md).
#
# Every step's full output is kept, and a failing step has its failing tests
# and panic messages printed into the summary beside the FAIL line. Failures
# that pass on rerun (a world that did not come up, a timeout under load)
# are only diagnosable from that first run's message.

set -uo pipefail

# Panics carry a backtrace in the kept logs.
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
RUNS="${1:-5}"
OUT="/tmp/moat-gate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.txt"

log() { echo "$*" | tee -a "$SUMMARY"; }

# 1-minute load average. A gate run starved of CPU produces timeouts that read
# as delivery failures, so the load has to be on the record next to each result:
# the 2026-09-27 run lost 29 minutes of one step to contention and the
# environment had to be inferred afterwards from missing wall-clock time.
load1() { uptime | sed -E 's/.*load averages?: *([0-9.]+).*/\1/'; }

# step <run> <name> <command...>
step() {
  local run="$1" name="$2"; shift 2
  local logfile="$OUT/run${run}-${name}.log"
  local t0=$SECONDS
  local l0; l0="$(load1)"
  if "$@" > "$logfile" 2>&1; then
    log "  PASS  $name  ($((SECONDS - t0))s, load ${l0}->$(load1))"
    return 0
  else
    local rc=$?
    log "  FAIL  $name  ($((SECONDS - t0))s, load ${l0}->$(load1), rc=$rc)  -> $logfile"
    echo "$run|$name|$rc|$logfile" >> "$OUT/failures.txt"
    # Why it failed, not just that it did.
    "$HERE/failure-summary.sh" "$logfile" | sed 's/^/      /' | tee -a "$SUMMARY"
    return 1
  fi
}

cd "$ROOT"

# Continuous load trace, so a contention window that straddles steps is visible
# rather than inferred. Killed with the script.
( while true; do echo "$(date +%H:%M:%S) $(uptime | sed -E 's/.*load averages?: *//')"; sleep 30; done ) > "$OUT/load.trace" 2>&1 &
TRACE_PID=$!
trap 'kill $TRACE_PID 2>/dev/null' EXIT

log "Verification gate: $RUNS runs"
log "Started  $(date)"
log "Output   $OUT"
log "Commit   $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)"
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  log "WARNING: tracked files are dirty -- the gate is meant to run on final code"
  git status --short --untracked-files=no | tee -a "$SUMMARY"
fi
log ""

# One web build up front: it is slow, it is not per-run, and a broken WASM
# build invalidates any Flutter result that follows it.
log "Pre-flight"
step 0 "flutter-build-web" bash -c 'cd moat-dart/app && flutter build web' || true
step 0 "cargo-build-workspace" cargo build --workspace --all-targets || true
step 0 "go-build-drawbridge" bash -c 'cd moat-drawbridge && go build ./...' || true
log ""

for run in $(seq 1 "$RUNS"); do
  log "=== Run $run/$RUNS  $(date +%H:%M:%S) ==="
  run_t0=$SECONDS

  step "$run" "moat-core"     cargo test -p moat-core --no-fail-fast
  step "$run" "moat-atproto"  cargo test -p moat-atproto --no-fail-fast
  step "$run" "moat-cli"      cargo test -p moat-cli --no-fail-fast
  step "$run" "moat-postern"  cargo test -p moat-postern --no-fail-fast
  step "$run" "ffi-crate"     bash -c 'cd moat-dart/app/rust && cargo test --no-fail-fast'
  step "$run" "flutter-test"  bash -c 'cd moat-dart/app && flutter test'
  step "$run" "drawbridge-go" bash -c 'cd moat-drawbridge && go test ./...'

  # Beacon last: it is the slowest and the most likely to find something, so a
  # failure lands with everything else already recorded for this run.
  step "$run" "moat-beacon"   cargo test -p moat-beacon --no-fail-fast

  log "  run $run total: $(( (SECONDS - run_t0) / 60 ))m"
  log ""
done

log "Finished $(date)"
log ""
if [[ -f "$OUT/failures.txt" ]]; then
  log "NOT MET -- $(wc -l < "$OUT/failures.txt" | tr -d ' ') failure(s):"
  while IFS='|' read -r run name rc logfile; do
    log "  run $run  $name  (rc=$rc)  $logfile"
  done < "$OUT/failures.txt"
else
  log "GATE MET: $RUNS consecutive clean runs."
fi
