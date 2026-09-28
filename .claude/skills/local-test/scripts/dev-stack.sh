#!/bin/bash
# Local manual-testing stack: Postern (PDS) + Drawbridge (relay).
# dev-stack.sh --help for services, accounts and how to drive devices.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
RUN_DIR="/tmp/moat-dev-stack"
POSTERN_PORT=4000
RELAY_PORT=8080

mkdir -p "$RUN_DIR"

start() {
  if [[ -f "$RUN_DIR/postern.pid" ]] && kill -0 "$(cat "$RUN_DIR/postern.pid")" 2>/dev/null; then
    echo "Stack already up. './scripts/dev-stack.sh down' first."
    exit 1
  fi

  echo "Building..."
  # Two invocations on purpose: a --bin filter applies to the whole command,
  # so combining these silently skips moat-cli's `moat` binary and leaves
  # devices running stale code.
  (cd "$ROOT" && cargo build -q -p moat-postern --bin dev_server)
  (cd "$ROOT" && cargo build -q -p moat-cli --bin moat)
  (cd "$ROOT/moat-drawbridge" && go build -o "$RUN_DIR/drawbridge" ./...)

  echo "Starting Postern on :${POSTERN_PORT}..."
  DRAWBRIDGE_URL="ws://127.0.0.1:$RELAY_PORT/ws" \
    "$ROOT/target/debug/dev_server" "$POSTERN_PORT" > "$RUN_DIR/postern.log" 2>&1 &
  echo $! > "$RUN_DIR/postern.pid"

  # describeServer is the readiness signal: it is the endpoint clients hit first.
  until curl -sf "http://127.0.0.1:$POSTERN_PORT/xrpc/com.atproto.server.describeServer" >/dev/null; do
    sleep 0.2
  done

  echo "Starting Drawbridge on :${RELAY_PORT}..."
  RELAY_TLS=false \
  RELAY_ADDR=":$RELAY_PORT" \
  RELAY_PUBLIC_URL="ws://127.0.0.1:$RELAY_PORT" \
  LOG_FORMAT=text \
  PLC_BASE_URL="http://127.0.0.1:$POSTERN_PORT" \
    "$RUN_DIR/drawbridge" > "$RUN_DIR/drawbridge.log" 2>&1 &
  echo $! > "$RUN_DIR/drawbridge.pid"

  until curl -sf "http://127.0.0.1:$RELAY_PORT/health" >/dev/null; do sleep 0.2; done

  cat <<EOF

Stack up.

  Postern      http://127.0.0.1:$POSTERN_PORT   (emulator: http://10.0.2.2:$POSTERN_PORT)
  Drawbridge   ws://127.0.0.1:$RELAY_PORT/ws    (advertised via describeServer)
  Logs         $RUN_DIR/{postern,drawbridge}.log

'$0 --help' for how to drive devices against it.

EOF
}

usage() {
  cat <<EOF
Local manual-testing stack: Postern (PDS) + Drawbridge (relay).

  $0 up      build and start both services (default)
  $0 down    stop them
  $0 logs    tail both logs
  $0 --help  this message

Services
  Postern      http://127.0.0.1:$POSTERN_PORT   (emulator: http://10.0.2.2:$POSTERN_PORT)
  Drawbridge   ws://127.0.0.1:$RELAY_PORT/ws    (advertised via describeServer)
  Logs         $RUN_DIR/{postern,drawbridge}.log
  PID files    $RUN_DIR/{postern,drawbridge}.pid

Accounts — any password, Postern does not validate one:
  alice.postern.test   did:plc:alice-dev
  bob.postern.test     did:plc:bob-dev

Device state dirs are NOT managed here. Give each device its own -s dir so
they hold separate keys, and delete them between passes for a clean slate:
  rm -rf /tmp/moat-alice /tmp/moat-bob1 /tmp/moat-bob2

Start a device (TUI):
  cargo run -p moat-cli -- -s /tmp/moat-alice --pds-url http://127.0.0.1:$POSTERN_PORT

Start a device (headless HTTP API) — one port per device:
  cargo run -p moat-cli -- -s /tmp/moat-alice --pds-url http://127.0.0.1:$POSTERN_PORT \\
    --http 127.0.0.1:9101
  cargo run -p moat-cli -- -s /tmp/moat-bob1  --pds-url http://127.0.0.1:$POSTERN_PORT \\
    --http 127.0.0.1:9102

  HTTP devices start logged out; log in explicitly (any password):
    curl -s -X POST http://127.0.0.1:9101/login \\
      -H 'Content-Type: application/json' \\
      -d '{"handle":"alice.postern.test","password":"x"}'

  The recipient must watch the inviter's repo or the invite is never seen:
    curl -s -X POST http://127.0.0.1:9102/watch \\
      -H 'Content-Type: application/json' -d '{"handle":"alice.postern.test"}'

  Useful endpoints:
    GET  /status                       account, DID, drawbridge_connected
    GET  /conversations                list
    POST /conversations                -d '{"recipient_handle":"bob.postern.test"}'
    GET  /conversations/<gid>/messages
    POST /conversations/<gid>/messages -d '{"text":"hi"}'
    POST /conversations/<gid>/messages/<message_id>/reactions
    POST /poll                         force one poll now
    POST /poll/<seconds>               set poll interval (300 = push-only test)

  Pairing a second device (new device mints the code, existing one approves):
    curl -s -X POST http://127.0.0.1:9102/pair/new       # -> {"code": "..."}
    curl -s -X POST http://127.0.0.1:9101/pair/confirm \\
      -H 'Content-Type: application/json' -d '{"code":"<code>"}'
    curl -s -X POST http://127.0.0.1:9101/pair/approve
    curl -s    http://127.0.0.1:9102/pair/status

  History sync between paired devices:
    curl -s -X POST http://127.0.0.1:9102/sync/request   # ask siblings
    curl -s -X POST http://127.0.0.1:9101/sync/offer     # push to a sibling
    curl -s    http://127.0.0.1:9101/ring-status

Health checks:
  curl -s http://127.0.0.1:$POSTERN_PORT/xrpc/com.atproto.server.describeServer
  curl -s http://127.0.0.1:$RELAY_PORT/health
  curl -s http://127.0.0.1:$RELAY_PORT/metrics

A full manual pass is scripted in scripts/MANUAL_TEST.md.
EOF
}

stop() {
  for name in drawbridge postern; do
    if [[ -f "$RUN_DIR/$name.pid" ]]; then
      pid="$(cat "$RUN_DIR/$name.pid")"
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" && echo "Stopped $name ($pid)."
      fi
      rm -f "$RUN_DIR/$name.pid"
    fi
  done

  # A lost pidfile used to mean `down` silently did nothing and the services
  # kept running -- ours ran for a week that way. Match on the exact binaries
  # this script starts so a stale process is still reachable.
  for pat in "$RUN_DIR/drawbridge" "$ROOT/target/debug/dev_server $POSTERN_PORT"; do
    for pid in $(pgrep -f "$pat" 2>/dev/null); do
      kill "$pid" 2>/dev/null && echo "Stopped orphan ($pid): $pat"
    done
  done
}

case "${1:-up}" in
  up) start ;;
  down) stop ;;
  logs) tail -f "$RUN_DIR"/postern.log "$RUN_DIR"/drawbridge.log ;;
  --help|-h|help) usage ;;
  *) echo "Unknown command: $1" >&2; echo "Usage: $0 [up|down|logs|--help]" >&2; exit 1 ;;
esac
