#!/bin/bash
# Integration test: starts a local Drawbridge relay, runs the Dart integration
# test that performs real WebSocket challenge-response auth, then tears down.
#
# Usage: ./scripts/test-drawbridge-integration.sh
#
# Prerequisites: Go toolchain, Flutter SDK

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DRAWBRIDGE_DIR="$(dirname "$PROJECT_DIR")/moat-drawbridge"
PORT=9877
RELAY_PID=""

cleanup() {
  if [ -n "$RELAY_PID" ]; then
    echo "Stopping Drawbridge relay (PID $RELAY_PID)..."
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# 1. Build and start the Go relay
echo "Building Drawbridge relay..."
cd "$DRAWBRIDGE_DIR"
go build -o /tmp/moat-drawbridge-test .

echo "Starting Drawbridge relay on port $PORT..."
RELAY_TLS=false RELAY_ADDR=":$PORT" LOG_FORMAT=text /tmp/moat-drawbridge-test &
RELAY_PID=$!

# Wait for the relay to be ready
for i in $(seq 1 20); do
  if curl -s -o /dev/null "http://localhost:$PORT/ws" 2>/dev/null; then
    break
  fi
  sleep 0.25
done

echo "Relay is ready (PID $RELAY_PID)"

# 2. Run the Dart integration test
cd "$PROJECT_DIR"
echo "Running Drawbridge integration tests..."
DRAWBRIDGE_TEST_URL="ws://localhost:$PORT/ws" \
  flutter test --run-skipped --tags integration test/integration/drawbridge_integration_test.dart --reporter expanded

echo "All integration tests passed!"
