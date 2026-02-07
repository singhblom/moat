#!/bin/bash
# Run Moat in Chrome with persistent localStorage and required CORS headers.
# Usage: ./scripts/run-web.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Wrapper script that adds --user-data-dir so localStorage persists across runs.
WRAPPER=$(mktemp)
cat > "$WRAPPER" <<'CHROME'
#!/bin/bash
exec "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir=/tmp/moat-chrome-dev \
  "$@"
CHROME
chmod +x "$WRAPPER"

trap "rm -f '$WRAPPER'" EXIT

cd "$PROJECT_DIR" && CHROME_EXECUTABLE="$WRAPPER" flutter run -d chrome \
  --web-header=Cross-Origin-Opener-Policy=same-origin \
  --web-header=Cross-Origin-Embedder-Policy=require-corp \
  "$@"
