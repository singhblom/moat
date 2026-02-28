#!/bin/bash
# Run Moat in Chrome with persistent localStorage and required CORS headers.
# Usage: ./scripts/run-web.sh [--profile PATH/TO/DIR] [flutter run args...]
#
# Flutter always creates a temp --user-data-dir and deletes it on exit,
# which wipes localStorage. We intercept via CHROME_EXECUTABLE to replace
# Flutter's temp dir with a persistent one, while keeping the fixed port
# so the origin (http://localhost:4200) stays the same across runs.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PERSISTENT_DIR="$HOME/.moat/chrome-dev"

# Parse --profile flag (consume it before passing rest to flutter)
FLUTTER_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PERSISTENT_DIR="$2"
      shift 2
      ;;
    --profile=*)
      PERSISTENT_DIR="${1#--profile=}"
      shift
      ;;
    *)
      FLUTTER_ARGS+=("$1")
      shift
      ;;
  esac
done

mkdir -p "$PERSISTENT_DIR"

# Wrapper that strips Flutter's --user-data-dir and substitutes ours.
WRAPPER=$(mktemp)
cat > "$WRAPPER" <<CHROME
#!/bin/bash
args=()
for arg in "\$@"; do
  case "\$arg" in
    --user-data-dir=*) ;; # drop Flutter's temp dir
    *) args+=("\$arg") ;;
  esac
done
exec "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \\
  --user-data-dir="$PERSISTENT_DIR" \\
  "\${args[@]}"
CHROME
chmod +x "$WRAPPER"

trap "rm -f '$WRAPPER'" EXIT

cd "$PROJECT_DIR" && CHROME_EXECUTABLE="$WRAPPER" flutter run -d chrome \
  --web-port=4200 \
  --web-header=Cross-Origin-Opener-Policy=same-origin \
  --web-header=Cross-Origin-Embedder-Policy=require-corp \
  "${FLUTTER_ARGS[@]}"
