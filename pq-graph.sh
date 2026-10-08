#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/pq-graph"
FILE="${1:-graph.json}"
PORT="${2:-${PORT:-8000}}"
MODULES=(data overview display render search camera investigate main)

[[ -f "$FILE" ]] || { echo "Missing file: $FILE" >&2; exit 1; }
[[ -f "$SRC/index.html" ]] || { echo "Missing $SRC/index.html" >&2; exit 1; }
[[ -f "$SRC/style.css" ]] || { echo "Missing $SRC/style.css" >&2; exit 1; }

for m in "${MODULES[@]}"; do
  [[ -f "$SRC/js/$m.js" ]] || { echo "Missing pq-graph/js/$m.js" >&2; exit 1; }
done

if grep -rFq '</script>' "$SRC/js" "$SRC/style.css"; then
  echo "</script> inside pq-graph sources; inline embedding would break" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"

cleanup() {
  kill "${SERVER_PID:-}" 2>/dev/null || true
  rm -rf "$TMPDIR"
}

trap cleanup EXIT INT TERM

cp "$FILE" "$TMPDIR/graph.json"

awk -v root="$SRC" -v out="$TMPDIR/modules.js" -v modules="${MODULES[*]}" 'BEGIN {
  n = split(modules, m, " ")
  for (i = 1; i <= n; i++) {
    path = root "/js/" m[i] ".js"
    while ((getline line < path) > 0) print line >> out
    close(path)
  }
}'

awk -v root="$SRC" -v mods="$TMPDIR/modules.js" '
  /<link rel="stylesheet"/ {
    path = root "/style.css"
    print "  <style>"
    while ((getline line < path) > 0) print line
    close(path)
    print "  </style>"
    next
  }
  /<script type="module" src=/ {
    print "<script type=\"module\">"
    while ((getline line < mods) > 0) print line
    print "</script>"
    next
  }
  { print }
' "$SRC/index.html" > "$TMPDIR/index.html"

cd "$TMPDIR"

python3 -m http.server "$PORT" >/dev/null 2>&1 &
SERVER_PID=$!

sleep 0.5

URL="http://127.0.0.1:${PORT}/"

echo "Opening: $URL"

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL" >/dev/null 2>&1 || true
fi

echo
echo "Ctrl-C to stop."
echo

wait "$SERVER_PID"
