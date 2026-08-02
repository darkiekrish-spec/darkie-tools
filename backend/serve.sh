#!/usr/bin/env bash
# Serve the Darkie Tools website + LIVE playground on port 8000.
# The playground runs the real tool (v4/tool.sh) through server.py.
#   ./serve.sh          serve on http://localhost:8000
#   PORT=9000 ./serve.sh  serve on a custom port
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-8000}"
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then echo "Python is required to serve the site."; exit 1; fi
echo "==> Darkie Tools website + live playground at http://localhost:$PORT"
echo "    Playground commands run the real tool via v4/tool.sh."
echo "    Press Ctrl+C to stop."
cd "$DIR"
exec "$PY" "$DIR/server.py" "$PORT"
