#!/bin/bash
# Darkie Suite v3 — Local Linux/macOS launcher (standalone)
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# 1) Try prebuilt AppImage
if [ -f "$DIR/tool.AppImage" ]; then
    chmod +x "$DIR/tool.AppImage"
    exec "$DIR/tool.AppImage" "$@"
fi

# 2) Try python3 from source
if command -v python3 &>/dev/null; then
    exec python3 tool.py "$@"
fi

echo "ERROR: No prebuilt binary or Python 3 found."
echo "Linux: chmod +x tool.AppImage && ./tool.AppImage"
echo "macOS: brew install python3 && python3 tool.py"
exit 1
