#!/bin/bash
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
echo "Starting Darkie Web GUI on http://0.0.0.0:5000"
python3 gui/web_app.py --host 0.0.0.0 --port 5000
