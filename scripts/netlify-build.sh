#!/usr/bin/env bash
set -e
# Writes a tiny runtime config that exposes window.DARKIE_API
# When Netlify sets base = "frontend", the script runs with cwd = frontend.
# Write runtime-config.js into the current directory.
cat > ./runtime-config.js <<'EOF'
window.DARKIE_API = "${DARKIE_API:-}";
EOF
