#!/usr/bin/env bash
set -e
# Writes a tiny runtime config that exposes window.DARKIE_API
mkdir -p frontend
cat > frontend/runtime-config.js <<'EOF'
window.DARKIE_API = "${DARKIE_API:-}";
EOF
