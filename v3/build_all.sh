#!/bin/bash
# Build all platform packages for Darkie Suite v3
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=== Building all Darkie Suite v3 packages ==="
chmod +x tool.sh tool.ps1 2>/dev/null

echo "[1/6] .deb..."
if command -v dpkg-deb &>/dev/null; then
    bash packaging/build_deb.sh 2>&1 || true
    cp build/darkie-suite_3.0.0_all.deb tool.deb 2>/dev/null || true
fi

echo "[2/6] .rpm..."
if command -v rpmbuild &>/dev/null; then
    bash packaging/build_rpm.sh 2>&1 || true
    find build/rpm/RPMS -name "*.rpm" -exec cp {} tool.rpm \; 2>/dev/null || true
fi

echo "[3/6] .AppImage..."
bash packaging/build_appimage.sh 2>&1 || true
cp tool.AppImage tool.AppImage 2>/dev/null || true

echo "[4/6] .exe (Windows)..."
echo "  Build on Windows: packaging\\build_exe.bat"

echo "[5/6] macOS .app..."
bash packaging/build_macos_app.sh 2>&1 || true

echo "[6/6] source tarball..."
tar czf darkie-suite-v3-source.tar.gz \
    --exclude=build --exclude=__pycache__ --exclude='*.pyc' --exclude=.git \
    tool.py gui/ requirements.txt README.md tool.sh tool.ps1 *.deb *.rpm *.AppImage 2>/dev/null

echo "=== Done ==="
ls -lh tool.* darkie-suite-v3-source.tar.gz 2>/dev/null || true
