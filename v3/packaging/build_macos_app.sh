#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP="$DIR/build/DarkieSuite.app"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Resources"
cp "$DIR/packaging/macos/Info.plist" "$APP/Contents/"
cat > "$APP/Contents/MacOS/DarkieSuite" << 'MACOS'
#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"
cd "$DIR/../../../"
exec python3 gui/app.py
MACOS
chmod +x "$APP/Contents/MacOS/DarkieSuite"
mkdir -p "$DIR/dist"
cd "$DIR/build"
hdiutil create -volname "DarkieSuite" -srcfolder DarkieSuite.app -ov -format UDZO "$DIR/dist/DarkieSuite-v3-macos.dmg" 2>/dev/null || echo "hdiutil not available (macOS only). App bundle created at $APP"
cp -r "$APP" "$DIR/dist/" 2>/dev/null || true
echo "macOS build complete. DMG/APP in dist/"
