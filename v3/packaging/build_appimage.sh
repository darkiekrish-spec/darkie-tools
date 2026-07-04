#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
APPDIR="$DIR/build/AppDir"
mkdir -p "$APPDIR/usr/share/darkie-suite/gui"
mkdir -p "$APPDIR/usr/bin"
cp "$DIR/tool.py" "$APPDIR/usr/share/darkie-suite/"
cp "$DIR/gui/app.py" "$APPDIR/usr/share/darkie-suite/gui/"
cp "$DIR/requirements.txt" "$APPDIR/usr/share/darkie-suite/"
cat > "$APPDIR/AppRun" << 'APPRUN'
#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"
export PATH="$DIR/usr/bin:$PATH"
cd "$DIR/usr/share/darkie-suite"
python3 gui/app.py
APPRUN
chmod +x "$APPDIR/AppRun"
cat > "$APPDIR/*.desktop" << 'DESKTOP'
[Desktop Entry]
Name=Darkie Security Suite
Comment=Advanced Cybersecurity Toolkit
Exec=darkie-suite-gui
Icon=darkie
Terminal=false
Type=Application
Categories=Network;Security;
DESKTOP
mkdir -p "$DIR/dist"
cd "$DIR/build"
wget -c "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" -O appimagetool 2>/dev/null || echo "Download appimagetool from github.com/AppImage/AppImageKit"
chmod +x appimagetool 2>/dev/null || true
./appimagetool AppDir "$DIR/dist/Darkie-Suite-v3-x86_64.AppImage" 2>/dev/null || echo "appimagetool not available. Install from https://github.com/AppImage/AppImageKit/releases"
echo "AppImage build attempted. Check dist/"
