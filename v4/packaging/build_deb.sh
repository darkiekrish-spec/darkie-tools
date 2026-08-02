#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$DIR/build"
DEB_ROOT="$BUILD/deb/darkie-suite_4.0.0_all"
mkdir -p "$DEB_ROOT/DEBIAN"
mkdir -p "$DEB_ROOT/usr/share/darkie-suite"
mkdir -p "$DEB_ROOT/usr/bin"
cp "$DIR/tool.py" "$DEB_ROOT/usr/share/darkie-suite/"
cp "$DIR/requirements.txt" "$DEB_ROOT/usr/share/darkie-suite/"
cp "$DIR/tool.sh" "$DEB_ROOT/usr/share/darkie-suite/"
cp "$DIR/packaging/DEBIAN/control" "$DEB_ROOT/DEBIAN/"
cp "$DIR/packaging/DEBIAN/postinst" "$DEB_ROOT/DEBIAN/"
cp "$DIR/packaging/DEBIAN/prerm" "$DEB_ROOT/DEBIAN/"
chmod 755 "$DEB_ROOT/DEBIAN/postinst" "$DEB_ROOT/DEBIAN/prerm"
ln -sf /usr/share/darkie-suite/tool.py "$DEB_ROOT/usr/bin/darkie-suite"
cat > "$DEB_ROOT/usr/bin/darkie-suite-gui" << 'EOF'
#!/bin/bash
exec python3 /usr/share/darkie-suite/tool.py --gui
EOF
cat > "$DEB_ROOT/usr/bin/darkie-suite-web" << 'EOF'
#!/bin/bash
exec python3 /usr/share/darkie-suite/tool.py --web "$@"
EOF
chmod +x "$DEB_ROOT/usr/bin/darkie-suite-gui" "$DEB_ROOT/usr/bin/darkie-suite-web"
dpkg-deb --build "$DEB_ROOT" "$DIR/dist/darkie-suite_4.0.0_all.deb"
echo "Debian package built: dist/darkie-suite_4.0.0_all.deb"
