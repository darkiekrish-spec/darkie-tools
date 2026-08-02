#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$DIR/build"
RPM_ROOT="$BUILD/rpm"
mkdir -p "$RPM_ROOT/SOURCES"
mkdir -p "$RPM_ROOT/SPECS"
cat > "$RPM_ROOT/SPECS/darkie-suite.spec" << 'SPEC'
Name: darkie-suite
Version: 4.0.0
Release: 1%{?dist}
Summary: Next-Gen Cybersecurity & Network Defense Platform
License: MIT
URL: https://github.com/darkiekrish-spec/darkie-tools
BuildArch: noarch
Requires: python3, python3-pip, python3-tkinter, python3-requests, python3-colorama
%description
Multi-module security toolkit including network monitoring, vulnerability scanning,
OSINT reconnaissance, penetration testing, SIEM, and stress testing.
%install
mkdir -p %{buildroot}/usr/share/darkie-suite
mkdir -p %{buildroot}/usr/bin
cp %{_sourcedir}/tool.py %{buildroot}/usr/share/darkie-suite/
cp %{_sourcedir}/requirements.txt %{buildroot}/usr/share/darkie-suite/
cp %{_sourcedir}/tool.sh %{buildroot}/usr/share/darkie-suite/
ln -sf /usr/share/darkie-suite/tool.py %{buildroot}/usr/bin/darkie-suite
echo '#!/bin/bash' > %{buildroot}/usr/bin/darkie-suite-gui
echo 'exec python3 /usr/share/darkie-suite/tool.py --gui' >> %{buildroot}/usr/bin/darkie-suite-gui
chmod +x %{buildroot}/usr/bin/darkie-suite-gui
echo '#!/bin/bash' > %{buildroot}/usr/bin/darkie-suite-web
echo 'exec python3 /usr/share/darkie-suite/tool.py --web "$@"' >> %{buildroot}/usr/bin/darkie-suite-web
chmod +x %{buildroot}/usr/bin/darkie-suite-web
%files
/usr/share/darkie-suite/
/usr/bin/darkie-suite
/usr/bin/darkie-suite-gui
/usr/bin/darkie-suite-web
SPEC
cd "$DIR"
tar czf "$RPM_ROOT/SOURCES/darkie-suite-4.0.0.tar.gz" --transform 's,^,darkie-suite-4.0.0/,' tool.py requirements.txt tool.sh
rpmbuild --define "_topdir $RPM_ROOT" -ba "$RPM_ROOT/SPECS/darkie-suite.spec" 2>/dev/null || echo "rpmbuild not installed. Install: yum install rpm-build"
mkdir -p "$DIR/dist"
find "$RPM_ROOT/RPMS" -name "*.rpm" -exec cp {} "$DIR/dist/" \;
echo "RPM packages in dist/"
