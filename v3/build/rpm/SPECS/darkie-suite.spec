Name: darkie-suite
Version: 3.0.0
Release: 1
Summary: Advanced Cybersecurity & Network Defense Platform
License: MIT
URL: https://github.com/darkie/suite
BuildArch: noarch
Requires: python3, python3-pip, python3-tkinter, python3-requests
%description
Multi-module security toolkit including network monitoring, vulnerability scanning,
OSINT reconnaissance, penetration testing, SIEM, and stress testing.
%install
mkdir -p %{buildroot}/usr/share/darkie-suite/gui
mkdir -p %{buildroot}/usr/bin
cp %{_sourcedir}/tool.py %{buildroot}/usr/share/darkie-suite/
cp %{_sourcedir}/gui/app.py %{buildroot}/usr/share/darkie-suite/gui/
cp %{_sourcedir}/gui/web_app.py %{buildroot}/usr/share/darkie-suite/gui/
cp %{_sourcedir}/requirements.txt %{buildroot}/usr/share/darkie-suite/
ln -sf /usr/share/darkie-suite/tool.py %{buildroot}/usr/bin/darkie-suite
echo '#!/bin/bash' > %{buildroot}/usr/bin/darkie-suite-gui
echo 'exec python3 /usr/share/darkie-suite/gui/app.py' >> %{buildroot}/usr/bin/darkie-suite-gui
chmod +x %{buildroot}/usr/bin/darkie-suite-gui
echo '#!/bin/bash' > %{buildroot}/usr/bin/darkie-suite-web
echo 'exec python3 /usr/share/darkie-suite/gui/web_app.py "$@"' >> %{buildroot}/usr/bin/darkie-suite-web
chmod +x %{buildroot}/usr/bin/darkie-suite-web
%files
/usr/share/darkie-suite/
/usr/bin/darkie-suite
/usr/bin/darkie-suite-gui
/usr/bin/darkie-suite-web
