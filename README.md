# Darkie Security Suite

Advanced Cybersecurity & Network Defense Platform — 60+ tools across 16 modules.

## Quick Start — Zero Dependencies

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/darkie.sh | bash
```
```bash
wget -qO- https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/darkie.sh | bash
```

**Windows (PowerShell):**
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/darkie.ps1'))
```

**npm:**
```bash
npm install -g darkie-tools
darkie
```

All binaries are built with PyInstaller — Python + all deps bundled inside.
No Python, pip, or any runtime required on the target system.

**GUI by default** — Launches a desktop GUI (tkinter) with clickable buttons.
On headless/VPS systems, automatically starts a web GUI at `http://0.0.0.0:5000`.

## Versions

| Version | Directory | Description |
|---------|-----------|-------------|
| **v3** | `v3/` | **Multi-OS standalone** — AppImage, .deb, .rpm, .exe. Zero deps. |
| v2.2 | `v2.2/` | Refined v2 with full 16 modules and auto-dependency installer |
| v2.1 | `v2.1/` | "GOAT Edition" — Mineflayer bots, 10 more modules, animated UI |
| v2 | `v2/` | Modular refactor with 6 modules |
| v1.3 | `v1.3/` | Added OSINT, telephone tools, network utilities, web recon |
| v1.2 | `v1.2/` | Added IP flood stress test |
| v1.0 | `stress_test.py` | Basic stress testing (Minecraft + Web) |

### v3 — Prebuilt Binaries

| File | OS | Size | Use |
|------|----|------|-----|
| `tool.AppImage` | Any Linux | 19MB | `./tool.AppImage` |
| `tool.deb` | Debian/Ubuntu | 19MB | `sudo dpkg -i tool.deb` |
| `tool.rpm` | Fedora/RHEL | 19MB | `sudo rpm -ivh tool.rpm` |
| `tool.exe` | Windows | 19MB | `tool.exe` |
| `tool` | Linux | 19MB | `./tool` |
| `tool.sh` | Linux/macOS | — | Launcher — tries AppImage → binary |
| `tool.ps1` | Windows | — | Runs `tool.exe` |
| `darkie.sh` | All (bash) | — | Universal curl\|bash installer |
| `darkie.ps1` | Windows | — | Universal iex installer |

### Run from Source (any OS)
```bash
git clone https://github.com/darkiekrish-spec/darkie-tools
cd darkie-tools/v3
pip install -r requirements.txt
python3 tool.py                          # Terminal
python3 gui/app.py                       # Desktop GUI
python3 gui/web_app.py --host 0.0.0.0    # Web GUI
```

## Modules

| # | Module | Tools |
|---|--------|-------|
| 1 | Network & Threat Monitoring | Packet capture, traffic monitor, IDS, ARP spoof detect, port scan detect, DDoS detect |
| 2 | Endpoint Security | Process monitor, suspicious process detector, file integrity, network connections |
| 3 | Vulnerability Management | Port scanner, CVE lookup, vuln assessment, security config checker |
| 4 | Data & Access Protection | AES-256 file encryption, password strength analyzer, brute-force detection |
| 5 | Ethical Hacking & Pentest | SQLi detector, XSS scanner, path traversal, subdomain takeover, HTTP methods fuzzer, login brute-force |
| 6 | SIEM & Log Analysis | Log analyzer, real-time monitor, alert dashboard, threat pattern detection |
| 7 | Stress Testing | Minecraft (Mineflayer bots + raw flood), Web stress, IP flood |
| 8 | OSINT Reconnaissance | Phone lookup, email OSINT, IP geolocation, DNS enum, subdomain discovery, social username search, website recon, whois |
| 9 | Telephone Tools | Number analysis, country codes, phone formatter |
| 10 | Network Utilities | Port scanner, SSL/TLS checker, HTTP security headers, ping, traceroute |
| 11 | Hash & Crypto Tools | Hash generator, hash identifier, hash cracker, encoder/decoder, password generator |
| 12 | System Security Audit | Rootkit detection, SUID/SGID scanner, cron job analyzer, file permissions audit, kernel hardening check |
| 13 | Advanced Network | Port knocking tester, banner grabbing, reverse shell detector, MAC lookup, LAN discovery, DHCP scanner |
| 14 | Advanced OSINT | Shodan search, certificate transparency, Bitcoin lookup, GitHub dorks, Wayback machine |
| 15 | WiFi & Wireless | WiFi scanner, security audit, deauth detection |
| 16 | Report Generator | HTML report, JSON/CSV export of session findings |

## Requirements

- **Python 3.10+** (for source run only — prebuilt binaries need nothing)
- **Node.js 18+** (for Minecraft Mineflayer bots — v2.1+)
- Dependencies auto-installed on first run

## Legal Disclaimer

For educational use only. You must own or have explicit permission to test any target system.
