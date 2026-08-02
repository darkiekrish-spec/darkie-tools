# Darkie TOOLS v3 — Multi-OS Cyber Toolkit

One script, any OS. A legitimate cybersecurity testing platform — network monitoring,
vulnerability scanning, OSINT reconnaissance, penetration testing, SIEM, stress testing
and reporting. **Educational use only. Only test systems you own or have explicit
permission to test.**

Everything lives in **one file per platform** — no extra scripts to juggle:

| File | Purpose |
|------|---------|
| `tool.py` | The whole toolkit (terminal menu + Web Dashboard + Desktop GUI) |
| `tool.sh` | Universal Linux/macOS/WSL launcher (auto-downloads if needed) |
| `tool.ps1` | Universal Windows/PowerShell launcher |
| `tool.bat` | Windows double-click launcher |

## Install & Run

**Linux / macOS — one line:**
```bash
curl -fsSL https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/tool.sh | bash
```
```bash
wget -qO- https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/tool.sh | bash
```

**Windows (PowerShell):**
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/tool.ps1'))
```

**Or clone and run from source (no binaries required):**
```bash
git clone https://github.com/darkiekrish-spec/darkie-tools
cd darkie-tools/v3
python3 -m pip install -r requirements.txt
./tool.sh                 # or: python3 tool.py
```

The launchers try a prebuilt binary first (from GitHub releases) and automatically
fall back to running the Python source. **Dependencies auto-install on first run** —
system tools (nmap, traceroute, aircrack-ng, tcpdump, ...) via your package manager
and Python packages via pip, prompting for your sudo/admin password when needed.

**Make it a system command** (Linux/macOS/WSL):
```bash
./tool.sh --install       # installs deps + adds a global `darkie-tools` command
darkie-tools              # launch from anywhere (menu / --web / --gui)
```

## Interfaces

Everything is built into `tool.py` — pick option **17** from the menu, or use flags:

```bash
python3 tool.py                     # Terminal (interactive CLI menu)
python3 tool.py --web               # Web Dashboard -> http://127.0.0.1:5000 (opens browser)
python3 tool.py --web 8080          # Web Dashboard on a custom port
python3 tool.py --web --host 0.0.0.0  # share the dashboard over your network (headless server / VPS)
python3 tool.py --gui               # Desktop GUI (tkinter window)
```

- **Terminal** — 16 modules, 100+ tools, full interactive menus, beginner-friendly help (`?`).
  Animated: typewriter banner, shimmering headers, live system status line, spinner animations
  during network lookups, and live progress bars during scans/stress tests.
- **Web Dashboard** — clickable buttons, live output, great for VPS/remote boxes.
- **Desktop GUI** — tabbed clickable interface with a built-in console.

## Modules

| # | Module | Purpose |
|---|--------|---------|
| 1 | Network & Threat Monitoring | Packet capture, traffic monitor, IDS, ARP spoof detect, port-scan detect, DDoS detect |
| 2 | Endpoint Security | Process monitor, suspicious process detector, file integrity, network connections |
| 3 | Vulnerability Management | Port scanner, CVE lookup, vuln assessment, security config checker |
| 4 | Data & Access Protection | AES-256 file encryption, password strength analyzer, brute-force detection |
| 5 | Ethical Hacking & Pentest | SQLi detector, XSS scanner, path traversal, subdomain takeover, HTTP methods, login brute-force, Instagram auth tester |
| 6 | SIEM & Log Analysis | Log analyzer, real-time monitor, alert dashboard, threat pattern detection |
| 7 | Stress Testing | Minecraft (Mineflayer bots + raw flood), Web stress, IP flood |

> **v3 fix:** the Minecraft bot attack now works out of the box — `mc_bots.js` ships with the
> v3 folder and `_ensure_mineflayer` auto-checks v2/v2.1/v2.2 module caches and auto-installs
> mineflayer on first use. Bots include retry logic (up to 4 attempts) and stagger connections.
| 8 | OSINT Reconnaissance | Phone lookup, email OSINT, IP geolocation, DNS enum, subdomain discovery, social search, website recon, whois |
| 9 | Telephone Tools | Number analysis, country codes, phone formatter |
| 10 | Network Utilities | Port scanner, SSL/TLS checker, HTTP security headers, ping, traceroute |
| 11 | Hash & Crypto Tools | Hash generator, hash identifier, hash cracker, encoder/decoder, password generator |
| 12 | System Security Audit | Rootkit detection, SUID/SGID scanner, cron analyzer, file permissions audit, kernel hardening check |
| 13 | Advanced Network | Port knocking tester, banner grabbing, reverse shell detector, MAC lookup, LAN discovery, DHCP scanner |
| 14 | Advanced OSINT | Shodan search, certificate transparency, Bitcoin lookup, GitHub dorks, Wayback machine |
| 15 | WiFi & Wireless | WiFi scanner, security audit, deauth detection |
| 16 | Report Generator | HTML report, JSON/CSV export of session findings |
| 17 | Graphical Interfaces | Web Dashboard + Desktop GUI launcher |

The Instagram auth tester in module 5 verifies single passwords or audits a wordlist
against **your own account** only (2FA-aware, rate-limit aware, honest verdicts).

## Requirements

- **Python 3.10+** for source runs (deps auto-install on first run).
- **Node.js 18+** optional — only needed for Minecraft Mineflayer bots.
- **tkinter** optional — only needed for the Desktop GUI (Linux: `sudo apt install python3-tk`).
- **Flask** optional — only needed for the Web Dashboard (`pip install flask`).

## Building Prebuilt Packages

Binaries are produced locally (they are not committed to the repo). From `v3/`:

```bash
./build_all.sh      # builds .deb, .rpm, .AppImage, macOS .app, source tarball
```
Windows `.exe` is built on Windows with `packaging\build_exe.bat`.
A Docker image is available via `packaging/docker/` (Web Dashboard on port 5000).

## Legal Disclaimer

For educational use only. You must own or have explicit written permission to test any
target system. Unauthorized use may violate local and international computer-fraud laws.
