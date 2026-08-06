# Darkie Security Suite

Advanced Cybersecurity & Network Defense Platform — 100+ tools across 17 modules.
**Educational use only. Only test systems you own or have explicit permission to test.**

## Quick Start

**Linux / macOS / WSL:**
```bash
curl -fsSL https://darkifolio.vercel.app/darkie-tool/install | bash
```

It asks whether you want to **run live** (just launch it) or **install on system**
(adds a global `darkie-tools` command) — no git clone needed. To skip the prompt:
```bash
curl -fsSL https://darkifolio.vercel.app/darkie-tool/install | bash -s -- --install   # install
curl -fsSL https://darkifolio.vercel.app/darkie-tool/install | bash -s -- --live     # run once
```
```bash
wget -qO- https://darkifolio.vercel.app/darkie-tool/install | bash
```

The installer automatically fetches the **newest version** from the repo
(no releases needed), then installs and launches it. **Dependencies auto-install
on first run** (may ask for your sudo/admin password).

Power users / direct repo:
```bash
curl -fsSL https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v4/tool.sh | bash
```

**Windows (PowerShell):**
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v4/tool.ps1'))
```

The installers try a prebuilt binary first (from GitHub releases) and automatically
fall back to running the Python source if no binary is available.

**Make it a system command** (Linux/macOS/WSL):
```bash
./tool.sh --install       # installs deps + adds a global `darkie-tools` command
darkie-tools              # launch from anywhere (menu / --web / --gui)
darkie-tools --update     # fetch & upgrade to the newest version at any time
```

**Run from source (any OS):**
```bash
git clone https://github.com/darkiekrish-spec/darkie-tools
cd darkie-tools/v4
python3 -m pip install -r requirements.txt
python3 tool.py                          # Terminal (interactive CLI)
python3 tool.py --web                    # Web Dashboard -> http://127.0.0.1:5000
python3 tool.py --gui                    # Desktop GUI (tkinter)
```

Prebuilt binaries (`.AppImage`, `.deb`, `.rpm`, `.exe`, macOS `.dmg`) are produced
locally with `v4/build_all.sh` — they are not committed to the repo.

The Python source is fully self-contained — run it with any Python 3.10+ install
and dependencies auto-install on first launch.

## Versions

| Version | Directory | Description |
|---------|-----------|-------------|
| **v4** | `v4/` | **Latest** — Full rewrite, 17 modules, argparse CLI, web + desktop GUIs |
| v3 | `v3/` | Multi-OS, 16 modules, auto-dependency installer, animated UI |
| v2.2 | `v2.2/` | Refined v2 with full 16 modules and auto-dependency installer |
| v2.1 | `v2.1/` | "GOAT Edition" — Mineflayer bots, 10 more modules, animated UI |
| v2 | `v2/` | Modular refactor with 6 modules |
| v1.3 | `v1.3/` | Added OSINT, telephone tools, network utilities, web recon |
| v1.2 | `v1.2/` | Added IP flood stress test |
| v1.0 | `stress_test.py` | Basic stress testing (Minecraft + Web) |

## Modules

| # | Module | Tools |
|---|--------|-------|
| 1 | Network & Threat Monitoring | Packet capture, traffic monitor, IDS, ARP spoof detect, port scan detect, DDoS detect |
| 2 | Endpoint Security | Process monitor, suspicious process detector, file integrity, network connections |
| 3 | Vulnerability Management | Port scanner, CVE lookup, vuln assessment, security config checker |
| 4 | Data & Access Protection | AES-256 file encryption, password strength analyzer, brute-force detection |
| 5 | Ethical Hacking & Pentest | SQLi detector, XSS scanner, HTTP methods fuzzer, login brute-force |
| 6 | SIEM & Log Analysis | Log analyzer, real-time monitor, alert dashboard, threat pattern detection |
| 7 | Stress Testing | Minecraft (Mineflayer bots), Web stress, IP flood (TCP/UDP/both) |
| 8 | OSINT Reconnaissance | Phone lookup, email OSINT, IP geolocation, DNS enum, subdomain discovery, website recon, whois |
| 9 | Telephone Tools | Number analysis, dialing codes, phone formatter |
| 10 | Network Utilities | Port scanner, SSL/TLS checker, HTTP security headers, ping, traceroute |
| 11 | Hash & Crypto Tools | Hash generator, hash identifier, hash cracker, encoder/decoder, password generator |
| 12 | System Security Audit | Rootkit detection, SUID/SGID scanner, cron job analyzer, kernel hardening check |
| 13 | Advanced Network | Port knocking tester, banner grabbing, reverse shell detector, LAN discovery |
| 14 | Advanced OSINT | Certificate transparency, DNS history, Wayback machine, Shodan InternetDB |
| 15 | WiFi & Wireless | WiFi scanner, security audit (with legal warning) |
| 16 | Report Generator | HTML report, JSON/CSV export of session findings |
| 17 | Graphical Interfaces | Web Dashboard + Desktop (tkinter) GUI |

## Requirements

- **Python 3.10+** (for source runs)
- **Node.js 18+** (optional — Minecraft Mineflayer bots)
- Dependencies auto-install on first run (`python3 -m pip install -r requirements.txt`)

## Legal Disclaimer

For educational use only. You must own or have explicit permission to test any target system.
Unauthorized use may violate local and international computer-fraud laws.
