# Darkie Security Suite

Advanced Cybersecurity & Network Defense Platform — 60+ tools across 16 modules.

## Versions

| Version | Directory | Description |
|---------|-----------|-------------|
| v1.0 | `stress_test.py` | Basic stress testing (Minecraft + Web) |
| v1.2 | `v1.2/` | Added IP flood stress test |
| v1.3 | `v1.3/` | Added OSINT, telephone tools, network utilities, web recon |
| v2 | `v2/` | Modular refactor with 6 modules (network threat, endpoint, vuln, data, pentest, SIEM) |
| v2.1 | `v2.1/` | "GOAT Edition" — Added Mineflayer bots, 10 more modules, animated UI |
| v2.2 | `v2.2/` | Latest — Refined v2 with full 16 modules and auto-dependency installer |

## Quick Start

```bash
# Latest version (auto-installs dependencies)
python3 v2.2/tool.py

# Or v2.1 GOAT Edition
python3 v2.1/tool.py
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
| 11 | Hash & Crypto Tools | Hash generator, hash identifier, hash cracker, encoder/decoder (Base64/URL/Hex/ROT13/Binary/Morse), password generator |
| 12 | System Security Audit | Rootkit detection, SUID/SGID scanner, cron job analyzer, file permissions audit, kernel hardening check |
| 13 | Advanced Network | Port knocking tester, banner grabbing, reverse shell detector, MAC lookup, LAN discovery, DHCP scanner |
| 14 | Advanced OSINT | Shodan search, certificate transparency, Bitcoin lookup, GitHub dorks, Wayback machine |
| 15 | WiFi & Wireless | WiFi scanner, security audit, deauth detection |
| 16 | Report Generator | HTML report, JSON/CSV export of session findings |

## Requirements

- **Python 3.10+**
- **Node.js 18+** (for Minecraft Mineflayer bots — v2.1+)
- **Linux** (primary), macOS, Windows (limited)

### Python packages (auto-installed)
```
colorama, requests, psutil, cryptography, netifaces,
beautifulsoup4, lxml, dnspython, ipwhois, python-nmap
```
`scapy` is optional — auto-detected if installed, graceful fallback if not.

### Node.js packages (auto-installed, v2.1+)
```
mineflayer, prismarine-chunk, prismarine-world
```

### System tools (auto-detected, prompted install)
The tool checks for `nmap`, `host`, `dig`, `whois`, `traceroute`, `aircrack-ng`, `tcpdump`, and `iptables` on startup. If any are missing, you'll be prompted to install them automatically via your platform's package manager.

Supported package managers: `apt` (Debian/Ubuntu/Kali), `dnf` (Fedora/RHEL), `pacman` (Arch), `apk` (Alpine), `zypper` (openSUSE), `brew` (macOS), `choco` (Windows).

## Legal Disclaimer

For educational use only. You must own or have explicit permission to test any target system. Unauthorized access is illegal and punishable by law.
