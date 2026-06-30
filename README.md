# Darkie Security Suite v3.0 — GOAT Edition

Advanced Cybersecurity & Network Defense Platform — 60+ tools across 16 modules.

## What's New in v3.0

- **Mineflayer Minecraft bots** auto-installed on startup
- **6 new modules**: Hash/Crypto, System Audit, Advanced Network, Advanced OSINT, WiFi Security, Report Generator
- **Auto-dependency installer** for both Python and Node.js packages
- **One-command launcher** (`./run.sh`)
- **HTML report generation** from session findings

## Quick Start

```bash
# Option 1: Universal launcher (auto-installs everything)
chmod +x run.sh
./run.sh

# Option 2: Direct Python
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
- **Node.js 18+** (for Minecraft Mineflayer bots)
- **Linux** (primary), macOS, Windows (limited)

### Auto-installed Python packages
colorama, requests, psutil, cryptography, scapy, beautifulsoup4, lxml, dnspython, netifaces

### Auto-installed Node.js packages
mineflayer, prismarine-chunk, prismarine-world

### Optional system tools (for full functionality)
```bash
sudo apt install nmap dnsutils whois traceroute aircrack-ng
```

## Legal Disclaimer

For educational use only. You must own or have explicit permission to test any target system. Unauthorized access is illegal and punishable by law.
