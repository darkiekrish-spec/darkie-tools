# Darkie Toolkit

**Cybersecurity & Network Testing Suite** — educational security research toolkit.

> ⚠ **WARNING**: For **educational purposes only**. Only use on systems you own or have explicit written permission to test.

---

## Versions

| Version | Location | Highlights |
|---------|----------|------------|
| **v2** | `v2/tool.py` | All-in-one: 6-module defense platform + stress testing + OSINT + phone tools + network utils (50+ tools) |
| v1.3 | `v1.3/stress_test.py` | OSINT + web recon + pentest suite |
| v1.2 | `v1.2/stress_test.py` | IP stress test, HTTPS support, 200 threads |
| v1.0 | `stress_test.py` | Original Minecraft & web stress tests |

---

## v2 — All-in-One Security Suite (10 Modules, 50+ Tools)

Menu options: `[1-6]` core defense modules, `[7-10]` legacy v1.3 features merged in.

### Module 1 — Network & Threat Monitoring
| Tool | Description |
|------|-------------|
| **Packet Capture** | Real-time packet sniffing with scapy/raw sockets, traffic analysis, threat detection |
| **Traffic Monitor** | Per-interface bandwidth tracking (real-time upload/download rates) |
| **IDS Signatures** | 15 built-in attack signatures (SQLi, XSS, path traversal, cmd injection, git exposure) |
| **ARP Spoofing Detector** | Passive ARP monitoring, detects MAC changes indicating ARP cache poisoning |
| **Port Scan Detector** | Identifies hosts scanning multiple ports (threshold-based alerting) |
| **DDoS Detection** | High-rate traffic detection with per-IP packet counting and top talkers |

### Module 2 — Endpoint Security
| Tool | Description |
|------|-------------|
| **Process Monitor** | Top processes by CPU/memory with color-coded usage indicators |
| **Suspicious Process Detector** | 50+ known pentest/hack tool signatures (nmap, hydra, metasploit, sqlmap, xmrig, etc.) |
| **File Integrity Checker** | SHA-256 baseline creation and verification, detects modifications/deletions |
| **Network Connections** | Real-time connection listing with PID, process name, status filtering |

### Module 3 — Vulnerability Management
| Tool | Description |
|------|-------------|
| **Advanced Port Scanner** | Fast (30 ports), normal (1000), or service version (-sV) scanning modes |
| **CVE Lookup** | Real-time CVE search via circl.lu API — by CVE ID or software keyword |
| **Vulnerability Assessment** | nmap vuln scripts + exposed service checks (SSH, MySQL, RDP, Redis, MongoDB) |
| **Security Config Checker** | Linux audit: SSH config, firewall rules, SYN cookies, IP forwarding, user UID 0 |

### Module 4 — Data & Access Protection
| Tool | Description |
|------|-------------|
| **File Encryption** | AES-256 (Fernet) with PBKDF2 key derivation, auto-deletes original |
| **Password Analyzer** | Entropy calculation, character set analysis, common password check, strength grade |
| **Brute-Force Detection** | Parses auth logs for failed attempts, identifies top attacking IPs |

### Module 5 — Ethical Hacking & Pentest
| Tool | Description |
|------|-------------|
| **SQL Injection Detector** | 10 payloads (UNION, tautology, auth bypass, ORDER BY column count) with error detection |
| **XSS Scanner** | 6 payloads (script, img onerror, SVG, JS protocol) checking for reflection |
| **Path Traversal Tester** | 6 payloads including null byte, double encoding, /etc/passwd and win.ini checks |
| **Subdomain Takeover Checker** | 20 common subdomains x 22 vulnerable services (AWS, Azure, GitHub, Heroku, etc.) |
| **HTTP Methods Fuzzer** | Tests 9 methods (GET/POST/PUT/DELETE/OPTIONS/HEAD/PATCH/TRACE/CONNECT) |
| **Brute-Force Login Tester** | 7 usernames x 12 passwords against login endpoints with success detection |

### Module 7 — Stress Testing
| Tool | Description |
|------|-------------|
| **Minecraft Stress** | Server DDoS tester with 200-thread async workers, auto port scan |
| **Web Stress** | HTTP flood with configurable threads, session reuse |
| **IP Flood** | Multi-port TCP flood with per-thread socket control |

### Module 8 — OSINT Reconnaissance
| Tool | Description |
|------|-------------|
| **Phone Deep Lookup** | NPA/NXX carrier DB, Indian operator prefixes, Truecaller/Spokeo/Whitepages links |
| **Email Deep Lookup** | MX resolution, SMTP VRFY, SPF/DMARC detection, Gravatar, HIBP breach check |
| **IP Geolocation** | Proxy/VPN detection, Google Maps link, Shodan/Censys/VirusTotal/AbuseIPDB links |
| **DNS Enumeration** | A, AAAA, MX, NS, TXT, SOA, CNAME records |
| **Subdomain Discovery** | 280+ common subdomain wordlist brute-force |
| **Social Username Search** | 45+ platforms (GitHub, Twitter, Instagram, Reddit, Telegram, etc.) |
| **Website Tech Recon** | HTTP header analysis, tech stack detection, common path checks |
| **Whois Lookup** | Registrar, dates, name servers, raw whois output |
| **Web Recon & Pentest** | 190+ path directory brute-force + nmap port scan + security checks |

### Module 9 — Telephone Tools
| Tool | Description |
|------|-------------|
| **Number Analysis** | Carrier DB lookup, NPA/NXX, line type detection, valid number check |
| **Country Codes** | Reference for 50+ country calling codes |
| **Number Formatting** | E.164, national, international format conversion |

### Module 10 — Network Utilities
| Tool | Description |
|------|-------------|
| **TCP Port Scanner** | Top 100, top 1000, or custom range scans |
| **SSL/TLS Checker** | Subject, issuer, SANs, expiry date, days remaining |
| **HTTP Security Headers** | 10-header analysis with A/C/F grading |
| **Ping Sweep** | Alive check with stats parsing |
| **Traceroute** | Hop-by-hop route discovery |

### Module 6 — SIEM & Log Analysis
| Tool | Description |
|------|-------------|
| **Log File Analyzer** | Parses log files: event breakdown (ERROR/WARN/INFO), IP extraction, sample errors |
| **Real-time Log Monitor** | Live tail with color-coded severity (ERROR=red, WARN=yellow, INFO=green) |
| **Alert Dashboard** | Centralized view of all alerts generated across modules |
| **Threat Pattern Detection** | Scans system logs for SSH brute-force, user enumeration, SYN flood, PAM failures |

---

## Directory Structure

```
.
├── stress_test.py          v1.0
├── v1.2/
│   └── stress_test.py      v1.2
├── v1.3/
│   └── stress_test.py      v1.3
├── v2/
│   └── tool.py             v2  (2752 lines, 80+ functions)
├── README.md               This file
└── __pycache__/
```

---

## Quick Start

```bash
python3 v2/tool.py
```

Dependencies (nmap, tcpdump, iptables, psutil, cryptography, colorama, requests) with auto-install on first run.

---

## Key Traits

- **Scalability** — Cross-platform (Linux, macOS, Windows), modular design
- **Integration** — Unified alert system across all modules (SIEM dashboard)
- **Actionability** — Every tool provides actionable findings with context and severity
- **Completeness** — Merged v1.2 & v1.3 feature sets into v2 as menu options 7-10

---

## License

Open source — educational purposes only.
