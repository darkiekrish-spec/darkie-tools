# Darkie TOOLS v5 — Next-Gen Cyber Toolkit

Educational use only. Test only systems you own or have permission to test.

A single-file, cross-platform cybersecurity and network-defense platform with a
terminal menu, a web dashboard, and a desktop GUI — 18 modules, 100+ tools.
v5 adds the **Native Toolbox**, which auto-detects the security tools already
installed on your OS (nmap, sqlmap, hydra, hashcat, Metasploit, aircrack-ng,
...), so they are ready to use from one menu with zero setup.

## Quick start

```bash
python3 tool.py            # interactive menu
python3 tool.py --web      # web dashboard (port 5000)
python3 tool.py --web 8080 # web dashboard on a custom port
python3 tool.py --gui      # desktop GUI (tkinter)
python3 tool.py --deps     # install missing dependencies, then exit
python3 tool.py --version
```

Or use the one-file launcher (auto-installs deps on first run):

```bash
./tool.sh                 # Linux / macOS / WSL / Git-Bash
.\tool.ps1                # Windows PowerShell
.\tool.bat                # Windows double-click
```

One-line install (universal — auto-detects the OS and the newest repo version):

```bash
# Linux / macOS / WSL / Git-Bash:
curl -fsSL https://darkifolio.vercel.app/darkie-tool/install | bash
# Windows (PowerShell):
iex (iwr https://darkifolio.vercel.app/darkie-tool/install.ps1)
./tool.sh --update        # upgrade to the newest version at any time
```

The universal installer auto-detects your OS and runs the right installer
(bash on Linux/macOS, PowerShell on Windows), and it auto-installs every
missing Python package and system tool on first run.

## Modules

| #  | Module                   | What it does |
|----|--------------------------|--------------|
| 1  | Network & Threat         | capture, traffic monitor, IDS, ARP/port-scan/DoS detection |
| 2  | Endpoint Security        | process monitor, suspicious processes, file integrity, connections |
| 3  | Vulnerability Mgmt       | port scan, CVE lookup, assessment, config checks |
| 4  | Data Protection          | AES-256 encrypt (PBKDF2), password strength, brute-force detect |
| 5  | Ethical Pentest          | SQLi, XSS, HTTP-method, login brute-force |
| 6  | SIEM & Logs              | log analyzer, real-time monitor, alert dashboard |
| 7  | Stress Testing           | TCP/UDP/both IP flood, HTTP load, Minecraft bot flood |
| 8  | OSINT Recon              | phone, email, IP-geo, DNS, subdomains, website, whois |
| 9  | Telephone Tools          | number analyze, format, dialing codes |
| 10 | Network Utilities        | port scan, SSL check, HTTP headers, ping, traceroute |
| 11 | Hash & Crypto            | generate, identify, crack, encode/decode, password generator |
| 12 | System Audit             | rootkit, SUID, cron, kernel hardening checks |
| 13 | Advanced Network         | port knocking, banner grab, rev-shell detect, LAN discovery |
| 14 | Advanced OSINT           | certificate transparency, DNS history, Wayback, Shodan InternetDB |
| 15 | WiFi & Wireless          | scan (airmon) and audit (with legal warning) |
| 16 | Reports                  | HTML report, JSON/CSV alert export |
| 17 | Graphical Interfaces     | web dashboard + tkinter desktop app |
| 18 | **Native Toolbox**       | **detects + launches the security tools already on your OS** |

## Native Toolbox

The v5 Native Toolbox scans your system for the real tools installed by your
distribution (Kali, Parrot, Ubuntu, ...) and lists them by category:

- Scanning & Recon — nmap, masscan, whois, dnsrecon, theHarvester, amass, ...
- Web & Application — sqlmap, commix, nikto, wpscan, gobuster, ffuf, ...
- Exploitation — msfconsole, msfvenom, searchsploit, setoolkit, ...
- Password Cracking — john, hashcat, hydra, medusa, ncrack, crunch, cewl, ...
- Wireless — aircrack-ng, airodump-ng, reaver, wifite, macchanger, ...
- Network & Sniffing — tcpdump, tshark, wireshark, netcat, socat, hping3, ...
- Forensics & OSINT — binwalk, exiftool, enum4linux, smbmap, ...
- Post-Exploitation — evil-winrm, crackmapexec, chisel, ...

Pick a tool, confirm the arguments, and it launches ready-to-use (with `sudo`
automatically when it needs root). Only installed tools are shown, so on Kali
almost everything is available with zero setup.

## Dependencies

```bash
pip install -r requirements.txt
```

- `flask` — web dashboard (optional)
- `cryptography` — AES-256 encryption module
- `psutil` — endpoint / system inspection
- `scapy` — packet capture, network monitoring
- `requests` — HTTP tooling and OSINT lookups
- `pyinstaller` — building standalone executables (packaging only)

Core modules (hash, encoder, audit, network utilities, reports, Native Toolbox)
work with the standard library alone.

## Packaging

See `packaging/` for AppImage / DEB / RPM / macOS / Windows build scripts, and
`build_all.sh` for one-command builds of all targets.
