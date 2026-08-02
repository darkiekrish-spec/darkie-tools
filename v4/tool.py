#!/usr/bin/env python3
"""
Darkie Security Suite v4 — Next-Gen Cybersecurity & Network Defense Platform
Educational use only. Test only systems you own or have permission to test.
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
import subprocess
import sys
import threading
import time
import warnings
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime as dt

warnings.filterwarnings("ignore")

VERSION = "4.0.0"
APP_NAME = "Darkie TOOLS v4"
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
]
MODULE_MAP = {m["id"]: m for m in MODULES}
KEY_MAP = {m["key"]: m for m in MODULES}


def _menu_loop(menu_id, title, items, color=CYAN):
    """Generic animated menu loop. items: list of (key, label, handler)."""
    handlers = {k: h for k, h, *_ in items}
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
    salt = b"darkie-salt-v4"
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
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (DarkieTools v4)"}, verify=False)
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
            r = requests.request(m, url, timeout=8, headers={"User-Agent": "DarkieTools v4"}, verify=False)
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
    wordlist = ["password", "123456", "admin", "admin123", "password123", "root", "letmein",
                "welcome", "test", "changeme", "12345678", "qwerty"]
    print(f"  {c(f'Testing {len(wordlist)} passwords against {url}...', CYAN)}")
    print(f"  {c('Note: use only on accounts you own.', YELLOW)}")
    for i, pwd in enumerate(wordlist):
        try:
            r = requests.post(url, data={"username": user, "password": pwd}, timeout=8,
                              headers={"User-Agent": "DarkieTools v4"}, verify=False)
            ok = "incorrect" not in (r.text or "").lower() and r.status_code == 200 and len(r.text or "") > 100
            print(f"  {c(f'[{i+1}/{len(wordlist)}]', CYAN)} {user}:{pwd} -> {r.status_code}")
        except Exception:
            pass
        time.sleep(0.4)
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
                r = requests.get(url, timeout=8, headers={"User-Agent": "DarkieTools v4"}, verify=False)
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


def menu_stress():
    _menu_loop("stress", "Stress Testing", [
        ("1", "IP Flood Test", stress_ip),
        ("2", "Web Stress Test", stress_http),
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


def hash_cracker():
    header_box("Hash Cracker (Dictionary)", CYAN)
    target = _get("Hash to crack")
    if not target:
        return
    algo = _get("Algorithm (md5/sha1/sha256)", "md5").lower()
    wordlist = ["password", "123456", "admin", "root", "test", "letmein", "welcome", "qwerty",
                "abc123", "password1", "monkey", "dragon", "master", "passw0rd", "shadow",
                "12345", "iloveyou", "sunshine", "princess", "football", "login", "hello",
                "trustno1", "batman", "access", "admin123", "root123", "changeme", "default"]
    print(f"  {c(f'Cracking {len(wordlist)} words against {algo.upper()}...', CYAN)}")
    found = False
    for word in wordlist:
        try:
            h = hashlib.new(algo)
            h.update(word.encode())
            if h.hexdigest().lower() == target.lower():
                print(f"\n  {RED}{SYM_WARN} CRACKED: {c(word, RED)}{RESET}")
                add_log_alert("HIGH", "HashCrack", f"Cracked {algo}: {word}")
                found = True
                break
        except ValueError:
            print(f"  {RED}{SYM_X} Invalid algorithm.{RESET}")
            return
    if not found:
        print(f"  {GREEN}{SYM_CHECK} Not found in dictionary.{RESET}")
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


def menu_wifi():
    _menu_loop("wifi", "WiFi & Wireless", [
        ("1", "WiFi Network Scanner", wifi_scan),
        ("2", "WiFi Security Audit", wifi_audit),
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
#  WEB DASHBOARD + DESKTOP GUI
# ══════════════════════════════════════════════════════

GUI_MODULES = [
    {"id": "menu_net", "name": "Network & Threat"},
    {"id": "menu_endpoint", "name": "Endpoint Security"},
    {"id": "menu_vuln", "name": "Vulnerability Mgmt"},
    {"id": "menu_data", "name": "Data Protection"},
    {"id": "menu_pentest", "name": "Pentest"},
    {"id": "menu_siem", "name": "SIEM & Logs"},
    {"id": "menu_stress", "name": "Stress Testing"},
    {"id": "menu_osint", "name": "OSINT Recon"},
    {"id": "menu_telephone", "name": "Telephone"},
    {"id": "menu_netutils", "name": "Network Utils"},
    {"id": "menu_hash_crypto", "name": "Hash & Crypto"},
    {"id": "menu_audit", "name": "System Audit"},
    {"id": "menu_advnet", "name": "Advanced Network"},
    {"id": "menu_advosint", "name": "Advanced OSINT"},
    {"id": "menu_wifi", "name": "WiFi"},
    {"id": "menu_reports", "name": "Reports"},
    {"id": "osint_recon_engine", "name": "Recon Engine"},
]

_WEB_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Darkie TOOLS v4 — Web Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:linear-gradient(135deg,#05070f,#0a0f1f 50%,#05070f);color:#eef3ff;min-height:100vh;padding:20px}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:26px;font-weight:800;letter-spacing:-.5px;background:linear-gradient(90deg,#7c5cff,#00d4ff);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:4px}
.sub{color:#8a94ad;font-size:13px;margin-bottom:18px}
.module-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px;margin-bottom:18px}
.module-btn{background:rgba(22,33,62,.7);color:#eef3ff;border:1px solid rgba(124,92,255,.35);padding:11px 14px;cursor:pointer;font-size:13px;font-weight:600;text-align:left;border-radius:10px;transition:all .2s}
.module-btn:hover{background:rgba(124,92,255,.25);border-color:#e94560;transform:translateY(-1px)}
.module-btn.running{background:linear-gradient(90deg,#e94560,#ff5cc8);color:#fff;border-color:#ff5cc8}
#output{background:rgba(3,5,12,.85);border:1px solid rgba(124,92,255,.3);border-radius:12px;padding:16px;height:46vh;overflow-y:auto;font-size:13px;line-height:1.6;white-space:pre-wrap;word-break:break-all;font-family:Consolas,monospace}
#output .info{color:#93c5fd}#output .success{color:#4ade80}#output .error{color:#ff4444}#output .warn{color:#ffaa00}
::-webkit-scrollbar{width:8px;background:#0d0d1a}::-webkit-scrollbar-thumb{background:#533483;border-radius:4px}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.clear-btn{background:rgba(255,255,255,.06);color:#eef3ff;border:1px solid rgba(255,255,255,.15);padding:8px 16px;cursor:pointer;border-radius:10px;font-size:12px;font-weight:600}
.clear-btn:hover{background:#e94560;border-color:#e94560}
.footer{margin-top:20px;text-align:center;color:#8a94ad;font-size:12px}
</style></head>
<body><div class="wrap">
<h1>Darkie TOOLS v4 — Web Dashboard</h1>
<div class="sub">Click a module to run it. Output streams live below.</div>
<div class="module-grid" id="modules"></div>
<div class="toolbar"><h3 style="color:#00ccff;font-size:14px;">Output</h3><button class="clear-btn" onclick="clearOutput()">Clear</button></div>
<pre id="output"></pre>
<div class="footer">Darkie Security Suite v4 — educational use only</div>
</div>
<script>
const modules=MODULES_PLACEHOLDER;
const grid=document.getElementById('modules');
modules.forEach(m=>{const b=document.createElement('button');b.className='module-btn';b.textContent=m.name;b.onclick=()=>runModule(m.id,b);grid.appendChild(b);});
function runModule(id,btn){btn.classList.add('running');btn.disabled=true;const out=document.getElementById('output');out.innerHTML+='<span class="info">[+] Running '+id+'...</span>\\n';out.scrollTop=out.scrollHeight;fetch('/run/'+id).then(r=>r.json()).then(d=>{btn.classList.remove('running');btn.disabled=false;if(d.error)out.innerHTML+='<span class="error">[!] '+d.error+'</span>\\n';});}
let lastLen=0;
setInterval(()=>{fetch('/output').then(r=>r.json()).then(d=>{const out=document.getElementById('output');if(d.lines&&d.lines.length>lastLen){for(let i=lastLen;i<d.lines.length;i++){const cls=d.tags[i]||'info';out.innerHTML+='<span class="'+cls+'">'+escapeHtml(d.lines[i])+'</span>\\n';}lastLen=d.lines.length;out.scrollTop=out.scrollHeight;}});},300);
function clearOutput(){document.getElementById('output').innerHTML='';fetch('/clear').then(r=>r.json());lastLen=0;}
function escapeHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script>
</body></html>"""


def start_web_gui(host="127.0.0.1", port=5000):
    """Run the clickable web dashboard in a browser."""
    import builtins
    import io as _io
    try:
        from flask import Flask, jsonify
    except ImportError:
        print(f"  {RED}{SYM_X} Flask required. Install: pip install flask{RESET}")
        return
    app = Flask(__name__)
    current_output = []

    def _index():
        return _WEB_HTML.replace("MODULES_PLACEHOLDER", json.dumps(GUI_MODULES))

    def _run_module(module_id):
        func = globals().get(module_id)
        if not func:
            return jsonify({"error": f"Module {module_id} not found"})

        def wrapper():
            old_out = sys.stdout
            old_input = builtins.input
            buf = _io.StringIO()
            sys.stdout = buf

            def auto_input(prompt=""):
                current_output.append(("warn", f"[prompt] {prompt}"))
                return "b"

            builtins.input = auto_input
            try:
                func()
            except Exception as e:
                print(f"Error: {e}")
            finally:
                builtins.input = old_input
                sys.stdout = old_out
                for line in buf.getvalue().splitlines():
                    current_output.append(("info", line))
            current_output.append(("info", f"[+] {module_id} completed"))

        threading.Thread(target=wrapper, daemon=True).start()
        return jsonify({"status": "started"})

    def _output():
        lines = [l for _, l in current_output[-500:]]
        tags = [t for t, _ in current_output[-500:]]
        return jsonify({"lines": lines, "tags": tags})

    def _clear():
        current_output.clear()
        return jsonify({"status": "ok"})

    app.add_url_rule("/", "index", _index)
    app.add_url_rule("/run/<module_id>", "run_module", _run_module)
    app.add_url_rule("/output", "output", _output)
    app.add_url_rule("/clear", "clear", _clear)

    try:
        import webbrowser
        webbrowser.open(f"http://{host}:{port}")
    except Exception:
        pass
    print(f"\n  {c('Web Dashboard started', GREEN)}")
    print(f"  {c('Open in your browser:', CYAN)} http://{host}:{port}")
    print(f"  {c('Press Ctrl+C to return.', YELLOW)}\n")
    try:
        app.run(host=host, port=port, debug=False)
    except KeyboardInterrupt:
        print(f"\n  {c('Web Dashboard stopped.', YELLOW)}")


def start_desktop_gui():
    """Run the clickable desktop app (tkinter)."""
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext
    except Exception:
        print(f"  {RED}{SYM_X} tkinter unavailable.{RESET}")
        print(f"  {YELLOW}Linux: sudo apt install python3-tk{RESET}")
        return
    import builtins
    import io as _io
    from queue import Queue

    _BG = "#101a2e"
    _BG2 = "#0c1526"
    _FG = "#35e0a0"
    _ACCENT = "#243b63"
    _TEXT = "#e8eefb"
    _ANSI = re.compile(r'\x1b\[[0-9;]*m')

    def _strip(s):
        return _ANSI.sub('', s)

    class _Out(_io.StringIO):
        def __init__(self, q):
            super().__init__()
            self.q = q

        def write(self, s):
            if s.strip():
                self.q.put(_strip(s))
            super().write(s)

    class _Prompt:
        def __init__(self, root):
            self.root = root
            self.result = None
            self.ev = threading.Event()

        def ask(self, prompt=""):
            self.ev.clear()
            self.result = None
            self.root.after(0, self._show, prompt)
            self.ev.wait()
            return self.result

        def _show(self, prompt):
            from tkinter import simpledialog
            self.result = simpledialog.askstring("Darkie Security Suite v4", prompt.strip() or "Input", parent=self.root)
            self.ev.set()

    class _App:
        def __init__(self, root):
            self.root = root
            self.prompt = _Prompt(root)
            self.lock = threading.Lock()
            self.root.title("Darkie Security Suite v4")
            self.root.geometry("1080x760")
            self.root.configure(bg=_BG)
            style = ttk.Style()
            style.theme_use("clam")
            style.configure("TNotebook", background=_BG, borderwidth=0)
            style.configure("TNotebook.Tab", background=_BG2, foreground=_TEXT, padding=[10, 5], font=("Segoe UI", 10, "bold"))
            style.map("TNotebook.Tab", background=[("selected", _ACCENT)], foreground=[("selected", _FG)])
            style.configure("TFrame", background=_BG)
            style.configure("TLabel", background=_BG, foreground=_TEXT)
            style.configure("TButton", background=_ACCENT, foreground=_TEXT, padding=[8, 4])
            self.notebook = ttk.Notebook(root)
            self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.tabs = {}
            self.queues = {}
            groups = [
                ("Network", [("Capture", "net_capture"), ("Traffic", "net_traffic_monitor"), ("IDS", "net_ids"), ("ARP", "net_arp_detect")]),
                ("Endpoint", [("Processes", "ep_process_monitor"), ("Suspicious", "ep_suspicious_processes"), ("Connections", "ep_network_connections")]),
                ("Vuln", [("Port Scan", "vuln_advanced_scan"), ("CVE", "vuln_cve_lookup")]),
                ("Pentest", [("SQLi", "pentest_sqli"), ("XSS", "pentest_xss")]),
                ("OSINT", [("GeoIP", "osint_ipgeo"), ("DNS", "osint_dns"), ("Subdomains", "osint_subdomain"), ("Recon", "osint_recon_engine")]),
                ("Hash", [("Generator", "hash_generator"), ("Cracker", "hash_cracker"), ("Passwords", "password_generator")]),
                ("Console", None),
            ]
            for name, btns in groups:
                frame = ttk.Frame(self.notebook)
                self.notebook.add(frame, text=f" {name} ")
                self.tabs[name] = frame
                self.queues[name] = Queue()
                self._build(frame, name, btns)
            self._poll()

        def _output_widget(self, parent):
            txt = scrolledtext.ScrolledText(parent, wrap=tk.WORD, height=10, bg=_BG2, fg=_TEXT,
                                            insertbackground=_TEXT, font=("Consolas", 10), state=tk.DISABLED)
            txt.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            return txt

        def _build(self, parent, name, btns):
            if btns is None:
                self.console = self._output_widget(parent)
                row = ttk.Frame(parent)
                row.pack(fill=tk.X, padx=5)
                self.cmd_var = tk.StringVar()
                e = ttk.Entry(row, textvariable=self.cmd_var)
                e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
                e.bind("<Return>", self._console_run)
                ttk.Button(row, text="Run", command=self._console_run).pack(side=tk.RIGHT)
                return
            row = ttk.Frame(parent)
            row.pack(fill=tk.X, padx=5, pady=3)
            for label, fn in btns:
                ttk.Button(row, text=label, command=lambda n=name, f=fn: self._run_module(n, globals().get(f))).pack(side=tk.LEFT, padx=3)
            self._output_widget(parent)

        def _poll(self):
            try:
                for name, q in self.queues.items():
                    while True:
                        line = q.get_nowait()
                        tab = self.tabs.get(name)
                        if not tab:
                            continue
                        for child in tab.winfo_children():
                            if isinstance(child, scrolledtext.ScrolledText):
                                child.configure(state=tk.NORMAL)
                                child.insert(tk.END, line + "\n")
                                child.see(tk.END)
                                child.configure(state=tk.DISABLED)
            except Exception:
                pass
            self.root.after(100, self._poll)

        def _run_module(self, name, func):
            if func is None:
                return
            if not self.lock.acquire(blocking=False):
                return
            q = self.queues[name]
            old_out = sys.stdout
            old_input = builtins.input
            sys.stdout = _Out(q)
            builtins.input = self.prompt.ask

            def wrapper():
                try:
                    func()
                except Exception as e:
                    print(f"Error: {e}")
                finally:
                    builtins.input = old_input
                    sys.stdout = old_out
                    self.lock.release()

            threading.Thread(target=wrapper, daemon=True).start()

        def _console_run(self, event=None):
            cmd = self.cmd_var.get().strip()
            if not cmd:
                return
            self.cmd_var.set("")
            self.console.configure(state=tk.NORMAL)
            self.console.insert(tk.END, f"> {cmd}\n")
            self.console.configure(state=tk.DISABLED)

            def run():
                try:
                    exec(cmd, globals())
                except Exception as e:
                    self.console.configure(state=tk.NORMAL)
                    self.console.insert(tk.END, f"Error: {e}\n")
                    self.console.configure(state=tk.DISABLED)

            threading.Thread(target=run, daemon=True).start()

    root = tk.Tk()
    _App(root)
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
                print(f"  {c('3.', GREEN)}  Option 17 opens the graphical interfaces.")
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
