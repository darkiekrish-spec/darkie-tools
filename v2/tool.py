#!/usr/bin/env python3
"""
Darkie Security Suite v2 — Advanced Cybersecurity & Network Defense Platform
Educational use only. Test only systems you own or have permission to test.
"""

import base64
import csv
import datetime
import importlib
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import textwrap
import threading
import time
import warnings
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime as dt
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

MISSING_PIPS = []
MISSING_SYSTEM = []

PIP_DEPS = {
    "colorama": "colorama",
    "requests": "requests",
    "psutil": "psutil",
    "cryptography": "cryptography",
}

PIP_OPTIONAL = {
    "scapy": "scapy",
}

SYSTEM_DEPS_COMMON = {
    "nmap": "nmap",
    "host": "host",
    "dig": "bind9-dnsutils",
    "whois": "whois",
    "tcpdump": "tcpdump",
    "iptables": "iptables",
}

SYSTEM_DEPS_BY_MGR = {
    "apt":     {"host": "dnsutils", "dig": "dnsutils", "whois": "whois", "tcpdump": "tcpdump", "iptables": "iptables"},
    "dnf":     {"host": "bind-utils", "dig": "bind-utils", "whois": "whois", "tcpdump": "tcpdump", "iptables": "iptables"},
    "pacman":  {"host": "bind-tools", "dig": "bind-tools", "whois": "whois", "tcpdump": "tcpdump", "iptables": "iptables"},
    "apk":     {"host": "bind-tools", "dig": "bind-tools", "whois": "whois", "tcpdump": "tcpdump", "iptables": "iptables"},
    "zypper":  {"host": "bind-utils", "dig": "bind-utils", "whois": "whois", "tcpdump": "tcpdump", "iptables": "iptables"},
    "brew":    {"host": "bind", "dig": "bind", "whois": "whois", "tcpdump": "tcpdump", "iptables": ""},
    "choco":   {"host": "bind-tool", "dig": "bind-tool", "whois": "whois", "tcpdump": "", "iptables": ""},
}

GRADIENT = [
    "\033[38;5;196m", "\033[38;5;197m", "\033[38;5;198m", "\033[38;5;199m",
    "\033[38;5;200m", "\033[38;5;201m", "\033[38;5;129m", "\033[38;5;93m",
]

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

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
SYM_LINE_V = "\u251c"

SCAN_RUNNING = False
LOG_ALERTS = []


def _detect_os():
    system = platform.system().lower()
    if system == "linux":
        try:
            with open("/etc/os-release") as f:
                data = f.read()
        except FileNotFoundError:
            return "linux", "unknown"
        if re.search(r'ID=("?)debian', data) or re.search(r'ID_LIKE=.*debian', data):
            return "linux", "apt"
        if re.search(r'ID=("?)(ubuntu|linuxmint|pop|kali)', data):
            return "linux", "apt"
        if re.search(r'ID=("?)(rhel|centos|fedora|rocky|alma)', data):
            return "linux", "dnf"
        if re.search(r'ID=("?)(arch|manjaro|endeavour)', data):
            return "linux", "pacman"
        if re.search(r'ID=("?)alpine', data):
            return "linux", "apk"
        if re.search(r'ID=("?)(opensuse|suse)', data):
            return "linux", "zypper"
        return "linux", "unknown"
    elif system == "darwin":
        return "macos", "brew"
    elif system == "windows":
        return "windows", "choco"
    return system, "unknown"


def _check_pip_deps():
    global MISSING_PIPS
    for mod, pkg in PIP_DEPS.items():
        try:
            importlib.import_module(mod)
        except ImportError:
            MISSING_PIPS.append(pkg)


def _check_system_deps():
    global MISSING_SYSTEM
    _, pkg_mgr = _detect_os()
    per_mgr = SYSTEM_DEPS_BY_MGR.get(pkg_mgr, {})
    for cmd, default_pkg in SYSTEM_DEPS_COMMON.items():
        if shutil.which(cmd) is None:
            pkg = per_mgr.get(cmd, default_pkg)
            if pkg:
                MISSING_SYSTEM.append((cmd, pkg))


PKG_MANAGERS = {
    "apt":     {"install": ["apt-get", "install", "-y", "-qq"], "update": ["apt-get", "update", "-qq"]},
    "dnf":     {"install": ["dnf", "install", "-y"], "update": None},
    "pacman":  {"install": ["pacman", "-S", "--noconfirm"], "update": ["pacman", "-Sy"]},
    "apk":     {"install": ["apk", "add"], "update": ["apk", "update"]},
    "zypper":  {"install": ["zypper", "install", "-y"], "update": ["zypper", "refresh"]},
    "brew":    {"install": ["brew", "install"], "update": ["brew", "update"]},
    "choco":   {"install": ["choco", "install", "-y"], "update": None},
}


def _run_as_admin(cmd_list, reason=""):
    desc = " ".join(cmd_list)
    print(f"  {CYAN}{reason or desc}{RESET}")
    try:
        r = subprocess.run(cmd_list, capture_output=True, text=True, timeout=300)
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


def _install_missing():
    _, pkg_mgr = _detect_os()
    if MISSING_PIPS:
        print(f"\n  {YELLOW}Installing Python packages: {', '.join(MISSING_PIPS)}{RESET}")
        pip_cmd = [sys.executable, "-m", "pip", "install"] + MISSING_PIPS
        _run_as_admin(pip_cmd, "pip install " + " ".join(MISSING_PIPS))
    if MISSING_SYSTEM:
        missing_names = [pkg for _, pkg in MISSING_SYSTEM]
        print(f"\n  {YELLOW}Installing system packages: {', '.join(missing_names)}{RESET}")
        info = PKG_MANAGERS.get(pkg_mgr)
        if info is None:
            print(f"  {RED}{SYM_X}  Unsupported package manager{RESET}")
            return
        for cmd, pkg in MISSING_SYSTEM:
            if info["update"]:
                _run_as_admin(info["update"], f"Updating {pkg_mgr} cache")
                break
        install_cmd = info["install"] + [pkg for _, pkg in MISSING_SYSTEM]
        _run_as_admin(install_cmd, f"Installing with {pkg_mgr}")


def ensure_deps():
    print(f"\n{CYAN}{BOLD}{SYM_BOX_TL}{'='*50}{SYM_BOX_TR}{RESET}")
    print(f"{CYAN}{BOLD}{SYM_BOX_V}  Checking dependencies...{' ' * 29}{SYM_BOX_V}{RESET}")
    print(f"{CYAN}{BOLD}{SYM_BOX_BL}{'='*50}{SYM_BOX_BR}{RESET}")
    _check_pip_deps()
    _check_system_deps()
    if MISSING_PIPS or MISSING_SYSTEM:
        if MISSING_PIPS:
            print(f"  {YELLOW}{SYM_WARN}  Missing Python packages: {', '.join(MISSING_PIPS)}{RESET}")
        if MISSING_SYSTEM:
            missing_names = [pkg for _, pkg in MISSING_SYSTEM]
            print(f"  {YELLOW}{SYM_WARN}  Missing system tools: {', '.join(missing_names)}{RESET}")
        print()
        choice = input(f"  {CYAN}Install missing dependencies? (yes/no) {SYM_PROMPT} {RESET}").strip().lower()
        if choice == "yes":
            _install_missing()
            print()
            _check_pip_deps()
            _check_system_deps()
            if MISSING_PIPS or MISSING_SYSTEM:
                print(f"  {RED}{SYM_X}  Some deps still missing. Trying to continue anyway...{RESET}")
            else:
                print(f"  {GREEN}{SYM_CHECK}  All dependencies satisfied!{RESET}")
        else:
            print(f"  {YELLOW}{SYM_WARN}  Skipping installation. Some features may not work.{RESET}")
    else:
        print(f"  {GREEN}{SYM_CHECK}  All dependencies found!{RESET}")


ensure_deps()

from colorama import init, Fore, Style, Back
import requests

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

init(autoreset=True)


BANNER_LINES = [
    " _____             _    _        _______        _    _    _ _   _",
    "|  __ \\           | |  (_)      |__   __|      | |  | |  | | | | |",
    "| |  | | __ _ _ __| | ___  ___     | | ___  ___| | _| | _| | |_| |__",
    "| |  | |/ _` | '__| |/ / |/ _ \\    | |/ _ \\/ __| |/ / |/ / | __| '_ \\",
    "| |__| | (_| | |  |   <| |  __/    | |  __/\\__ \\   <|   <| | |_| | | |",
    "|_____/ \\__,_|_|  |_|\\_\\_|\\___|    |_|\\___||___/_|\\_\\_|\\_\\_|\\__|_| |_|",
]


def c(string, color=Fore.GREEN):
    return f"{color}{Style.BRIGHT}{string}{Style.RESET_ALL}"


def c_dim(string, color=Fore.GREEN):
    return f"{color}{Style.DIM}{string}{Style.RESET_ALL}"


def gradient_line(line):
    out = ""
    for i, ch in enumerate(line):
        idx = min(i % len(GRADIENT), len(GRADIENT) - 1)
        out += f"{GRADIENT[idx]}{Style.BRIGHT}{ch}{RESET}"
    return out


def gradient_banner():
    for line in BANNER_LINES:
        print(f"  {gradient_line(line)}")


def header_box(title, color=Fore.CYAN, width=66):
    top = f"{color}{Style.BRIGHT}{SYM_BOX_TL}{'='*(width-2)}{SYM_BOX_TR}{Style.RESET_ALL}"
    mid = f"{color}{Style.BRIGHT}{SYM_BOX_V} {title.center(width-4)} {SYM_BOX_V}{Style.RESET_ALL}"
    bot = f"{color}{Style.BRIGHT}{SYM_BOX_BL}{'='*(width-2)}{SYM_BOX_BR}{Style.RESET_ALL}"
    print(f"\n{top}\n{mid}\n{bot}\n")


def info_box(title, content_lines, color=Fore.CYAN):
    width = 60
    print(f"  {color}{Style.BRIGHT}{SYM_BOX_TL}{'='*width}{SYM_BOX_TR}{Style.RESET_ALL}")
    print(f"  {color}{Style.BRIGHT}{SYM_BOX_V}  {title.center(width-4)}  {SYM_BOX_V}{Style.RESET_ALL}")
    print(f"  {color}{Style.BRIGHT}{SYM_BOX_V}{'='*width}{SYM_BOX_V}{Style.RESET_ALL}")
    for line in content_lines:
        clean = re.sub(r'\033\[[0-9;]*m', '', line)
        label = f"  {color}{Style.BRIGHT}{SYM_BOX_V}{Style.RESET_ALL}  {line}"
        if len(clean) > width - 2:
            label = label[:width + 20] + "..."
        print(f"  {label}")
    print(f"  {color}{Style.BRIGHT}{SYM_BOX_BL}{'='*width}{SYM_BOX_BR}{Style.RESET_ALL}")


def print_banner():
    gradient_banner()
    header_box("Advanced Cybersecurity & Network Defense Platform v2", Fore.CYAN)
    print(f"  {c(SYM_CLOCK + ' Author:', Fore.CYAN)} Darkie Tester")
    print(f"  {c(SYM_WARN + ' Purpose:', Fore.CYAN)} Educational security testing & network defense\n")
    print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT} DISCLAIMER {Style.RESET_ALL}{Fore.YELLOW}  Educational use only. You must own or have permission to test the target systems.{Style.RESET_ALL}")
    print()


def add_log_alert(level, source, message):
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")
    LOG_ALERTS.append({"timestamp": timestamp, "level": level, "source": source, "message": message})


def progress_bar(current, total, bar_len=40):
    filled = int(bar_len * current // total) if total else 0
    bar = f"{Fore.GREEN}{SYM_BLOCK_FULL*filled}{Fore.WHITE}{SYM_BLOCK_EMPTY*(bar_len-filled)}{Style.RESET_ALL}"
    return f"    [{bar}] {Fore.CYAN}{current}/{total}{Style.RESET_ALL}"


SCAN_RUNNING = False
SYM_CLOCK = "\u23f0"


# ──────────────────────────────────────────────────────────
#  MODULE 1: NETWORK & THREAT MONITORING
# ──────────────────────────────────────────────────────────

def net_capture(interface=None, count=50):
    header_box("Packet Capture & Analysis", Fore.RED)
    if not HAS_SCAPY:
        print(f"  {YELLOW}scapy not installed. Using raw socket capture (limited).{RESET}")
        print(f"  {YELLOW}Install scapy for full packet analysis: pip install scapy{RESET}")

    if not interface:
        if platform.system().lower() == "linux":
            try:
                r = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
                interfaces = re.findall(r'^\d+:\s+(\w+)', r.stdout, re.MULTILINE)
                ifaces = [i for i in interfaces if i != "lo"]
                print(f"\n  {c('Available interfaces:', Fore.CYAN)}")
                for i, iface in enumerate(ifaces, 1):
                    print(f"    {c(f'[{i}]', Fore.GREEN)} {iface}")
                choice = input(f"\n  {c(f'Select interface {SYM_PROMPT} ', Fore.CYAN)}").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
                    interface = ifaces[int(choice) - 1]
                else:
                    interface = ifaces[0] if ifaces else "eth0"
            except Exception:
                interface = "eth0"
        else:
            interface = "en0"

    count_input = input(f"  {c(f'Packets to capture (default 50) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    count = int(count_input) if count_input.isdigit() else 50

    print(f"\n  {c(f'Capturing {count} packets on {interface}...', Fore.RED)}")
    print(f"  {c('Press Ctrl+C to stop early', Fore.YELLOW)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    captured = 0
    start = time.time()

    if HAS_SCAPY:
        try:
            packets = scapy.sniff(iface=interface, count=count, timeout=30)
            for pkt in packets:
                captured += 1
                ts = dt.now().strftime("%H:%M:%S.%f")[:-3]
                summary = pkt.summary()
                if len(summary) > 80:
                    summary = summary[:77] + "..."
                print(f"  {c(f'[{ts}]', Fore.GREEN)} {c(summary, Fore.CYAN)}")

                # Basic threat detection
                if pkt.haslayer(scapy.IP):
                    src = pkt[scapy.IP].src
                    dst = pkt[scapy.IP].dst
                    if pkt.haslayer(scapy.TCP):
                        dport = pkt[scapy.TCP].dport
                        if dport == 22:
                            add_log_alert("INFO", "Packet Capture", f"SSH connection: {src} -> {dst}")
                        if dport in (23, 3389):
                            add_log_alert("WARN", "Packet Capture", f"Remote access: {src} -> {dst}:{dport}")
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"  {RED}{SYM_X} Capture error: {e}{RESET}")
    else:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.settimeout(1)
            sock.bind((interface, 0))
            while captured < count:
                try:
                    data, addr = sock.recvfrom(65535)
                    captured += 1
                    ts = dt.now().strftime("%H:%M:%S.%f")[:-3]
                    mac = ":".join(f"{b:02x}" for b in data[:6])
                    print(f"  {c(f'[{ts}]', Fore.GREEN)} Packet from {c(mac, Fore.CYAN)} ({len(data)} bytes)")
                except socket.timeout:
                    continue
            sock.close()
        except PermissionError:
            print(f"  {RED}{SYM_X} Root privileges required for packet capture.{RESET}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")

    elapsed = time.time() - start
    print(f"\n  {c(SYM_CHECK + f' Captured {captured} packets in {elapsed:.1f}s', Fore.GREEN)}")
    print()


def net_traffic_monitor():
    header_box("Real-time Traffic Monitor", Fore.RED)
    if not HAS_PSUTIL:
        print(f"  {YELLOW}psutil not installed. Install for full monitoring: pip install psutil{RESET}")
        print(f"  {YELLOW}Showing basic network stats only.{RESET}")

    duration = input(f"  {c(f'Monitor duration (seconds, default 10) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 10
    interval = 1

    print(f"\n  {c(f'Monitoring traffic for {duration}s...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    try:
        if HAS_PSUTIL:
            old_stats = psutil.net_io_counters(pernic=True)
            for sec in range(duration):
                time.sleep(interval)
                new_stats = psutil.net_io_counters(pernic=True)
                sys.stdout.write(f"\r  {c(f'Second {sec+1}/{duration}', Fore.CYAN)}  ")
                for iface in new_stats:
                    if iface in old_stats:
                        sent = new_stats[iface].bytes_sent - old_stats[iface].bytes_sent
                        recv = new_stats[iface].bytes_recv - old_stats[iface].bytes_recv
                        if sent > 0 or recv > 0:
                            up_arrow = "\u2191"
                            down_arrow = "\u2193"
                            sys.stdout.write(f"{c(f'{iface}:', Fore.GREEN)} {c(f'{up_arrow}{sent/1024:.1f}KB', Fore.YELLOW)} {c(f'{down_arrow}{recv/1024:.1f}KB', Fore.CYAN)}  ")
                sys.stdout.flush()
                old_stats = new_stats
            print()
        else:
            old = psutil.net_io_counters() if HAS_PSUTIL else None
            for sec in range(duration):
                time.sleep(interval)
                sys.stdout.write(f"\r  {c(f'Second {sec+1}/{duration}', Fore.CYAN)}")
                sys.stdout.flush()
            print()

        print(f"\n  {c(SYM_CHECK + ' Monitoring complete', Fore.GREEN)}")
    except KeyboardInterrupt:
        print(f"\n  {c(SYM_WARN + ' Stopped by user', Fore.YELLOW)}")
    print()


SIGNATURES = [
    (r"GET /admin", "Admin page access", "MEDIUM"),
    (r"GET /\.env", "Environment file access", "HIGH"),
    (r"GET /\.git", "Git repo exposure", "HIGH"),
    (r"SELECT.*FROM", "SQL injection attempt", "HIGH"),
    (r"<script>", "XSS attempt", "HIGH"),
    (r"UNION.*SELECT", "SQL injection (UNION)", "CRITICAL"),
    (r"exec\(|system\(|passthru\(", "PHP code execution attempt", "CRITICAL"),
    (r"admin' OR '1'='1", "SQL auth bypass attempt", "CRITICAL"),
    (r"/etc/passwd", "Path traversal attempt", "HIGH"),
    (r"../..", "Directory traversal", "MEDIUM"),
    (r"wget |curl ", "Remote file download", "MEDIUM"),
    (r"DROP TABLE", "SQL DROP attempt", "CRITICAL"),
    (r"cmd=", "Command injection", "HIGH"),
    (r"../../etc", "Deep path traversal", "HIGH"),
    (r"load_file\(", "MySQL file read attempt", "CRITICAL"),
]


def net_ids():
    header_box("IDS Signature Detection", Fore.RED)
    print(f"  {c('Loaded signatures:', Fore.CYAN)} {len(SIGNATURES)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    for pattern, desc, severity in SIGNATURES:
        sev_color = Fore.RED if severity in ("CRITICAL", "HIGH") else Fore.YELLOW
        print(f"    {c(f'[{severity:8s}]', sev_color)} {c(desc, Fore.GREEN)}")
        print(f"    {' ' * 14}{c_dim(pattern, Fore.WHITE)}")
    print(f"\n  {c('Total signatures loaded: 15', Fore.GREEN)}")

    test_data = input(f"\n  {c(f'Test a log line against signatures {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if test_data:
        print(f"\n  {c('Results:', Fore.CYAN)}")
        for pattern, desc, severity in SIGNATURES:
            if re.search(pattern, test_data, re.IGNORECASE):
                sev_color = Fore.RED if severity in ("CRITICAL", "HIGH") else Fore.YELLOW
                print(f"    {c(f'[{severity}]', sev_color)} {c(desc, Fore.GREEN)} {c(SYM_CHECK, Fore.GREEN)}")
                add_log_alert(severity, "IDS", f"Signature matched: {desc} in: {test_data[:80]}")
        print()


def net_arp_detect():
    header_box("ARP Spoofing Detector", Fore.RED)
    if not HAS_SCAPY:
        print(f"  {YELLOW}scapy required for ARP detection. Install: pip install scapy{RESET}")
        print(f"  {YELLOW}Checking gateway ARP manually...{RESET}")

    iface = input(f"  {c(f'Interface (default eth0) {SYM_PROMPT} ', Fore.CYAN)}").strip() or "eth0"

    try:
        r = subprocess.run(["ip", "route", "show"], capture_output=True, text=True)
        gw_match = re.search(r'default via (\S+)', r.stdout)
        gateway = gw_match.group(1) if gw_match else None
        if gateway:
            print(f"  {c('Gateway:', Fore.CYAN)} {gateway}")
    except Exception:
        gateway = None

    if HAS_SCAPY:
        print(f"\n  {c('Sending ARP request for gateway...', Fore.CYAN)}")
        try:
            arp_req = scapy.ARP(pdst=gateway or "192.168.1.1")
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_req
            answered = scapy.srp(packet, timeout=3, iface=iface, verbose=False)[0]

            if answered:
                for sent, recv in answered:
                    print(f"    {c('IP:', Fore.GREEN)} {recv.psrc}  {c('MAC:', Fore.CYAN)} {recv.hwsrc}")
                    add_log_alert("INFO", "ARP Scan", f"Host {recv.psrc} has MAC {recv.hwsrc}")
            else:
                print(f"  {YELLOW}No ARP responses.{RESET}")

            print(f"\n  {c('Passive ARP monitoring (5s)...', Fore.CYAN)}")
            arp_packets = scapy.sniff(iface=iface, filter="arp", count=10, timeout=5)
            ip_mac_map = {}
            for pkt in arp_packets:
                if pkt.haslayer(scapy.ARP):
                    src_ip = pkt[scapy.ARP].psrc
                    src_mac = pkt[scapy.ARP].hwsrc
                    if src_ip in ip_mac_map and ip_mac_map[src_ip] != src_mac:
                        print(f"  {RED}{SYM_WARN} ARP SPOOF DETECTED: {src_ip} changed from {ip_mac_map[src_ip]} to {src_mac}{RESET}")
                        add_log_alert("CRITICAL", "ARP Detector", f"ARP spoof: {src_ip} MAC changed to {src_mac}")
                    ip_mac_map[src_ip] = src_mac
                    print(f"    {c(f'{src_ip:15s}', Fore.GREEN)} {c(src_mac, Fore.CYAN)}")
        except Exception as e:
            print(f"  {RED}{SYM_X} ARP detection error: {e}{RESET}")
    else:
        try:
            r = subprocess.run(["arp", "-n"], capture_output=True, text=True)
            print(f"\n  {c('ARP Cache:', Fore.CYAN)}")
            for line in r.stdout.splitlines():
                if line.strip():
                    print(f"    {c(line, Fore.GREEN)}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def net_portscan_detect():
    header_box("Port Scan Detection", Fore.RED)
    if not HAS_SCAPY:
        print(f"  {YELLOW}scapy required for real-time detection. Install: pip install scapy{RESET}")
    iface = input(f"  {c(f'Interface (default eth0) {SYM_PROMPT} ', Fore.CYAN)}").strip() or "eth0"
    duration = input(f"  {c(f'Monitor duration (seconds, default 15) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 15
    threshold = input(f"  {c(f'Port count threshold (default 10) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    threshold = int(threshold) if threshold.isdigit() else 10

    print(f"\n  {c(f'Monitoring for port scans on {iface} ({duration}s)...', Fore.RED)}")
    print(f"  {c('Threshold: >{threshold} distinct ports from same IP = scan alert', Fore.YELLOW)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    connections = defaultdict(set)
    start = time.time()

    try:
        if HAS_SCAPY:
            def process_pkt(pkt):
                if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP):
                    src = pkt[scapy.IP].src
                    dport = pkt[scapy.TCP].dport
                    connections[src].add(dport)

            scapy.sniff(iface=iface, prn=process_pkt, timeout=duration, store=False)
        else:
            while time.time() - start < duration:
                try:
                    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                    sock.settimeout(1)
                    sock.bind((iface, 0))
                    data, _ = sock.recvfrom(65535)
                    sock.close()
                except Exception:
                    break

        print()
        for src, ports in sorted(connections.items()):
            if len(ports) > threshold:
                print(f"  {RED}{SYM_WARN} PORT SCAN DETECTED from {c(src, Fore.RED)} ({len(ports)} ports){RESET}")
                add_log_alert("CRITICAL", "Port Scan Detector", f"Port scan from {src}: {len(ports)} ports")
            else:
                print(f"  {c(f'{src:15s}', Fore.GREEN)} contacted {c(str(len(ports)), Fore.CYAN)} ports")

        if not connections:
            print(f"  {YELLOW}No TCP connections captured.{RESET}")

    except PermissionError:
        print(f"  {RED}{SYM_X} Root privileges required.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    elapsed = time.time() - start
    print(f"\n  {c(SYM_CHECK + f' Monitored for {elapsed:.0f}s', Fore.GREEN)}")
    print()


def net_ddos_detect():
    header_box("DDoS Detection", Fore.RED)
    iface = input(f"  {c(f'Interface (default eth0) {SYM_PROMPT} ', Fore.CYAN)}").strip() or "eth0"
    duration = input(f"  {c(f'Monitor duration (seconds, default 20) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 20
    rate_threshold = input(f"  {c(f'Packet rate threshold (pkts/sec, default 100) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    rate_threshold = int(rate_threshold) if rate_threshold.isdigit() else 100

    print(f"\n  {c(f'DDoS detection on {iface} ({duration}s)...', Fore.RED)}")
    print(f"  {c(f'Threshold: >{rate_threshold} pkts/sec from same IP', Fore.YELLOW)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    packet_counts = defaultdict(int)
    start = time.time()
    last_report = start
    total_packets = 0

    try:
        if HAS_SCAPY:
            def count_pkt(pkt):
                if pkt.haslayer(scapy.IP):
                    packet_counts[pkt[scapy.IP].src] += 1
                    nonlocal total_packets
                    total_packets += 1

            scapy.sniff(iface=iface, prn=count_pkt, timeout=duration, store=False)
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.settimeout(0.5)
            sock.bind((iface, 0))
            while time.time() - start < duration:
                try:
                    data, _ = sock.recvfrom(65535)
                    total_packets += 1
                    if time.time() - last_report >= 1:
                        rate = total_packets / (time.time() - start)
                        sys.stdout.write(f"\r  {c(f'Rate: {rate:.1f} pkts/sec', Fore.CYAN)}  {c(f'Total: {total_packets}', Fore.GREEN)}  ")
                        sys.stdout.flush()
                        last_report = time.time()
                except socket.timeout:
                    continue
            sock.close()

        print()
        elapsed = time.time() - start
        rate = total_packets / elapsed if elapsed > 0 else 0

        print(f"\n  {c('Summary:', Fore.CYAN)}")
        print(f"    Total packets: {c(str(total_packets), Fore.GREEN)}")
        print(f"    Duration:      {c(f'{elapsed:.1f}s', Fore.CYAN)}")
        print(f"    Avg rate:      {c(f'{rate:.1f} pkts/sec', Fore.YELLOW)}")

        if rate > rate_threshold:
            print(f"\n  {RED}{SYM_WARN} HIGH TRAFFIC RATE DETECTED: {rate:.1f} pkts/sec{RESET}")
            add_log_alert("CRITICAL", "DDoS Detector", f"High traffic rate: {rate:.1f} pkts/sec")

        if packet_counts:
            top = sorted(packet_counts.items(), key=lambda x: -x[1])[:5]
            print(f"\n  {c('Top talkers:', Fore.CYAN)}")
            for ip, count in top:
                pct = count / total_packets * 100 if total_packets > 0 else 0
                bar = SYM_BLOCK_FULL * min(int(pct / 5), 20)
                print(f"    {c(f'{ip:15s}', Fore.GREEN)} {c(f'{count:6d}', Fore.CYAN)} {c(f'({pct:.1f}%)', Fore.YELLOW)} {c(bar, Fore.GREEN)}")

    except PermissionError:
        print(f"  {RED}{SYM_X} Root privileges required.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 2: ENDPOINT SECURITY
# ──────────────────────────────────────────────────────────

ENDPOINT_HOOKS = []


def ep_process_monitor():
    header_box("Process Monitor", Fore.MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {RED}{SYM_X} psutil required. Install: pip install psutil{RESET}")
        return

    sort_by = input(f"  {c('Sort by (cpu/mem/name, default cpu) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() or "cpu"
    count = input(f"  {c(f'Number of processes (default 20) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    count = int(count) if count.isdigit() else 20

    print(f"\n  {c(f'Top {count} processes by {sort_by}:', Fore.MAGENTA)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    procs = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
        try:
            procs.append(proc.info)
        except Exception:
            pass

    if sort_by == "mem":
        procs.sort(key=lambda x: x.get("memory_percent", 0) or 0, reverse=True)
    else:
        procs.sort(key=lambda x: x.get("cpu_percent", 0) or 0, reverse=True)

    print(f"  {c('PID', Fore.CYAN):>8s} {'CPU%':>6s} {'MEM%':>6s} {'Status':>12s}  Name")
    print(f"  {SYM_LINE_H*50}")
    for p in procs[:count]:
        pid = p.get("pid", 0)
        cpu = p.get("cpu_percent", 0) or 0
        mem = p.get("memory_percent", 0) or 0
        status = p.get("status", "?") or "?"
        name = p.get("name", "?") or "?"
        cpu_color = Fore.RED if cpu > 50 else Fore.YELLOW if cpu > 10 else Fore.GREEN
        mem_color = Fore.RED if mem > 10 else Fore.YELLOW if mem > 5 else Fore.GREEN
        print(f"  {c(f'{pid:>7d}', Fore.CYAN)} {c(f'{cpu:>5.1f}', cpu_color)} {c(f'{mem:>5.1f}', mem_color)} {c(f'{status:>12s}', Fore.YELLOW)}  {c(name, Fore.GREEN)}")

    print()


SUSPICIOUS_PROCESS_NAMES = [
    "nc", "netcat", "ncat", "nmap", "zenmap", "masscan", "zmap",
    "hydra", "medusa", "john", "hashcat", "aircrack", "kismet",
    "tshark", "tcpdump", "ettercap", "bettercap", "driftnet",
    "metasploit", "msfconsole", "msfvenom", "veil",
    "sqlmap", "sqlninja", "havij", "pangolin",
    "beef", "beef-xss", "xsser",
    "proxychains", "tor", "vidalia",
    "cryptomining", "minerd", "xmrig", "cpuminer",
    "socat", "sbd", "cryptcat", "pwncat",
    "nikto", "wpscan", "joomscan", "droopescan",
    "dirb", "dirbuster", "gobuster", "wfuzz", "ffuf",
    "burp", "burpsuite",
    "wireshark", "dumpcap",
    "keylogger", "logkeys", "lkl",
    "backdoor", "rootkit", "rkit",
]


def ep_suspicious_processes():
    header_box("Suspicious Process Detector", Fore.MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {RED}{SYM_X} psutil required. Install: pip install psutil{RESET}")
        return

    print(f"  {c('Scanning for suspicious processes...', Fore.MAGENTA)}")
    print(f"  {c(f'Known bad patterns: {len(SUSPICIOUS_PROCESS_NAMES)}', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    found = []
    for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            cmdline = " ".join(info.get("cmdline") or [])
            combined = name + " " + cmdline.lower()

            for pattern in SUSPICIOUS_PROCESS_NAMES:
                if pattern.lower() in combined:
                    found.append((info.get("pid", 0), info.get("name", "?"), info.get("username", "?"), pattern))
                    break
        except Exception:
            pass

    if found:
        print(f"  {RED}{SYM_WARN} Found {len(found)} suspicious processes!{RESET}")
        for pid, name, user, pattern in found:
            print(f"    {c(f'PID {pid:>6d}', Fore.RED)} {c(name, Fore.YELLOW):20s} user={c(user, Fore.CYAN)} matched: {c(pattern, Fore.GREEN)}")
            add_log_alert("WARN", "Endpoint Security", f"Suspicious process: {name} (PID {pid}) matched pattern {pattern}")
    else:
        print(f"  {GREEN}{SYM_CHECK} No suspicious processes found.{RESET}")

    print()


def ep_file_integrity():
    header_box("File Integrity Checker", Fore.MAGENTA)
    path = input(f"  {c(f'Directory to monitor {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not path or not os.path.isdir(path):
        print(f"  {RED}{SYM_X} Invalid directory.{RESET}")
        return

    mode = input(f"  {c(f'Mode: (s)napshot or (c)heck baseline {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    baseline_file = os.path.join(path, ".integrity_baseline.json")

    if mode == "s":
        checksums = {}
        print(f"  {c('Creating integrity snapshot...', Fore.CYAN)}")
        for root, dirs, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        content = f.read()
                    import hashlib
                    h = hashlib.sha256(content).hexdigest()
                    checksums[fpath] = h
                except Exception:
                    pass
        with open(baseline_file, "w") as f:
            json.dump(checksums, f, indent=2)
        print(f"  {GREEN}{SYM_CHECK} Baseline saved: {baseline_file} ({len(checksums)} files){RESET}")

    elif mode == "c":
        if not os.path.exists(baseline_file):
            print(f"  {RED}{SYM_X} No baseline found. Run snapshot first.{RESET}")
            return
        with open(baseline_file) as f:
            baseline = json.load(f)

        print(f"  {c('Verifying integrity...', Fore.CYAN)}")
        import hashlib
        changes = []
        for fpath, old_hash in baseline.items():
            if not os.path.exists(fpath):
                changes.append((fpath, "DELETED", ""))
                continue
            try:
                with open(fpath, "rb") as f:
                    content = f.read()
                new_hash = hashlib.sha256(content).hexdigest()
                if new_hash != old_hash:
                    changes.append((fpath, "MODIFIED", old_hash[:16]))
            except Exception:
                changes.append((fpath, "ACCESS ERROR", ""))

        print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
        if changes:
            print(f"  {RED}{SYM_WARN} {len(changes)} changes detected!{RESET}")
            for fpath, change_type, old in changes:
                color = Fore.RED if change_type == "DELETED" else Fore.YELLOW
                print(f"    {c(f'[{change_type:8s}]', color)} {c(fpath, Fore.GREEN)}")
                add_log_alert("WARN", "File Integrity", f"File {change_type}: {fpath}")
        else:
            print(f"  {GREEN}{SYM_CHECK} All files intact.{RESET}")
    else:
        print(f"  {RED}{SYM_X} Invalid mode (s/c).{RESET}")
    print()


def ep_network_connections():
    header_box("Network Connection Monitor", Fore.MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {RED}{SYM_X} psutil required. Install: pip install psutil{RESET}")
        return

    filters = input(f"  {c(f'Filter (all/listen/estab, default all) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() or "all"

    print(f"\n  {c('Active network connections:', Fore.MAGENTA)}")
    print(f"  {c(SYM_LINE_H*55, Fore.CYAN)}")

    try:
        connections = psutil.net_connections()
        count = 0
        for conn in connections:
            status = conn.status.lower() if conn.status else "?"
            if filters == "listen" and "listen" not in status:
                continue
            if filters == "estab" and "established" not in status:
                continue

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?:?"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?:?"
            pid = conn.pid or 0
            proc_name = ""
            try:
                proc_name = psutil.Process(pid).name() if pid else ""
            except Exception:
                pass

            status_color = Fore.GREEN if "established" in status else Fore.YELLOW if "listen" in status else Fore.CYAN
            print(f"  {c(f'{status:>12s}', status_color)} {c(f'{laddr:22s}', Fore.GREEN)} {SYM_ARROW} {c(f'{raddr:22s}', Fore.CYAN)} {c(f'PID {pid}', Fore.YELLOW)} {c(proc_name, Fore.MAGENTA)}")
            count += 1

        print(f"\n  {c(f'Total connections: {count}', Fore.GREEN)}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 3: VULNERABILITY MANAGEMENT
# ──────────────────────────────────────────────────────────

def vuln_advanced_scan():
    header_box("Advanced Port Scanner", Fore.BLUE)
    target = input(f"  {c(f'Enter IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target:
        print(f"  {RED}No target.{RESET}")
        return

    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {GREEN}{SYM_CHECK} Resolved: {target} {SYM_ARROW} {ip}{RESET}")
        except Exception:
            print(f"  {RED}{SYM_X} Could not resolve.{RESET}")
            return

    print(f"\n  {c('Scan mode:', Fore.CYAN)}")
    print(f"  {c('[1]', Fore.GREEN)}  Fast (top 30 ports)")
    print(f"  {c('[2]', Fore.GREEN)}  Normal (top 1000)")
    print(f"  {c('[3]', Fore.GREEN)}  Service version scan (nmap -sV)")
    scan_mode = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()

    has_nmap = shutil.which("nmap")
    open_ports = []

    if has_nmap and scan_mode == "3":
        print(f"\n  {c('Running nmap service version scan...', Fore.CYAN)}")
        try:
            result = subprocess.run(
                ["nmap", "-sV", "--version-intensity", "2", "-T4", ip],
                capture_output=True, text=True, timeout=300
            )
            print(f"\n  {c('Results:', Fore.CYAN)}")
            for line in result.stdout.splitlines():
                if re.search(r'(tcp|udp)\s+open', line):
                    print(f"    {c(line, Fore.GREEN)}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")

    elif has_nmap and scan_mode == "2":
        print(f"\n  {c('Scanning top 1000 ports...', Fore.CYAN)}")
        try:
            result = subprocess.run(
                ["nmap", "-T4", "--open", ip],
                capture_output=True, text=True, timeout=300
            )
            for line in result.stdout.splitlines():
                m = re.match(r'^(\d+)/tcp\s+open', line)
                if m:
                    port = int(m.group(1))
                    svc = socket.getservbyport(port) if port <= 65535 else "?"
                    try:
                        svc = socket.getservbyport(port)
                    except OSError:
                        svc = "?"
                    open_ports.append((port, svc))
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    else:
        targets = [22, 21, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                   1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080,
                   8443, 9000, 9090, 9200, 27017]
        print(f"\n  {c(f'Scanning {len(targets)} common ports...', Fore.CYAN)}")

        def check(port, results, idx):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                r = s.connect_ex((ip, port))
                s.close()
                results[idx] = port if r == 0 else None
            except Exception:
                results[idx] = None

        batch_size = 50
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            batch_results = {}
            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = {ex.submit(check, p, batch_results, j): j for j, p in enumerate(batch)}
                for f in as_completed(futures):
                    f.result()
            for idx in batch_results:
                if batch_results[idx] is not None:
                    p = batch_results[idx]
                    try:
                        svc = socket.getservbyport(p)
                    except OSError:
                        svc = "?"
                    open_ports.append((p, svc))

    print(f"\n  {c('Open Ports:', Fore.GREEN)}")
    if open_ports:
        for port, svc in sorted(set(open_ports)):
            print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(f'{port:5d}', Fore.GREEN)} ({c(svc, Fore.CYAN)})")
    else:
        print(f"    {YELLOW}No open ports detected.{RESET}")

    print()


CVE_CACHE = {}


def vuln_cve_lookup():
    header_box("CVE Lookup", Fore.BLUE)
    keyword = input(f"  {c(f'Enter software name or CVE ID {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not keyword:
        print(f"  {RED}No input.{RESET}")
        return

    print(f"\n  {c(f'Looking up CVEs for: {keyword}', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    try:
        if keyword.upper().startswith("CVE-"):
            resp = requests.get(f"https://cve.circl.lu/api/cve/{keyword.upper()}", timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                info_lines = [
                    f"  CVE ID:      {c(data.get('id', 'N/A'), Fore.RED)}",
                    f"  Summary:     {c((data.get('description', 'N/A') or 'N/A')[:120], Fore.GREEN)}",
                    f"  CVSS Score:  {c(str(data.get('cvss', 'N/A')), Fore.YELLOW)}",
                    f"  Published:   {c(data.get('Published', 'N/A'), Fore.CYAN)}",
                    f"  Modified:    {c(data.get('last-modified', 'N/A'), Fore.CYAN)}",
                ]
                if data.get("access"):
                    info_lines.append(f"  Vector:      {c(data['access'].get('vector', 'N/A'), Fore.MAGENTA)}")
                info_box("CVE Details", info_lines, Fore.RED)
            else:
                print(f"  {YELLOW}CVE not found.{RESET}")
        else:
            resp = requests.get(f"https://cve.circl.lu/api/search/{keyword}", timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    print(f"  {c(f'Found {len(data)} CVEs', Fore.GREEN)}")
                    for item in data[:10]:
                        cve_id = item.get("id", "?")
                        score = item.get("cvss", "?")
                        desc = (item.get("description", "") or "")[:80]
                        score_color = Fore.RED if (isinstance(score, (int, float)) and score >= 7) else Fore.YELLOW
                        print(f"    {c(cve_id, Fore.RED)} {c(f'CVSS:{score}', score_color)} {c(desc, Fore.GREEN)}")
                else:
                    print(f"  {YELLOW}Unexpected response format.{RESET}")
            else:
                print(f"  {YELLOW}No results.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Lookup error: {e}{RESET}")
    print()


def vuln_assessment():
    header_box("Basic Vulnerability Assessment", Fore.BLUE)
    target = input(f"  {c(f'Enter IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target:
        print(f"  {RED}No target.{RESET}")
        return

    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {GREEN}{SYM_CHECK} Resolved: {target} {SYM_ARROW} {ip}{RESET}")
        except Exception:
            print(f"  {RED}{SYM_X} Could not resolve.{RESET}")
            return

    print(f"\n  {c('Running vulnerability assessment...', Fore.BLUE)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    findings = []
    has_nmap = shutil.which("nmap")

    if has_nmap:
        try:
            r = subprocess.run(
                ["nmap", "-sV", "--script", "vuln", "-T4", ip],
                capture_output=True, text=True, timeout=300
            )
            for line in r.stdout.splitlines():
                if re.search(r'(VULNERABLE|CVE-\d|vulners:)', line, re.IGNORECASE):
                    findings.append(line.strip())
                    add_log_alert("HIGH", "Vuln Assessment", f"Vulnerability found on {ip}: {line.strip()}")
        except subprocess.TimeoutExpired:
            print(f"  {YELLOW}nmap timed out (300s). Showing partial results.{RESET}")

    if findings:
        print(f"\n  {RED}{SYM_WARN} Potential vulnerabilities:{RESET}")
        for finding in findings[:20]:
            print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(finding, Fore.RED)}")
    else:
        print(f"\n  {GREEN}{SYM_CHECK} No obvious vulnerabilities detected via nmap vuln scripts.{RESET}")

    print(f"\n  {c('Basic security checks:', Fore.CYAN)}")
    checks = [
        ("SSH (22)", is_port_open(ip, 22)),
        ("HTTP (80)", is_port_open(ip, 80)),
        ("HTTPS (443)", is_port_open(ip, 443)),
        ("MySQL (3306)", is_port_open(ip, 3306)),
        ("RDP (3389)", is_port_open(ip, 3389)),
        ("Redis (6379)", is_port_open(ip, 6379)),
        ("MongoDB (27017)", is_port_open(ip, 27017)),
    ]
    for name, open_status in checks:
        if open_status:
            print(f"    {c(SYM_X, Fore.RED)} {name}: EXPOSED")
            add_log_alert("WARN", "Vuln Assessment", f"Service exposed: {name} on {ip}")
        else:
            print(f"    {c(SYM_CHECK, Fore.GREEN)} {name}: filtered/closed")
    print()


def is_port_open(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def vuln_config_check():
    header_box("Security Configuration Checker", Fore.BLUE)
    print(f"  {c('Checking local system security posture...', Fore.BLUE)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    issues = []

    if platform.system().lower() == "linux":
        try:
            with open("/etc/ssh/sshd_config") as f:
                ssh_config = f.read()
            if "PermitRootLogin yes" in ssh_config:
                issues.append("SSH root login enabled")
            if "PasswordAuthentication yes" in ssh_config:
                issues.append("SSH password authentication enabled")
            if "Port 22" in ssh_config and "Port " in ssh_config:
                pass
        except Exception:
            pass

        try:
            import pwd
            for user in pwd.getpwall():
                if user.pw_uid == 0 and user.pw_name != "root":
                    issues.append(f"Non-root user with UID 0: {user.pw_name}")
        except Exception:
            pass

        try:
            r = subprocess.run(["iptables", "-L"], capture_output=True, text=True, timeout=5)
            if "Chain INPUT (policy ACCEPT)" in r.stdout:
                issues.append("Firewall: INPUT chain policy is ACCEPT (not DROP)")
        except Exception:
            pass

        try:
            r = subprocess.run(["sysctl", "net.ipv4.tcp_syncookies"], capture_output=True, text=True, timeout=5)
            if "= 0" in r.stdout:
                issues.append("SYN cookies disabled (DDoS mitigation off)")
        except Exception:
            pass

        try:
            r = subprocess.run(["sysctl", "net.ipv4.ip_forward"], capture_output=True, text=True, timeout=5)
            if "= 1" in r.stdout:
                issues.append("IP forwarding enabled (system may be routing)")
        except Exception:
            pass

        try:
            with open("/etc/hostname") as f:
                hn = f.read().strip()
            if hn == "localhost" or not hn:
                issues.append("Hostname not properly configured")
        except Exception:
            pass

    else:
        issues.append("Full checks only available on Linux")

    if issues:
        print(f"  {RED}{SYM_WARN} Configuration issues found:{RESET}")
        for issue in issues:
            print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(issue, Fore.RED)}")
            add_log_alert("WARN", "Config Check", issue)
    else:
        print(f"  {GREEN}{SYM_CHECK} No critical configuration issues.{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 4: DATA & ACCESS PROTECTION
# ──────────────────────────────────────────────────────────

def data_encrypt():
    header_box("File Encryption / Decryption", Fore.YELLOW)
    if not HAS_CRYPTO:
        print(f"  {RED}{SYM_X} cryptography library required. Install: pip install cryptography{RESET}")
        return

    mode = input(f"  {c(f'(e)ncrypt or (d)ecrypt {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    filepath = input(f"  {c(f'File path {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not filepath or not os.path.exists(filepath):
        print(f"  {RED}{SYM_X} File not found.{RESET}")
        return

    password = input(f"  {c(f'Password {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not password:
        print(f"  {RED}{SYM_X} Password required.{RESET}")
        return

    salt = b"darkie_v2_salt"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    cipher = Fernet(key)

    try:
        if mode == "e":
            with open(filepath, "rb") as f:
                data = f.read()
            encrypted = cipher.encrypt(data)
            outpath = filepath + ".encrypted"
            with open(outpath, "wb") as f:
                f.write(encrypted)
            print(f"  {GREEN}{SYM_CHECK} Encrypted: {outpath}{RESET}")
            os.remove(filepath)
            print(f"  {YELLOW}Original file deleted: {filepath}{RESET}")
            add_log_alert("INFO", "Encryption", f"File encrypted: {filepath}")

        elif mode == "d":
            if not filepath.endswith(".encrypted"):
                print(f"  {YELLOW}Warning: file does not end with .encrypted{RESET}")
            with open(filepath, "rb") as f:
                data = f.read()
            decrypted = cipher.decrypt(data)
            outpath = filepath.replace(".encrypted", ".decrypted")
            with open(outpath, "wb") as f:
                f.write(decrypted)
            print(f"  {GREEN}{SYM_CHECK} Decrypted: {outpath}{RESET}")
            add_log_alert("INFO", "Decryption", f"File decrypted: {filepath}")

    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def data_password_strength():
    header_box("Password Strength Analyzer", Fore.YELLOW)
    password = input(f"  {c(f'Enter password to analyze {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not password:
        print(f"  {RED}No password provided.{RESET}")
        return

    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>\/?`~]', password))
    has_space = " " in password

    score = 0
    if length >= 8: score += 25
    if length >= 12: score += 15
    if length >= 16: score += 10
    if has_upper: score += 10
    if has_lower: score += 10
    if has_digit: score += 10
    if has_symbol: score += 15
    if has_space: score += 5

    # Check against common patterns
    common = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "monkey", "dragon",
              "master", "login", "abc123", "111111", "iloveyou", "sunshine", "princess"]
    is_common = password.lower() in common

    entropy = 0
    char_space = 0
    if has_lower: char_space += 26
    if has_upper: char_space += 26
    if has_digit: char_space += 10
    if has_symbol: char_space += 32
    if char_space > 0:
        entropy = length * (char_space.bit_length())

    info_lines = [
        f"  Length:       {c(str(length), Fore.CYAN)}",
        f"  Uppercase:    {c(SYM_CHECK if has_upper else SYM_X, Fore.GREEN if has_upper else Fore.RED)}",
        f"  Lowercase:    {c(SYM_CHECK if has_lower else SYM_X, Fore.GREEN if has_lower else Fore.RED)}",
        f"  Digits:       {c(SYM_CHECK if has_digit else SYM_X, Fore.GREEN if has_digit else Fore.RED)}",
        f"  Symbols:      {c(SYM_CHECK if has_symbol else SYM_X, Fore.GREEN if has_symbol else Fore.RED)}",
        f"  Entropy:      {c(f'{entropy} bits', Fore.CYAN)}",
        f"  Common:       {c(SYM_WARN + ' Yes' if is_common else SYM_CHECK + ' No', Fore.RED if is_common else Fore.GREEN)}",
    ]

    if score >= 80:
        grade = c(f"STRONG ({score}/100)", Fore.GREEN)
    elif score >= 50:
        grade = c(f"MODERATE ({score}/100)", Fore.YELLOW)
    else:
        grade = c(f"WEAK ({score}/100)", Fore.RED)

    info_lines.append(f"  Strength:     {grade}")

    info_box("Password Analysis", info_lines, Fore.YELLOW)
    print()


def data_bruteforce_detect():
    header_box("Brute-Force Detection", Fore.YELLOW)
    print(f"  {c('Checking for failed login attempts...', Fore.YELLOW)}")

    if platform.system().lower() == "linux":
        log_files = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]
        found = 0
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file) as f:
                        content = f.read()
                    failed = re.findall(r'(Failed password|authentication failure|Invalid user)', content, re.IGNORECASE)
                    if failed:
                        print(f"  {RED}{SYM_WARN} {log_file}: {len(failed)} failed attempts{RESET}")
                        found += len(failed)

                    ip_pattern = re.findall(r'Failed password for .* from (\S+)', content)
                    if ip_pattern:
                        ip_counts = defaultdict(int)
                        for ip in ip_pattern:
                            ip_counts[ip] += 1
                        print(f"  {c('Top attacking IPs:', Fore.CYAN)}")
                        for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:5]:
                            color = Fore.RED if count > 10 else Fore.YELLOW
                            print(f"    {c(ip, color)}: {c(str(count), Fore.CYAN)} attempts")
                except Exception:
                    pass
        if found == 0:
            print(f"  {GREEN}{SYM_CHECK} No brute-force patterns detected in logs.{RESET}")
        else:
            add_log_alert("WARN", "Bruteforce Detection", f"{found} total failed login attempts detected")
    else:
        try:
            r = subprocess.run(["lastb"], capture_output=True, text=True, timeout=5)
            if r.stdout.strip():
                print(f"  {YELLOW}Failed login records found:{RESET}")
                for line in r.stdout.splitlines()[:10]:
                    print(f"    {c(line, Fore.RED)}")
            else:
                print(f"  {GREEN}{SYM_CHECK} No failed login records.{RESET}")
        except Exception:
            print(f"  {YELLOW}Log analysis not supported on this platform.{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 5: ETHICAL HACKING & PENTEST
# ──────────────────────────────────────────────────────────

WEB_ATTACK_PATHS = [
    ("SQL Injection", "sql_test"),
    ("XSS", "xss_test"),
    ("Command Injection", "cmd_test"),
    ("Path Traversal", "path_test"),
]


def pentest_sqli():
    header_box("SQL Injection Detector", Fore.GREEN)
    url = input(f"  {c(f'Enter URL with parameter (e.g. http://example.com?id=1) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url:
        print(f"  {RED}No URL.{RESET}")
        return

    payloads = [
        ("' OR '1'='1", "Single quote + tautology"),
        ("' OR '1'='1' --", "Single quote + comment"),
        ("' UNION SELECT NULL--", "UNION NULL"),
        ("' UNION SELECT 1,2,3--", "UNION columns"),
        ("admin' --", "Auth bypass"),
        ("1' AND 1=1--", "AND true"),
        ("1' AND 1=2--", "AND false"),
        ('" OR "1"="1', "Double quote"),
        ("1' ORDER BY 1--", "ORDER BY probe"),
        ("1' ORDER BY 100--", "ORDER BY column count"),
    ]

    print(f"\n  {c(f'Testing {len(payloads)} SQL injection payloads...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    for payload, desc in payloads:
        try:
            test_url = url + ("" if "?" in url else "?") + payload
            r = requests.get(test_url, timeout=5, headers={"User-Agent": "DarkieV2/1.0"})
            indicators = []
            if r.status_code == 200 and any(x in r.text.lower() for x in ["sql", "mysql", "syntax", "odbc", "driver", "warning", "unexpected"]):
                indicators.append("DB error in response")
            if len(r.text) > 2000 and "1=1" in payload:
                indicators.append("Length anomaly")
            if indicators:
                print(f"  {RED}{SYM_WARN} Potential SQLi: {c(payload[:30], Fore.RED)} ({desc})")
                for ind in indicators:
                    print(f"    {c(ind, Fore.YELLOW)}")
                add_log_alert("HIGH", "Pentest SQLi", f"SQLi detected on {url}: {payload}")
            else:
                print(f"  {c(SYM_CHECK, Fore.GREEN)} {c(f'{desc:30s}', Fore.GREEN)} {c('No obvious injection', Fore.DIM)}")
        except Exception as e:
            print(f"  {c(SYM_X, Fore.RED)} {c(f'{desc:30s}', Fore.RED)} Error: {e}")
    print()


def pentest_xss():
    header_box("XSS Scanner", Fore.GREEN)
    url = input(f"  {c(f'Enter URL to test {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url:
        print(f"  {RED}No URL.{RESET}")
        return

    payloads = [
        ("<script>alert(1)</script>", "Basic script"),
        ("<img src=x onerror=alert(1)>", "Image onerror"),
        ('"><script>alert(1)</script>', "Tag break"),
        ("<svg onload=alert(1)>", "SVG onload"),
        ("javascript:alert(1)", "JS protocol"),
        ("'><img src=x onerror=alert(1)>", "Single quote break"),
    ]

    print(f"\n  {c(f'Testing {len(payloads)} XSS payloads...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    for payload, desc in payloads:
        try:
            r = requests.get(url, params={"q": payload} if "?" not in url else {},
                           timeout=5, headers={"User-Agent": "DarkieV2/1.0"})
            if payload in r.text:
                print(f"  {RED}{SYM_WARN} XSS Reflected: {c(desc, Fore.RED)}")
                add_log_alert("HIGH", "Pentest XSS", f"XSS reflected on {url}: {desc}")
            else:
                print(f"  {c(SYM_CHECK, Fore.GREEN)} {c(f'{desc:30s}', Fore.GREEN)} Not reflected")
        except Exception as e:
            print(f"  {c(SYM_X, Fore.RED)} {c(f'{desc:30s}', Fore.RED)} Error: {e}")
    print()


def pentest_path_traversal():
    header_box("Path Traversal Tester", Fore.GREEN)
    url = input(f"  {c(f'Enter base URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url:
        print(f"  {RED}No URL.{RESET}")
        return

    payloads = [
        ("../../etc/passwd", "/etc/passwd"),
        ("../../../etc/passwd", "/etc/passwd (deep)"),
        ("../../windows/win.ini", "Windows config"),
        ("../etc/passwd%00", "Null byte injection"),
        ("..%252f..%252fetc/passwd", "Double encoding"),
        ("../../../../../../../../etc/passwd", "Very deep traversal"),
    ]

    print(f"\n  {c(f'Testing {len(payloads)} path traversal payloads...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    for payload, desc in payloads:
        try:
            test_url = url.rstrip('/') + '/' + payload.lstrip('/')
            r = requests.get(test_url, timeout=5, headers={"User-Agent": "DarkieV2/1.0"})
            indicators = []
            if "root:" in r.text and ":/bin/" in r.text:
                indicators.append("/etc/passwd contents leaked")
            if "[fonts]" in r.text or "for 16-bit" in r.text:
                indicators.append("win.ini contents leaked")
            if len(r.text) > 500:
                indicators.append(f"Unusually large response ({len(r.text)}B)")
            if indicators:
                print(f"  {RED}{SYM_WARN} Path Traversal: {c(desc, Fore.RED)}")
                for ind in indicators:
                    print(f"    {c(ind, Fore.YELLOW)}")
                add_log_alert("HIGH", "Pentest Path", f"Path traversal on {url}: {desc}")
            else:
                print(f"  {c(SYM_CHECK, Fore.GREEN)} {c(f'{desc:30s}', Fore.GREEN)} No leak detected")
        except Exception as e:
            print(f"  {c(SYM_X, Fore.RED)} {c(f'{desc:30s}', Fore.RED)} Error: {e}")
    print()


def pentest_subdomain_takeover():
    header_box("Subdomain Takeover Checker", Fore.GREEN)
    print(f"  {c('Check if a domain is vulnerable to subdomain takeover.', Fore.CYAN)}")
    domain = input(f"  {c(f'Enter domain (e.g. example.com) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain:
        print(f"  {RED}No domain.{RESET}")
        return

    print(f"\n  {c('Checking for CNAME records pointing to unclaimed services...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    has_dig = shutil.which("dig")
    vulnerable_services = {
        "github.io": "GitHub Pages",
        "s3.amazonaws.com": "AWS S3",
        "s3-website": "AWS S3 Website",
        "cloudfront.net": "AWS CloudFront",
        "azurewebsites.net": "Azure App Service",
        "trafficmanager.net": "Azure Traffic Manager",
        "azureedge.net": "Azure CDN",
        "herokuapp.com": "Heroku",
        "herokudns.com": "Heroku DNS",
        "firebaseio.com": "Firebase",
        "appspot.com": "Google App Engine",
        "pantheonsite.io": "Pantheon",
        "wordpress.com": "WordPress.com",
        "squarespace.com": "Squarespace",
        "unbouncepages.com": "Unbounce",
        "statuspage.io": "StatusPage.io",
        "freshdesk.com": "Freshdesk",
        "zendesk.com": "Zendesk",
        "helpscoutdocs.com": "HelpScout",
        "atlassian.net": "Atlassian",
        "shopify.com": "Shopify",
        "myshopify.com": "Shopify",
        "thinkific.com": "Thinkific",
        "teachable.com": "Teachable",
    }

    # Check common subdomains
    common_subs = ["www", "blog", "shop", "store", "mail", "cdn", "api", "dev", "staging",
                   "test", "admin", "support", "help", "docs", "wiki", "status", "app", "m"]
    found_takeovers = []

    for sub in common_subs:
        fqdn = f"{sub}.{domain}"
        if has_dig:
            try:
                r = subprocess.run(["dig", "+short", "CNAME", fqdn], capture_output=True, text=True, timeout=5)
                cname = r.stdout.strip()
                if cname:
                    for service_pattern, service_name in vulnerable_services.items():
                        if service_pattern in cname.lower():
                            found_takeovers.append((fqdn, cname, service_name))
                            print(f"  {RED}{SYM_WARN} POTENTIAL TAKEOVER: {c(fqdn, Fore.RED)} -> {c(cname, Fore.YELLOW)} [{service_name}]{RESET}")
                            add_log_alert("CRITICAL", "Pentest Subdomain", f"Takeover risk: {fqdn} -> {cname} ({service_name})")
                            break
            except Exception:
                pass
        else:
            try:
                ip = socket.gethostbyname(fqdn)
                if ip.startswith("192.0.2.") or ip == "0.0.0.0":
                    found_takeovers.append((fqdn, ip, "Unclaimed IP range"))
                    print(f"  {RED}{SYM_WARN} POTENTIAL: {c(fqdn, Fore.RED)} -> {c(ip, Fore.YELLOW)} (unclaimed){RESET}")
            except socket.gaierror:
                pass

    if not found_takeovers:
        print(f"  {GREEN}{SYM_CHECK} No obvious subdomain takeover risks detected.{RESET}")
    else:
        print(f"\n  {RED}{SYM_WARN} {len(found_takeovers)} potential takeover(s) detected!{RESET}")
    print()


def pentest_http_methods():
    header_box("HTTP Methods Fuzzer", Fore.GREEN)
    url = input(f"  {c(f'Enter target URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url:
        print(f"  {RED}No URL.{RESET}")
        return

    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "CONNECT"]

    print(f"\n  {c('Testing HTTP methods...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    for method in methods:
        try:
            r = requests.request(method, url, timeout=5, headers={"User-Agent": "DarkieV2/1.0"})
            status = r.status_code
            if status not in (405, 501, 403, 404):
                color = Fore.RED if method in ("PUT", "DELETE", "TRACE", "CONNECT") else Fore.YELLOW
                print(f"  {c(f'{method:8s}', color)} {c(f'[{status}]', Fore.GREEN)} {c('Enabled', color)}")
                if method in ("PUT", "DELETE", "TRACE", "CONNECT"):
                    add_log_alert("WARN", "Pentest HTTP", f"Dangerous HTTP method enabled: {method} on {url}")
            else:
                print(f"  {c(f'{method:8s}', Fore.GREEN)} {c(f'[{status}]', YELLOW)} {c('Disabled', Fore.DIM)}")
        except Exception as e:
            print(f"  {c(f'{method:8s}', Fore.RED)} {c('Error:', Fore.RED)} {e}")
    print()


def pentest_bruteforce_login():
    header_box("Brute-Force Login Tester", Fore.GREEN)
    url = input(f"  {c(f'Enter login URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url:
        print(f"  {RED}No URL.{RESET}")
        return

    username_param = input(f"  {c(f'Username parameter (default: username) {SYM_PROMPT} ', Fore.CYAN)}").strip() or "username"
    password_param = input(f"  {c(f'Password parameter (default: password) {SYM_PROMPT} ', Fore.CYAN)}").strip() or "password"

    usernames = ["admin", "root", "user", "test", "administrator", "guest", "admin@admin.com"]
    passwords = ["admin", "password", "123456", "admin123", "root", "test", "password123",
                 "admin1", "P@ssw0rd", "letmein", "welcome", "qwerty"]

    print(f"\n  {c(f'Testing {len(usernames)} x {len(passwords)} combinations...', Fore.CYAN)}")
    print(f"  {c('This can be detected as an attack. Use only on authorized systems.', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    found = 0
    for user in usernames:
        for pwd in passwords:
            try:
                data = {username_param: user, password_param: pwd}
                r = requests.post(url, data=data, timeout=5, headers={"User-Agent": "DarkieV2/1.0"})
                r.raise_for_status()
                # Check for login success indicators
                success_indicators = ["dashboard", "welcome", "logout", "profile", "session"]
                if any(ind in r.text.lower() for ind in success_indicators) and r.status_code == 200:
                    print(f"  {RED}{SYM_WARN} LOGIN SUCCESS: {user}:{pwd}{RESET}")
                    add_log_alert("CRITICAL", "Pentest BruteForce", f"Login credentials found: {user}:{pwd}")
                    found += 1
                    break
            except requests.RequestException:
                pass
        if found:
            break

    if not found:
        print(f"  {GREEN}{SYM_CHECK} No weak credentials found (limited wordlist).{RESET}")
    print()


def pentest_instagram():
    header_box("Instagram OSINT & Auth Tester", Fore.MAGENTA)
    print(f"  {Back.RED}{Fore.WHITE} DISCLAIMER {Style.RESET_ALL}{Fore.YELLOW}  For educational use only. Test only your own accounts.{Style.RESET_ALL}\n")
    user = input(f"  {c(f'Instagram username {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not user: return
    print(f"\n  {c('Gathering public info...', Fore.CYAN)}")
    lines = [f"  Username: {c(user, Fore.GREEN)}"]
    try:
        r = requests.get(f"https://www.instagram.com/{user}/", timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (compatible; DarkieV2)"})
        if r.status_code == 200:
            import re
            m = re.search(r'window\.__INITIAL_STATE__\s*=\s*({.*?});', r.text, re.DOTALL)
            if m:
                import json
                data = json.loads(m.group(1))
                ep = data.get("entry_data", {}).get("ProfilePage", [{}])[0].get("graphql", {}).get("user", {})
                if ep.get("username") == user:
                    flw = ep.get("edge_followed_by", {}).get("count", "?")
                    flg = ep.get("edge_follow", {}).get("count", "?")
                    pst = ep.get("edge_owner_to_timeline_media", {}).get("count", "?")
                    lines.append(f"  Full Name: {c(ep.get('full_name', 'N/A'), Fore.CYAN)}")
                    lines.append(f"  Bio: {c(ep.get('biography', 'N/A')[:50], Fore.YELLOW)}")
                    lines.append(f"  Followers: {c(str(flw), Fore.MAGENTA)}")
                    lines.append(f"  Following: {c(str(flg), Fore.MAGENTA)}")
                    lines.append(f"  Posts: {c(str(pst), Fore.MAGENTA)}")
                    is_priv = ep.get("is_private", False)
                    lines.append(f"  Private: {c(str(is_priv), Fore.RED if is_priv else Fore.GREEN)}")
                    if ep.get("is_business_account"): lines.append(f"  Business: {c('Yes', Fore.GREEN)}")
                    if ep.get("is_verified"): lines.append(f"  Verified: {c(SYM_CHECK, Fore.GREEN)}")
                    ext_url = ep.get("external_url", "")
                    if ext_url: lines.append(f"  Website: {c(ext_url[:40], Fore.CYAN)}")
                    pfp = ep.get("profile_pic_url_hd", "")
                    if pfp: lines.append(f"  PFP: {c(pfp[:60]+'...', Fore.BLUE)}")
        else:
            lines.append(f"  Profile: {c('Private or not found', Fore.RED)}")
    except Exception as e:
        lines.append(f"  Error: {c(str(e)[:40], Fore.RED)}")
    info_box("Instagram Profile", lines, Fore.MAGENTA)
    print(f"  {c('Password Testing (educational):', Fore.YELLOW)}")
    print(f"  {c('Instagram uses:', Fore.RED)} bcrypt + rate limiting + 2FA — brute-force is not feasible.")
    print(f"  {c('Common passwords for', Fore.YELLOW)} '{user}': {c('instagram, 123456, password, qwerty, iloveyou', Fore.RED)}")
    print(f"  {c('Security tip:', Fore.GREEN)} Use unique 12+ char passwords with 2FA enabled.\n")


# ──────────────────────────────────────────────────────────
#  MODULE 6: SIEM & LOG ANALYSIS
# ──────────────────────────────────────────────────────────

def siem_log_analyzer():
    header_box("Log File Analyzer", Fore.CYAN)
    log_path = input(f"  {c(f'Enter log file path {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not log_path or not os.path.exists(log_path):
        print(f"  {RED}{SYM_X} File not found.{RESET}")
        return

    print(f"\n  {c('Analyzing log file...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    try:
        with open(log_path) as f:
            lines = f.readlines()
    except Exception as e:
        print(f"  {RED}{SYM_X} Error reading file: {e}{RESET}")
        return

    print(f"  Total lines:  {c(f'{len(lines):,}', Fore.GREEN)}")

    # Pattern analysis
    patterns = {
        "ERROR": 0, "WARN": 0, "INFO": 0, "DEBUG": 0,
        "FAILED": 0, "DENIED": 0, "TIMEOUT": 0, "TIMED OUT": 0,
    }

    ip_counts = defaultdict(int)
    error_lines = []

    for line in lines:
        line_upper = line.upper()
        for pattern in patterns:
            if pattern in line_upper:
                patterns[pattern] += 1
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        for ip in ips:
            ip_counts[ip] += 1
        if re.search(r'(ERROR|FAILED|DENIED|CRITICAL)', line_upper):
            error_lines.append(line.strip())

    print(f"\n  {c('Log Event Breakdown:', Fore.CYAN)}")
    for pattern, count in patterns.items():
        if count > 0:
            color = Fore.RED if pattern in ("ERROR", "FAILED", "DENIED") else Fore.YELLOW if pattern == "WARN" else Fore.GREEN
            bar = SYM_BLOCK_FULL * min(count // max(len(lines) // 20, 1), 20)
            print(f"    {c(f'{pattern:10s}', color)} {c(f'{count:>6d}', Fore.CYAN)} {c(bar, color)}")

    if error_lines:
        print(f"\n  {c('Sample Errors:', Fore.RED)}")
        for line in error_lines[:5]:
            print(f"    {c(line[:120], Fore.RED)}")

    if ip_counts:
        print(f"\n  {c('Top IPs:', Fore.CYAN)}")
        for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"    {c(f'{ip:15s}', Fore.GREEN)} {c(f'{count:>6d}', Fore.CYAN)} requests")

    print()


def siem_realtime_monitor():
    header_box("Real-time Log Monitor", Fore.CYAN)
    log_path = input(f"  {c(f'Enter log file path to tail {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not log_path or not os.path.exists(log_path):
        print(f"  {RED}{SYM_X} File not found.{RESET}")
        return

    duration = input(f"  {c(f'Monitor duration (seconds, default 30) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 30

    print(f"\n  {c(f'Tailing {log_path} for {duration}s...', Fore.CYAN)}")
    print(f"  {c('Press Ctrl+C to stop', Fore.YELLOW)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    try:
        with open(log_path) as f:
            f.seek(0, 2)
            start = time.time()
            while time.time() - start < duration:
                line = f.readline()
                if line:
                    line = line.strip()
                    if re.search(r'(ERROR|CRITICAL|FAILED)', line, re.IGNORECASE):
                        print(f"  {RED}{line[:120]}{RESET}")
                        add_log_alert("HIGH", "Log Monitor", line[:120])
                    elif re.search(r'(WARN|DENIED)', line, re.IGNORECASE):
                        print(f"  {YELLOW}{line[:120]}{RESET}")
                    else:
                        print(f"  {c(line[:120], Fore.GREEN)}")
                else:
                    time.sleep(0.1)
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}{SYM_WARN} Stopped by user{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def siem_alert_viewer():
    header_box("Alert Dashboard", Fore.CYAN)
    print(f"  {c('Recent security alerts:', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    if not LOG_ALERTS:
        print(f"  {YELLOW}No alerts generated yet. Run other modules to generate alerts.{RESET}")

    for alert in LOG_ALERTS[-30:]:
        ts = alert["timestamp"]
        level = alert["level"]
        src = alert["source"]
        msg = alert["message"][:80]

        if level in ("CRITICAL", "HIGH"):
            color = Fore.RED
        elif level == "WARN":
            color = Fore.YELLOW
        else:
            color = Fore.GREEN

        print(f"  {c(f'[{ts}]', Fore.CYAN)} {c(f'[{level:8s}]', color)} {c(f'{src:20s}', Fore.MAGENTA)} {c(msg, Fore.GREEN)}")

    print(f"\n  {c(f'Total alerts: {len(LOG_ALERTS)}', Fore.CYAN)}")
    print()


def siem_threat_patterns():
    header_box("Threat Pattern Detection", Fore.CYAN)
    print(f"  {c('Scanning for known threat patterns...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    patterns_found = []
    check_paths = []

    if platform.system().lower() == "linux":
        check_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
                       "/var/log/apache2/access.log", "/var/log/nginx/access.log"]

    for log_path in check_paths:
        if os.path.exists(log_path):
            try:
                with open(log_path) as f:
                    content = f.read()

                # Check for specific threats
                if re.search(r'Failed password.*root', content):
                    patterns_found.append(("SSH Brute-force (root)", log_path))
                if re.search(r'Invalid user', content):
                    patterns_found.append(("SSH User Enumeration", log_path))
                if re.search(r'Possible SYN flooding', content):
                    patterns_found.append(("SYN Flood / DDoS", log_path))
                if re.search(r'authentication failure', content):
                    patterns_found.append(("Auth Failures", log_path))
                if re.search(r'Did not receive identification', content):
                    patterns_found.append(("SSH Scan Probe", log_path))
                if re.search(r'pam_unix.*authentication failure', content):
                    patterns_found.append(("PAM Auth Failures", log_path))
            except Exception:
                pass

    if patterns_found:
        print(f"  {RED}{SYM_WARN} Threat patterns detected:{RESET}")
        for pattern, source in patterns_found:
            print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(pattern, Fore.RED)} ({c(source, Fore.CYAN)})")
            add_log_alert("HIGH", "Threat Detection", f"Pattern: {pattern} in {source}")
    else:
        print(f"  {GREEN}{SYM_CHECK} No common threat patterns detected in logs.{RESET}")

    print(f"\n  {c('Total alerts in this session:', Fore.CYAN)} {c(str(len(LOG_ALERTS)), Fore.GREEN)}")
    print()


# ──────────────────────────────────────────────────────────
#  LEGACY MODULES (v1.2 / v1.3 features)
# ──────────────────────────────────────────────────────────

COUNTRY_CODES = {
    "1": "US/CA", "44": "UK", "91": "India", "86": "China", "81": "Japan",
    "49": "Germany", "33": "France", "39": "Italy", "34": "Spain", "7": "Russia",
    "55": "Brazil", "61": "Australia", "82": "Korea", "31": "Netherlands",
    "46": "Sweden", "41": "Switzerland", "45": "Denmark", "47": "Norway",
    "358": "Finland", "48": "Poland", "90": "Turkey", "966": "Saudi Arabia",
    "971": "UAE", "972": "Israel", "27": "South Africa", "52": "Mexico",
    "54": "Argentina", "56": "Chile", "57": "Colombia", "351": "Portugal",
    "30": "Greece", "353": "Ireland", "43": "Austria", "32": "Belgium",
}

NPA_DB = {
    "201": ("Jersey City", "NJ", "Eastern"), "202": ("Washington", "DC", "Eastern"),
    "203": ("Bridgeport", "CT", "Eastern"), "212": ("New York City", "NY", "Eastern"),
    "213": ("Los Angeles", "CA", "Pacific"), "214": ("Dallas", "TX", "Central"),
    "215": ("Philadelphia", "PA", "Eastern"), "310": ("Los Angeles", "CA", "Pacific"),
    "312": ("Chicago", "IL", "Central"), "313": ("Detroit", "MI", "Eastern"),
    "314": ("St. Louis", "MO", "Central"), "315": ("Syracuse", "NY", "Eastern"),
    "316": ("Wichita", "KS", "Central"), "317": ("Indianapolis", "IN", "Eastern"),
    "323": ("Los Angeles", "CA", "Pacific"), "347": ("Brooklyn", "NY", "Eastern"),
    "408": ("San Jose", "CA", "Pacific"), "412": ("Pittsburgh", "PA", "Eastern"),
    "413": ("Springfield", "MA", "Eastern"), "414": ("Milwaukee", "WI", "Central"),
    "415": ("San Francisco", "CA", "Pacific"), "416": ("Toronto", "ON", "Eastern"),
    "417": ("Springfield", "MO", "Central"), "425": ("Bellevue", "WA", "Pacific"),
    "443": ("Baltimore", "MD", "Eastern"), "469": ("Plano", "TX", "Central"),
    "480": ("Phoenix", "AZ", "Mountain"), "503": ("Portland", "OR", "Pacific"),
    "504": ("New Orleans", "LA", "Central"), "510": ("Oakland", "CA", "Pacific"),
    "512": ("Austin", "TX", "Central"), "513": ("Cincinnati", "OH", "Eastern"),
    "515": ("Des Moines", "IA", "Central"), "516": ("Hempstead", "NY", "Eastern"),
    "530": ("Redding", "CA", "Pacific"), "540": ("Roanoke", "VA", "Eastern"),
    "541": ("Eugene", "OR", "Pacific"), "551": ("Jersey City", "NJ", "Eastern"),
    "559": ("Fresno", "CA", "Pacific"), "561": ("West Palm Beach", "FL", "Eastern"),
    "562": ("Long Beach", "CA", "Pacific"), "570": ("Scranton", "PA", "Eastern"),
    "571": ("Arlington", "VA", "Eastern"), "585": ("Rochester", "NY", "Eastern"),
    "586": ("Warren", "MI", "Eastern"), "602": ("Phoenix", "AZ", "Mountain"),
    "603": ("Manchester", "NH", "Eastern"), "605": ("Sioux Falls", "SD", "Central"),
    "606": ("Ashland", "KY", "Eastern"), "607": ("Binghamton", "NY", "Eastern"),
    "608": ("Madison", "WI", "Central"), "609": ("Trenton", "NJ", "Eastern"),
    "610": ("Allentown", "PA", "Eastern"), "612": ("Minneapolis", "MN", "Central"),
    "614": ("Columbus", "OH", "Eastern"), "615": ("Nashville", "TN", "Central"),
    "616": ("Grand Rapids", "MI", "Eastern"), "617": ("Boston", "MA", "Eastern"),
    "618": ("Belleville", "IL", "Central"), "619": ("San Diego", "CA", "Pacific"),
    "626": ("Pasadena", "CA", "Pacific"), "630": ("Naperville", "IL", "Central"),
    "631": ("Ronkonkoma", "NY", "Eastern"), "646": ("Manhattan", "NY", "Eastern"),
    "647": ("Toronto", "ON", "Eastern"), "650": ("Palo Alto", "CA", "Pacific"),
    "651": ("St. Paul", "MN", "Central"), "660": ("Sedalia", "MO", "Central"),
    "661": ("Bakersfield", "CA", "Pacific"), "662": ("Tupelo", "MS", "Central"),
    "669": ("San Jose", "CA", "Pacific"), "678": ("Atlanta", "GA", "Eastern"),
    "682": ("Fort Worth", "TX", "Central"), "701": ("Fargo", "ND", "Central"),
    "702": ("Las Vegas", "NV", "Pacific"), "703": ("Arlington", "VA", "Eastern"),
    "704": ("Charlotte", "NC", "Eastern"), "706": ("Augusta", "GA", "Eastern"),
    "707": ("Santa Rosa", "CA", "Pacific"), "708": ("Oak Lawn", "IL", "Central"),
    "712": ("Sioux City", "IA", "Central"), "713": ("Houston", "TX", "Central"),
    "714": ("Anaheim", "CA", "Pacific"), "715": ("Wausau", "WI", "Central"),
    "716": ("Buffalo", "NY", "Eastern"), "717": ("Harrisburg", "PA", "Eastern"),
    "718": ("Brooklyn", "NY", "Eastern"), "719": ("Colorado Springs", "CO", "Mountain"),
    "720": ("Denver", "CO", "Mountain"), "724": ("New Kensington", "PA", "Eastern"),
    "727": ("St. Petersburg", "FL", "Eastern"), "731": ("Jackson", "TN", "Central"),
    "732": ("New Brunswick", "NJ", "Eastern"), "734": ("Ann Arbor", "MI", "Eastern"),
    "740": ("Zanesville", "OH", "Eastern"), "747": ("Los Angeles", "CA", "Pacific"),
    "754": ("Fort Lauderdale", "FL", "Eastern"), "757": ("Virginia Beach", "VA", "Eastern"),
    "760": ("Palm Springs", "CA", "Pacific"), "762": ("Augusta", "GA", "Eastern"),
    "763": ("Minneapolis", "MN", "Central"), "765": ("Lafayette", "IN", "Eastern"),
    "770": ("Marietta", "GA", "Eastern"), "772": ("Fort Pierce", "FL", "Eastern"),
    "773": ("Chicago", "IL", "Central"), "774": ("New Bedford", "MA", "Eastern"),
    "775": ("Reno", "NV", "Pacific"), "781": ("Boston", "MA", "Eastern"),
    "785": ("Topeka", "KS", "Central"), "786": ("Miami", "FL", "Eastern"),
    "787": ("San Juan", "PR", "Atlantic"), "801": ("Salt Lake City", "UT", "Mountain"),
    "802": ("Burlington", "VT", "Eastern"), "803": ("Columbia", "SC", "Eastern"),
    "804": ("Richmond", "VA", "Eastern"), "805": ("Santa Barbara", "CA", "Pacific"),
    "806": ("Amarillo", "TX", "Central"), "808": ("Honolulu", "HI", "Pacific"),
    "810": ("Flint", "MI", "Eastern"), "812": ("Evansville", "IN", "Eastern"),
    "813": ("Tampa", "FL", "Eastern"), "814": ("Erie", "PA", "Eastern"),
    "815": ("Rockford", "IL", "Central"), "816": ("Kansas City", "MO", "Central"),
    "817": ("Fort Worth", "TX", "Central"), "818": ("Los Angeles", "CA", "Pacific"),
    "828": ("Asheville", "NC", "Eastern"), "830": ("New Braunfels", "TX", "Central"),
    "831": ("Monterey", "CA", "Pacific"), "832": ("Houston", "TX", "Central"),
    "843": ("Charleston", "SC", "Eastern"), "845": ("New City", "NY", "Eastern"),
    "847": ("Evanston", "IL", "Central"), "848": ("New Brunswick", "NJ", "Eastern"),
    "850": ("Tallahassee", "FL", "Eastern"), "856": ("Camden", "NJ", "Eastern"),
    "857": ("Boston", "MA", "Eastern"), "858": ("San Diego", "CA", "Pacific"),
    "859": ("Lexington", "KY", "Eastern"), "860": ("Hartford", "CT", "Eastern"),
    "862": ("Newark", "NJ", "Eastern"), "863": ("Lakeland", "FL", "Eastern"),
    "864": ("Greenville", "SC", "Eastern"), "865": ("Knoxville", "TN", "Eastern"),
    "870": ("Jonesboro", "AR", "Central"), "901": ("Memphis", "TN", "Central"),
    "902": ("Halifax", "NS", "Atlantic"), "903": ("Tyler", "TX", "Central"),
    "904": ("Jacksonville", "FL", "Eastern"), "905": ("Mississauga", "ON", "Eastern"),
    "906": ("Marquette", "MI", "Eastern"), "907": ("Anchorage", "AK", "Alaska"),
    "908": ("Elizabeth", "NJ", "Eastern"), "909": ("San Bernardino", "CA", "Pacific"),
    "910": ("Wilmington", "NC", "Eastern"), "912": ("Savannah", "GA", "Eastern"),
    "913": ("Kansas City", "KS", "Central"), "914": ("White Plains", "NY", "Eastern"),
    "915": ("El Paso", "TX", "Mountain"), "916": ("Sacramento", "CA", "Pacific"),
    "917": ("New York City", "NY", "Eastern"), "918": ("Tulsa", "OK", "Central"),
    "919": ("Raleigh", "NC", "Eastern"), "920": ("Green Bay", "WI", "Central"),
    "925": ("Concord", "CA", "Pacific"), "928": ("Flagstaff", "AZ", "Mountain"),
    "929": ("New York City", "NY", "Eastern"), "931": ("Clarksville", "TN", "Central"),
    "936": ("Huntsville", "TX", "Central"), "937": ("Dayton", "OH", "Eastern"),
    "940": ("Wichita Falls", "TX", "Central"), "941": ("Sarasota", "FL", "Eastern"),
    "947": ("Farmington Hills", "MI", "Eastern"), "949": ("Irvine", "CA", "Pacific"),
    "951": ("Riverside", "CA", "Pacific"), "952": ("Bloomington", "MN", "Central"),
    "954": ("Fort Lauderdale", "FL", "Eastern"), "956": ("Laredo", "TX", "Central"),
    "959": ("Hartford", "CT", "Eastern"), "970": ("Fort Collins", "CO", "Mountain"),
    "971": ("Portland", "OR", "Pacific"), "972": ("Irving", "TX", "Central"),
    "973": ("Newark", "NJ", "Eastern"), "978": ("Lowell", "MA", "Eastern"),
    "979": ("Bryan", "TX", "Central"), "980": ("Charlotte", "NC", "Eastern"),
    "984": ("Raleigh", "NC", "Eastern"), "985": ("Hammond", "LA", "Central"),
}

SOCIAL_PLATFORMS = {
    "GitHub": ("https://github.com/{}", "user not found"),
    "Twitter/X": ("https://x.com/{}", "this account doesn"),
    "Instagram": ("https://www.instagram.com/{}/", "page isn't available"),
    "Reddit": ("https://www.reddit.com/user/{}", "page not found"),
    "YouTube": ("https://www.youtube.com/@{}/videos", "page not found"),
    "LinkedIn": ("https://www.linkedin.com/in/{}", "page not found"),
    "Pinterest": ("https://www.pinterest.com/{}/", "not found"),
    "TikTok": ("https://www.tiktok.com/@{}", "couldn't find this account"),
    "Snapchat": ("https://www.snapchat.com/add/{}", "couldn't find"),
    "Telegram": ("https://t.me/{}", "Sorry, this chat"),
    "Medium": ("https://medium.com/@{}", "page not found"),
    "Dev.to": ("https://dev.to/{}", "page not found"),
    "Twitch": ("https://www.twitch.tv/{}", "page not found"),
    "Facebook": ("https://www.facebook.com/{}/", "page not found"),
    "Tumblr": ("https://{}.tumblr.com", "there's nothing here"),
    "Patreon": ("https://www.patreon.com/{}", "page not found"),
    "Keybase": ("https://keybase.io/{}", "not found"),
    "About.me": ("https://about.me/{}", "not found"),
    "Behance": ("https://www.behance.net/{}", "page not found"),
    "Dribbble": ("https://dribbble.com/{}", "page not found"),
    "Flickr": ("https://www.flickr.com/people/{}/", "not found"),
    "Vimeo": ("https://vimeo.com/{}", "page not found"),
    "SoundCloud": ("https://soundcloud.com/{}", "page not found"),
    "Bandcamp": ("https://{}.bandcamp.com", "page not found"),
    "Replit": ("https://replit.com/@{}", "page not found"),
    "Codepen": ("https://codepen.io/{}", "page not found"),
    "HackerNews": ("https://news.ycombinator.com/user?id={}", "No such user"),
    "ProductHunt": ("https://www.producthunt.com/@{}", "page not found"),
    "BitBucket": ("https://bitbucket.org/{}/", "page not found"),
    "GitLab": ("https://gitlab.com/{}", "page not found"),
    "Steam": ("https://steamcommunity.com/id/{}/", "The specified profile could not be found"),
    "Spotify": ("https://open.spotify.com/user/{}", "page not found"),
    "Last.fm": ("https://www.last.fm/user/{}", "page not found"),
    "Fiverr": ("https://www.fiverr.com/{}", "page not found"),
    "GoodReads": ("https://www.goodreads.com/{}", "page not found"),
    "Wikipedia": ("https://en.wikipedia.org/wiki/User:{}", "page not found"),
    "Etsy": ("https://www.etsy.com/shop/{}", "page not found"),
    "HackerOne": ("https://hackerone.com/{}", "not found"),
    "Bugcrowd": ("https://bugcrowd.com/{}", "page not found"),
}

SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","admin","api","dev","test","staging","blog","cdn","static",
    "assets","img","css","js","download","support","help","docs","wiki","forum",
    "shop","store","app","mobile","webmail","cpanel","whm","ns1","ns2","smtp",
    "pop","imap","mx","calendar","drive","cloud","git","jenkins","jira","confluence",
    "redis","mongo","mysql","db","database","backup","monitor","status","analytics",
    "tracking","live","stream","news","info","about","contact","careers","jobs",
    "portal","my","client","clients","login","register","account","billing","payment",
    "orders","cart","checkout","ssl","secure","vpn","proxy","gateway","firewall",
    "docker","k8s","kubernetes","swarm","gitlab","bitbucket","svn","bugzilla",
    "demo","example","beta","alpha","prod","production","qa","quality","survey",
    "sso","auth","oauth","ldap","saml","idp","okta",
]
SUBDOMAIN_WORDLIST = list(dict.fromkeys(SUBDOMAIN_WORDLIST))

MINECRAFT_PORTS = [25565, 25566, 25575, 19132, 19133]
STRESS_PORTS = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 5601, 9090, 3000, 8000, 8888]
MINECRAFT_PAYLOADS = [
    b"\x00\xff\xff\xff\xff\x01\x00", b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff",
    b"\xfe\x01\x00", b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x00" * 64, b"\xff" * 128,
]

TOLLFREE_PREFIXES = ["800", "833", "844", "855", "866", "877", "888"]

INDIAN_NDC = {
    "9810": ("New Delhi", "Delhi", "Delhi NCR"), "9811": ("New Delhi", "Delhi", "Delhi NCR"),
    "9818": ("New Delhi", "Delhi", "Delhi NCR"), "9819": ("New Delhi", "Delhi", "Delhi NCR"),
    "9868": ("New Delhi", "Delhi", "Delhi NCR"), "9871": ("New Delhi", "Delhi", "Delhi NCR"),
    "9873": ("New Delhi", "Delhi", "Delhi NCR"), "9874": ("New Delhi", "Delhi", "Delhi NCR"),
    "9910": ("New Delhi", "Delhi", "Delhi NCR"), "9911": ("New Delhi", "Delhi", "Delhi NCR"),
    "9958": ("New Delhi", "Delhi", "Delhi NCR"), "9968": ("New Delhi", "Delhi", "Delhi NCR"),
    "9971": ("New Delhi", "Delhi", "Delhi NCR"),
    "9820": ("Mumbai", "Maharashtra", "Mumbai"), "9821": ("Mumbai", "Maharashtra", "Mumbai"),
    "9833": ("Mumbai", "Maharashtra", "Mumbai"), "9867": ("Mumbai", "Maharashtra", "Mumbai"),
    "9869": ("Mumbai", "Maharashtra", "Mumbai"), "9870": ("Mumbai", "Maharashtra", "Mumbai"),
    "9920": ("Mumbai", "Maharashtra", "Mumbai"), "9930": ("Mumbai", "Maharashtra", "Mumbai"),
    "9987": ("Mumbai", "Maharashtra", "Mumbai"),
    "9830": ("Kolkata", "West Bengal", "Kolkata"), "9831": ("Kolkata", "West Bengal", "Kolkata"),
    "9836": ("Kolkata", "West Bengal", "Kolkata"), "9874": ("Kolkata", "West Bengal", "Kolkata"),
    "9875": ("Kolkata", "West Bengal", "Kolkata"), "9903": ("Kolkata", "West Bengal", "Kolkata"),
    "9932": ("Kolkata", "West Bengal", "Kolkata"), "9986": ("Kolkata", "West Bengal", "Kolkata"),
    "9840": ("Chennai", "Tamil Nadu", "Chennai"), "9841": ("Chennai", "Tamil Nadu", "Chennai"),
    "9884": ("Chennai", "Tamil Nadu", "Chennai"), "9886": ("Chennai", "Tamil Nadu", "Chennai"),
    "9887": ("Chennai", "Tamil Nadu", "Chennai"), "9940": ("Chennai", "Tamil Nadu", "Chennai"),
    "9962": ("Chennai", "Tamil Nadu", "Chennai"),
    "9845": ("Bangalore", "Karnataka", "Bangalore"), "9844": ("Bangalore", "Karnataka", "Bangalore"),
    "9880": ("Bangalore", "Karnataka", "Bangalore"), "9900": ("Bangalore", "Karnataka", "Bangalore"),
    "9945": ("Bangalore", "Karnataka", "Bangalore"), "9980": ("Bangalore", "Karnataka", "Bangalore"),
    "9848": ("Hyderabad", "Telangana", "Hyderabad"), "9849": ("Hyderabad", "Telangana", "Hyderabad"),
    "9885": ("Hyderabad", "Telangana", "Hyderabad"), "9908": ("Hyderabad", "Telangana", "Hyderabad"),
    "9948": ("Hyderabad", "Telangana", "Hyderabad"), "9949": ("Hyderabad", "Telangana", "Hyderabad"),
    "9989": ("Hyderabad", "Telangana", "Hyderabad"),
    "9825": ("Ahmedabad", "Gujarat", "Gujarat"), "9824": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9879": ("Ahmedabad", "Gujarat", "Gujarat"), "9925": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9978": ("Ahmedabad", "Gujarat", "Gujarat"), "9998": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9822": ("Pune", "Maharashtra", "Pune"), "9850": ("Pune", "Maharashtra", "Pune"),
    "9881": ("Pune", "Maharashtra", "Pune"), "9970": ("Pune", "Maharashtra", "Pune"),
    "9922": ("Pune", "Maharashtra", "Pune"), "9923": ("Pune", "Maharashtra", "Pune"),
    "9829": ("Jaipur", "Rajasthan", "Rajasthan"), "9928": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9950": ("Jaipur", "Rajasthan", "Rajasthan"), "9982": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9983": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9815": ("Chandigarh", "Chandigarh", "Chandigarh"), "9872": ("Chandigarh", "Chandigarh", "Chandigarh"),
    "9888": ("Chandigarh", "Chandigarh", "Chandigarh"), "9988": ("Chandigarh", "Chandigarh", "Chandigarh"),
    "9838": ("Lucknow", "Uttar Pradesh", "UP East"), "9839": ("Lucknow", "Uttar Pradesh", "UP East"),
    "9935": ("Lucknow", "Uttar Pradesh", "UP East"), "9984": ("Lucknow", "Uttar Pradesh", "UP East"),
    "9450": ("Lucknow", "Uttar Pradesh", "UP East"),
    "9835": ("Patna", "Bihar", "Bihar"), "9931": ("Patna", "Bihar", "Bihar"),
    "9934": ("Patna", "Bihar", "Bihar"), "9973": ("Bihar", "Bihar", "Bihar"),
    "9893": ("Bhopal", "Madhya Pradesh", "MP"), "9892": ("Bhopal", "Madhya Pradesh", "MP"),
    "9993": ("Bhopal", "Madhya Pradesh", "MP"), "9826": ("Indore", "Madhya Pradesh", "MP"),
    "9827": ("Indore", "Madhya Pradesh", "MP"),
    "9414": ("Lucknow", "Uttar Pradesh", "UP"), "9415": ("Lucknow", "Uttar Pradesh", "UP"),
    "9416": ("Agra", "Uttar Pradesh", "UP"), "9417": ("Varanasi", "Uttar Pradesh", "UP"),
    "9418": ("Kanpur", "Uttar Pradesh", "UP"), "9419": ("Allahabad", "Uttar Pradesh", "UP"),
    "9422": ("Nagpur", "Maharashtra", "Vidarbha"), "9423": ("Nagpur", "Maharashtra", "Vidarbha"),
    "9424": ("Nagpur", "Maharashtra", "Vidarbha"),
    "9425": ("Aurangabad", "Maharashtra", "Marathwada"),
    "9426": ("Nashik", "Maharashtra", "North Maharashtra"),
    "9427": ("Kolhapur", "Maharashtra", "West Maharashtra"),
    "9428": ("Amravati", "Maharashtra", "Vidarbha"),
    "9431": ("Guwahati", "Assam", "Assam"), "9435": ("Guwahati", "Assam", "Assam"),
    "9437": ("Shillong", "Meghalaya", "NE"),
    "9438": ("Imphal", "Manipur", "NE"),
    "9439": ("Agartala", "Tripura", "NE"),
    "9440": ("Kochi", "Kerala", "Kerala"), "9446": ("Kochi", "Kerala", "Kerala"),
    "9447": ("Thiruvananthapuram", "Kerala", "Kerala"),
    "9448": ("Kozhikode", "Kerala", "Kerala"),
    "9450": ("Varanasi", "Uttar Pradesh", "UP East"),
    "9451": ("Gorakhpur", "Uttar Pradesh", "UP East"),
    "9452": ("Faizabad", "Uttar Pradesh", "UP East"),
    "9453": ("Jhansi", "Uttar Pradesh", "UP"),
    "9455": ("Moradabad", "Uttar Pradesh", "UP West"),
    "9460": ("Ganganagar", "Rajasthan", "Rajasthan"),
    "9461": ("Bikaner", "Rajasthan", "Rajasthan"),
    "9462": ("Jodhpur", "Rajasthan", "Rajasthan"),
    "9464": ("Ajmer", "Rajasthan", "Rajasthan"),
    "9465": ("Kota", "Rajasthan", "Rajasthan"),
    "9479": ("Ranchi", "Jharkhand", "Jharkhand"),
    "9480": ("Bangalore", "Karnataka", "Bangalore"),
    "9481": ("Mysore", "Karnataka", "Karnataka"),
    "9482": ("Mangalore", "Karnataka", "Karnataka"),
    "9483": ("Hubli", "Karnataka", "Karnataka"),
    "9484": ("Belgaum", "Karnataka", "Karnataka"),
    "9490": ("Vijayawada", "Andhra Pradesh", "AP"),
    "9491": ("Visakhapatnam", "Andhra Pradesh", "AP"),
    "9492": ("Guntur", "Andhra Pradesh", "AP"),
    "9493": ("Tirupati", "Andhra Pradesh", "AP"),
    "9494": ("Kurnool", "Andhra Pradesh", "AP"),
    "9495": ("Warangal", "Telangana", "Telangana"),
    "9496": ("Kakinada", "Andhra Pradesh", "AP"),
    "9497": ("Rajahmundry", "Andhra Pradesh", "AP"),
    "9498": ("Nellore", "Andhra Pradesh", "AP"),
    "9500": ("Chandigarh", "Chandigarh", "Chandigarh"),
    "9501": ("Ludhiana", "Punjab", "Punjab"),
    "9502": ("Jalandhar", "Punjab", "Punjab"),
    "9503": ("Amritsar", "Punjab", "Punjab"),
    "9504": ("Bathinda", "Punjab", "Punjab"),
    "9505": ("Patiala", "Punjab", "Punjab"),
    "9510": ("Mohan", "Himachal Pradesh", "HP"),
    "9533": ("Shimla", "Himachal Pradesh", "HP"),
    "9535": ("Jammu", "Jammu & Kashmir", "J&K"),
    "9541": ("Dehradun", "Uttarakhand", "Uttarakhand"),
    "9542": ("Haridwar", "Uttarakhand", "Uttarakhand"),
    "9550": ("Lucknow", "Uttar Pradesh", "UP"),
    "9551": ("Kanpur", "Uttar Pradesh", "UP"),
    "9552": ("Allahabad", "Uttar Pradesh", "UP"),
    "9553": ("Varanasi", "Uttar Pradesh", "UP"),
    "9554": ("Agra", "Uttar Pradesh", "UP"),
    "9555": ("Aligarh", "Uttar Pradesh", "UP"),
    "9560": ("Kozhikode", "Kerala", "Kerala"),
    "9561": ("Kochi", "Kerala", "Kerala"),
    "9562": ("Thrissur", "Kerala", "Kerala"),
    "9563": ("Thiruvananthapuram", "Kerala", "Kerala"),
    "9564": ("Kollam", "Kerala", "Kerala"),
    "9565": ("Kannur", "Kerala", "Kerala"),
    "9570": ("Tirunelveli", "Tamil Nadu", "Tamil Nadu"),
    "9571": ("Madurai", "Tamil Nadu", "Tamil Nadu"),
    "9572": ("Coimbatore", "Tamil Nadu", "Tamil Nadu"),
    "9573": ("Salem", "Tamil Nadu", "Tamil Nadu"),
    "9574": ("Trichy", "Tamil Nadu", "Tamil Nadu"),
    "9575": ("Vellore", "Tamil Nadu", "Tamil Nadu"),
    "9580": ("Jammu", "Jammu & Kashmir", "J&K"),
    "9581": ("Srinagar", "Jammu & Kashmir", "J&K"),
    "9590": ("Srinagar", "Jammu & Kashmir", "J&K"),
    "9591": ("Anantnag", "Jammu & Kashmir", "J&K"),
    "9592": ("Baramulla", "Jammu & Kashmir", "J&K"),
    "9593": ("Jammu", "Jammu & Kashmir", "J&K"),
    "9596": ("Shimla", "Himachal Pradesh", "HP"),
    "9597": ("Dharamshala", "Himachal Pradesh", "HP"),
    "9598": ("Solan", "Himachal Pradesh", "HP"),
    "9600": ("Ludhiana", "Punjab", "Punjab"),
    "9601": ("Jalandhar", "Punjab", "Punjab"),
    "9602": ("Amritsar", "Punjab", "Punjab"),
    "9603": ("Bathinda", "Punjab", "Punjab"),
    "9604": ("Patiala", "Punjab", "Punjab"),
    "9605": ("Mohali", "Punjab", "Punjab"),
    "9610": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9611": ("Jodhpur", "Rajasthan", "Rajasthan"),
    "9612": ("Kota", "Rajasthan", "Rajasthan"),
    "9613": ("Bikaner", "Rajasthan", "Rajasthan"),
    "9614": ("Udaipur", "Rajasthan", "Rajasthan"),
    "9620": ("Bangalore", "Karnataka", "Bangalore"),
    "9621": ("Mysore", "Karnataka", "Karnataka"),
    "9622": ("Mangalore", "Karnataka", "Karnataka"),
    "9623": ("Hubli", "Karnataka", "Karnataka"),
    "9624": ("Belgaum", "Karnataka", "Karnataka"),
    "9625": ("Gulbarga", "Karnataka", "Karnataka"),
    "9630": ("Mumbai", "Maharashtra", "Mumbai"),
    "9631": ("Pune", "Maharashtra", "Pune"),
    "9632": ("Nagpur", "Maharashtra", "Vidarbha"),
    "9633": ("Nashik", "Maharashtra", "North Maharashtra"),
    "9634": ("Aurangabad", "Maharashtra", "Marathwada"),
    "9635": ("Kolhapur", "Maharashtra", "West Maharashtra"),
    "9640": ("Hyderabad", "Telangana", "Hyderabad"),
    "9641": ("Warangal", "Telangana", "Telangana"),
    "9642": ("Nizamabad", "Telangana", "Telangana"),
    "9643": ("Khammam", "Telangana", "Telangana"),
    "9650": ("Chennai", "Tamil Nadu", "Chennai"),
    "9651": ("Coimbatore", "Tamil Nadu", "Tamil Nadu"),
    "9652": ("Madurai", "Tamil Nadu", "Tamil Nadu"),
    "9653": ("Trichy", "Tamil Nadu", "Tamil Nadu"),
    "9654": ("Salem", "Tamil Nadu", "Tamil Nadu"),
    "9655": ("Tirunelveli", "Tamil Nadu", "Tamil Nadu"),
    "9660": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9661": ("Vadodara", "Gujarat", "Gujarat"),
    "9662": ("Surat", "Gujarat", "Gujarat"),
    "9663": ("Rajkot", "Gujarat", "Gujarat"),
    "9664": ("Bhavnagar", "Gujarat", "Gujarat"),
    "9670": ("Kolkata", "West Bengal", "Kolkata"),
    "9671": ("Siliguri", "West Bengal", "West Bengal"),
    "9672": ("Durgapur", "West Bengal", "West Bengal"),
    "9673": ("Asansol", "West Bengal", "West Bengal"),
    "9674": ("Burdwan", "West Bengal", "West Bengal"),
    "9680": ("Guwahati", "Assam", "Assam"),
    "9681": ("Silchar", "Assam", "Assam"),
    "9685": ("Shillong", "Meghalaya", "NE"),
    "9686": ("Imphal", "Manipur", "NE"),
    "9689": ("Agartala", "Tripura", "NE"),
    "9690": ("Raipur", "Chhattisgarh", "CG"),
    "9691": ("Bhilai", "Chhattisgarh", "CG"),
    "9692": ("Bilaspur", "Chhattisgarh", "CG"),
    "9693": ("Jagdalpur", "Chhattisgarh", "CG"),
    "9700": ("Hyderabad", "Telangana", "Hyderabad"),
    "9701": ("Hyderabad", "Telangana", "Hyderabad"),
    "9702": ("Warangal", "Telangana", "Telangana"),
    "9703": ("Nizamabad", "Telangana", "Telangana"),
    "9704": ("Khammam", "Telangana", "Telangana"),
    "9705": ("Karimnagar", "Telangana", "Telangana"),
    "9711": ("Delhi", "Delhi", "Delhi NCR"),
    "9712": ("Delhi", "Delhi", "Delhi NCR"),
    "9713": ("Delhi", "Delhi", "Delhi NCR"),
    "9714": ("Delhi", "Delhi", "Delhi NCR"),
    "9715": ("Delhi", "Delhi", "Delhi NCR"),
    "9716": ("Delhi", "Delhi", "Delhi NCR"),
    "9717": ("Delhi", "Delhi", "Delhi NCR"),
    "9718": ("Delhi", "Delhi", "Delhi NCR"),
    "9719": ("Delhi", "Delhi", "Delhi NCR"),
    "9720": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9721": ("Vadodara", "Gujarat", "Gujarat"),
    "9722": ("Surat", "Gujarat", "Gujarat"),
    "9723": ("Rajkot", "Gujarat", "Gujarat"),
    "9724": ("Bhavnagar", "Gujarat", "Gujarat"),
    "9725": ("Jamnagar", "Gujarat", "Gujarat"),
    "9726": ("Junagadh", "Gujarat", "Gujarat"),
    "9727": ("Anand", "Gujarat", "Gujarat"),
    "9728": ("Nadiad", "Gujarat", "Gujarat"),
    "9729": ("Gandhinagar", "Gujarat", "Gujarat"),
    "9730": ("Bangalore", "Karnataka", "Bangalore"),
    "9731": ("Bangalore", "Karnataka", "Bangalore"),
    "9732": ("Bangalore", "Karnataka", "Bangalore"),
    "9733": ("Bangalore", "Karnataka", "Bangalore"),
    "9734": ("Mysore", "Karnataka", "Karnataka"),
    "9735": ("Mangalore", "Karnataka", "Karnataka"),
    "9736": ("Hubli", "Karnataka", "Karnataka"),
    "9737": ("Belgaum", "Karnataka", "Karnataka"),
    "9738": ("Gulbarga", "Karnataka", "Karnataka"),
    "9739": ("Bellary", "Karnataka", "Karnataka"),
    "9740": ("Kochi", "Kerala", "Kerala"),
    "9741": ("Kochi", "Kerala", "Kerala"),
    "9742": ("Thrissur", "Kerala", "Kerala"),
    "9743": ("Thiruvananthapuram", "Kerala", "Kerala"),
    "9744": ("Kozhikode", "Kerala", "Kerala"),
    "9745": ("Kollam", "Kerala", "Kerala"),
    "9746": ("Kannur", "Kerala", "Kerala"),
    "9747": ("Alappuzha", "Kerala", "Kerala"),
    "9748": ("Palakkad", "Kerala", "Kerala"),
    "9749": ("Malappuram", "Kerala", "Kerala"),
    "9750": ("Bhopal", "Madhya Pradesh", "MP"),
    "9751": ("Indore", "Madhya Pradesh", "MP"),
    "9752": ("Gwalior", "Madhya Pradesh", "MP"),
    "9753": ("Jabalpur", "Madhya Pradesh", "MP"),
    "9754": ("Ujjain", "Madhya Pradesh", "MP"),
    "9755": ("Sagar", "Madhya Pradesh", "MP"),
    "9756": ("Rewa", "Madhya Pradesh", "MP"),
    "9757": ("Satna", "Madhya Pradesh", "MP"),
    "9758": ("Ratlam", "Madhya Pradesh", "MP"),
    "9759": ("Mandsaur", "Madhya Pradesh", "MP"),
    "9760": ("Mumbai", "Maharashtra", "Mumbai"),
    "9761": ("Mumbai", "Maharashtra", "Mumbai"),
    "9762": ("Mumbai", "Maharashtra", "Mumbai"),
    "9763": ("Mumbai", "Maharashtra", "Mumbai"),
    "9764": ("Pune", "Maharashtra", "Pune"),
    "9765": ("Pune", "Maharashtra", "Pune"),
    "9766": ("Nagpur", "Maharashtra", "Vidarbha"),
    "9767": ("Nashik", "Maharashtra", "North Maharashtra"),
    "9768": ("Aurangabad", "Maharashtra", "Marathwada"),
    "9769": ("Kolhapur", "Maharashtra", "West Maharashtra"),
    "9770": ("Chandigarh", "Chandigarh", "Chandigarh"),
    "9771": ("Chandigarh", "Chandigarh", "Chandigarh"),
    "9772": ("Ludhiana", "Punjab", "Punjab"),
    "9773": ("Jalandhar", "Punjab", "Punjab"),
    "9774": ("Amritsar", "Punjab", "Punjab"),
    "9775": ("Bathinda", "Punjab", "Punjab"),
    "9776": ("Patiala", "Punjab", "Punjab"),
    "9777": ("Mohali", "Punjab", "Punjab"),
    "9778": ("Patiala", "Punjab", "Punjab"),
    "9779": ("Ludhiana", "Punjab", "Punjab"),
    "9780": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9781": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9782": ("Jodhpur", "Rajasthan", "Rajasthan"),
    "9783": ("Kota", "Rajasthan", "Rajasthan"),
    "9784": ("Bikaner", "Rajasthan", "Rajasthan"),
    "9785": ("Udaipur", "Rajasthan", "Rajasthan"),
    "9786": ("Ajmer", "Rajasthan", "Rajasthan"),
    "9787": ("Bhilwara", "Rajasthan", "Rajasthan"),
    "9788": ("Alwar", "Rajasthan", "Rajasthan"),
    "9789": ("Sikar", "Rajasthan", "Rajasthan"),
    "9790": ("Patna", "Bihar", "Bihar"),
    "9791": ("Patna", "Bihar", "Bihar"),
    "9792": ("Gaya", "Bihar", "Bihar"),
    "9793": ("Muzaffarpur", "Bihar", "Bihar"),
    "9794": ("Bhagalpur", "Bihar", "Bihar"),
    "9795": ("Darbhanga", "Bihar", "Bihar"),
    "9796": ("Purnia", "Bihar", "Bihar"),
    "9797": ("Sasaram", "Bihar", "Bihar"),
    "9798": ("Chhapra", "Bihar", "Bihar"),
    "9799": ("Motihari", "Bihar", "Bihar"),
    "9800": ("Ranchi", "Jharkhand", "Jharkhand"),
    "9801": ("Jamshedpur", "Jharkhand", "Jharkhand"),
    "9802": ("Dhanbad", "Jharkhand", "Jharkhand"),
    "9803": ("Bokaro", "Jharkhand", "Jharkhand"),
    "9812": ("Dehradun", "Uttarakhand", "Uttarakhand"),
    "9813": ("Haridwar", "Uttarakhand", "Uttarakhand"),
    "9837": ("Dehradun", "Uttarakhand", "Uttarakhand"),
    "9842": ("Chennai", "Tamil Nadu", "Chennai"),
    "9843": ("Chennai", "Tamil Nadu", "Chennai"),
    "9846": ("Bangalore", "Karnataka", "Bangalore"),
    "9847": ("Bangalore", "Karnataka", "Bangalore"),
    "9860": ("Guwahati", "Assam", "Assam"),
    "9862": ("Shillong", "Meghalaya", "NE"),
    "9863": ("Imphal", "Manipur", "NE"),
    "9864": ("Agartala", "Tripura", "NE"),
    "9865": ("Kohima", "Nagaland", "NE"),
    "9866": ("Itanagar", "Arunachal Pradesh", "NE"),
    "9876": ("Mumbai", "Maharashtra", "Mumbai"),
    "9877": ("Mumbai", "Maharashtra", "Mumbai"),
    "9878": ("Mumbai", "Maharashtra", "Mumbai"),
    "9881": ("Pune", "Maharashtra", "Pune"),
    "9882": ("Nagpur", "Maharashtra", "Vidarbha"),
    "9883": ("Nashik", "Maharashtra", "North Maharashtra"),
    "9890": ("Delhi", "Delhi", "Delhi NCR"),
    "9891": ("Delhi", "Delhi", "Delhi NCR"),
    "9892": ("Bhopal", "Madhya Pradesh", "MP"),
    "9893": ("Indore", "Madhya Pradesh", "MP"),
    "9894": ("Hyderabad", "Telangana", "Hyderabad"),
    "9895": ("Chennai", "Tamil Nadu", "Chennai"),
    "9900": ("Bangalore", "Karnataka", "Bangalore"),
    "9901": ("Bangalore", "Karnataka", "Bangalore"),
    "9902": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9903": ("Kolkata", "West Bengal", "Kolkata"),
    "9904": ("Chennai", "Tamil Nadu", "Chennai"),
    "9912": ("Delhi", "Delhi", "Delhi NCR"),
    "9913": ("Delhi", "Delhi", "Delhi NCR"),
    "9914": ("Delhi", "Delhi", "Delhi NCR"),
    "9915": ("Delhi", "Delhi", "Delhi NCR"),
    "9916": ("Delhi", "Delhi", "Delhi NCR"),
    "9917": ("Delhi", "Delhi", "Delhi NCR"),
    "9918": ("Delhi", "Delhi", "Delhi NCR"),
    "9919": ("Delhi", "Delhi", "Delhi NCR"),
    "9921": ("Mumbai", "Maharashtra", "Mumbai"),
    "9924": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9929": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9930": ("Mumbai", "Maharashtra", "Mumbai"),
    "9933": ("Kolkata", "West Bengal", "Kolkata"),
    "9936": ("Kolkata", "West Bengal", "Kolkata"),
    "9937": ("Kolkata", "West Bengal", "Kolkata"),
    "9938": ("Kolkata", "West Bengal", "Kolkata"),
    "9939": ("Kolkata", "West Bengal", "Kolkata"),
    "9941": ("Chennai", "Tamil Nadu", "Chennai"),
    "9942": ("Chennai", "Tamil Nadu", "Chennai"),
    "9943": ("Chennai", "Tamil Nadu", "Chennai"),
    "9944": ("Bangalore", "Karnataka", "Bangalore"),
    "9946": ("Bangalore", "Karnataka", "Bangalore"),
    "9947": ("Bangalore", "Karnataka", "Bangalore"),
    "9951": ("Delhi", "Delhi", "Delhi NCR"),
    "9952": ("Delhi", "Delhi", "Delhi NCR"),
    "9953": ("Delhi", "Delhi", "Delhi NCR"),
    "9954": ("Delhi", "Delhi", "Delhi NCR"),
    "9955": ("Delhi", "Delhi", "Delhi NCR"),
    "9956": ("Delhi", "Delhi", "Delhi NCR"),
    "9957": ("Delhi", "Delhi", "Delhi NCR"),
    "9959": ("Delhi", "Delhi", "Delhi NCR"),
    "9960": ("Mumbai", "Maharashtra", "Mumbai"),
    "9961": ("Mumbai", "Maharashtra", "Mumbai"),
    "9963": ("Chennai", "Tamil Nadu", "Chennai"),
    "9964": ("Chennai", "Tamil Nadu", "Chennai"),
    "9965": ("Chennai", "Tamil Nadu", "Chennai"),
    "9966": ("Bangalore", "Karnataka", "Bangalore"),
    "9967": ("Bangalore", "Karnataka", "Bangalore"),
    "9969": ("Mumbai", "Maharashtra", "Mumbai"),
    "9970": ("Pune", "Maharashtra", "Pune"),
    "9972": ("Chandigarh", "Chandigarh", "Chandigarh"),
    "9974": ("Delhi", "Delhi", "Delhi NCR"),
    "9975": ("Delhi", "Delhi", "Delhi NCR"),
    "9976": ("Delhi", "Delhi", "Delhi NCR"),
    "9977": ("Delhi", "Delhi", "Delhi NCR"),
    "9978": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9979": ("Ahmedabad", "Gujarat", "Gujarat"),
    "9980": ("Bangalore", "Karnataka", "Bangalore"),
    "9981": ("Bangalore", "Karnataka", "Bangalore"),
    "9982": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9983": ("Jaipur", "Rajasthan", "Rajasthan"),
    "9984": ("Lucknow", "Uttar Pradesh", "UP"),
    "9985": ("Lucknow", "Uttar Pradesh", "UP"),
    "9986": ("Kolkata", "West Bengal", "Kolkata"),
    "9987": ("Mumbai", "Maharashtra", "Mumbai"),
    "9988": ("Chandigarh", "Chandigarh", "Chandigarh"),
    "9989": ("Hyderabad", "Telangana", "Hyderabad"),
    "9990": ("Delhi", "Delhi", "Delhi NCR"),
    "9991": ("Delhi", "Delhi", "Delhi NCR"),
    "9992": ("Delhi", "Delhi", "Delhi NCR"),
    "9993": ("Bhopal", "Madhya Pradesh", "MP"),
    "9994": ("Chennai", "Tamil Nadu", "Chennai"),
    "9995": ("Chennai", "Tamil Nadu", "Chennai"),
    "9996": ("Bangalore", "Karnataka", "Bangalore"),
    "9997": ("Bangalore", "Karnataka", "Bangalore"),
    "9999": ("Mumbai", "Maharashtra", "Mumbai"),
}

WEB_PATH_WORDLIST = [
    "admin", "login", "wp-admin", "wp-login", "administrator", "dashboard",
    "api", "v1", "v2", "graphql", "api/v1", "api/v2",
    ".env", ".git/config", ".git/HEAD", ".htaccess", "robots.txt", "sitemap.xml",
    "backup", "db", "database", "dump", "sql", "mysql", "phpmyadmin",
    "config", "configuration", "settings", "setup", "install",
    "wp-content", "wp-includes", "wp-json", "uploads", "download", "files",
    "assets", "static", "public", "images", "img", "css", "js", "scripts",
    "server-status", "server-info", "cgi-bin", "cgi-bin/test.cgi",
    "test", "testing", "dev", "development", "staging", "stage",
    "debug", "log", "logs", "error", "errors", "trace",
    "phpinfo.php", "info.php", "test.php",
    ".DS_Store", "Thumbs.db", "crossdomain.xml", "web.config",
    "composer.json", "package.json", "Dockerfile", "docker-compose.yml",
    "README.md", "CHANGELOG.md", "LICENSE", "LICENSE.txt",
    "swagger.json", "swagger-ui", "openapi.json", "docs", "documentation",
    "proxy", "vpn", "remote", "panel", "cpanel",
    "status", "health", "healthcheck", "healthz", "metrics", "monitor",
    "prometheus", "grafana", "kibana", "jenkins", "jira", "sonar", "nexus",
    ".aws", ".azure", "cloud", "credentials", "token", "tokens", "keys",
    "register", "signup", "account", "accounts",
    "user", "users", "profile", "profiles", "me",
    "index.php", "index.html", "default.php",
    "xmlrpc.php", "actuator", "actuator/health",
    ".well-known/security.txt", "vendor", "node_modules",
    "webalizer", "stats", "statistics", "awstats",
]
WEB_PATH_WORDLIST = list(dict.fromkeys(WEB_PATH_WORDLIST))


# ── Stress Testing ─────────────────────────────────

def legacy_resolve(domain):
    try:
        socket.inet_aton(domain)
        return domain
    except OSError:
        try:
            ip = socket.gethostbyname(domain)
            print(f"  {c(SYM_CHECK + ' Resolved:', Fore.GREEN)} {domain} {SYM_ARROW} {ip}")
            return ip
        except socket.gaierror:
            print(f"  {c(SYM_X + ' Could not resolve.', Fore.RED)}")
            return None


def legacy_nmap(target):
    header_box(f"Port Scan: {target}", Fore.MAGENTA)
    open_ports = []
    try:
        r = subprocess.run(["nmap", "-T4", "-F", target], capture_output=True, text=True, timeout=120)
        for line in r.stdout.splitlines():
            m = re.match(r'^(\d+)/tcp\s+open', line)
            if m: open_ports.append(int(m.group(1)))
    except Exception:
        pass
    try:
        mc_str = ",".join(str(p) for p in MINECRAFT_PORTS)
        r = subprocess.run(["nmap", "-T4", "-p", mc_str, target], capture_output=True, text=True, timeout=60)
        for line in r.stdout.splitlines():
            m = re.match(r'^(\d+)/tcp\s+open', line)
            if m:
                p = int(m.group(1))
                if p not in open_ports: open_ports.append(p)
    except Exception:
        pass
    open_ports.sort()
    if open_ports:
        print(f"\n  {c(SYM_CHECK + ' Open Ports Found:', Fore.GREEN)}")
        for p in open_ports:
            try: svc = socket.getservbyport(p)
            except: svc = "unknown"
            tag = f" {Fore.YELLOW}[MINECRAFT]{Style.RESET_ALL}" if p in MINECRAFT_PORTS else ""
            print(f"    {SYM_LINE_V}{SYM_LINE_H} {Fore.GREEN}{p}{Style.RESET_ALL} ({Fore.CYAN}{svc}{Style.RESET_ALL}){tag}")
    else:
        print(f"\n  {c('No open ports detected.', Fore.YELLOW)}")
    print(f"\n{Fore.MAGENTA}{SYM_LINE_H*40}{Style.RESET_ALL}")
    return open_ports


def mc_worker(ip, port, results, idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0); s.connect((ip, port))
        s.sendall(MINECRAFT_PAYLOADS[idx % len(MINECRAFT_PAYLOADS)])
        s.close(); results[idx] = 1
    except Exception: results[idx] = 0


def stress_minecraft():
    header_box("Minecraft Stress Test", Fore.RED)
    target = input(f"  {c(f'Server IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    ip = legacy_resolve(target)
    if not ip: return
    ports = legacy_nmap(ip) or []
    if ports:
        p_in = input(f"  {c(f'Port (default 25565) {SYM_PROMPT} ', Fore.CYAN)}").strip()
        port = int(p_in) if p_in.isdigit() else 25565
    else:
        p_in = input(f"  {c(f'Port (default 25565) {SYM_PROMPT} ', Fore.CYAN)}").strip()
        port = int(p_in) if p_in.isdigit() else 25565
    n_in = input(f"  {c(f'Packets (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    num = int(n_in) if n_in.isdigit() else 500
    start = time.time(); sent = 0; done = 0; bs = 1600
    try:
        for b in range(0, num, bs):
            be = min(b + bs, num); batch = list(range(b, be)); br = {}
            with ThreadPoolExecutor(max_workers=200) as ex:
                fs = {ex.submit(mc_worker, ip, port, br, i): i for i in batch}
                for f in as_completed(fs): f.result()
            for v in br.values(): sent += v; done += 1
            sys.stdout.write(f"\r{progress_bar(min(done, num), num)}  {c(f'Sent: {sent}', Fore.GREEN)}  {c(f'Errors: {done-sent}', Fore.RED)}  ")
            sys.stdout.flush()
        print()
    except KeyboardInterrupt: print(f"\n  {YELLOW}Interrupted.{RESET}")
    el = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} {c(str(sent), Fore.CYAN)} pkts in {c(f'{el:.1f}s', Fore.CYAN)} ({c(f'{sent/el:.1f} pkt/s', Fore.MAGENTA)})\n")


def http_worker(session, url, results, idx):
    try: session.get(url, timeout=8, headers={"User-Agent": "DarkieV2/1.0"}); results[idx] = 1
    except: results[idx] = 0


def stress_web():
    header_box("Web Stress Test", Fore.RED)
    url = input(f"  {c(f'URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url: return
    if not url.startswith("http"): url = "https://" + url
    n_in = input(f"  {c(f'Requests (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    num = int(n_in) if n_in.isdigit() else 500
    start = time.time(); sent = 0; done = 0; bs = 1600
    try:
        for b in range(0, num, bs):
            be = min(b + bs, num); batch = list(range(b, be)); br = {}
            with ThreadPoolExecutor(max_workers=200) as ex:
                with requests.Session() as s:
                    fs = {ex.submit(http_worker, s, url, br, i): i for i in batch}
                    for f in as_completed(fs): f.result()
            for v in br.values(): sent += v; done += 1
            sys.stdout.write(f"\r{progress_bar(min(done, num), num)}  {c(f'OK: {sent}', Fore.GREEN)}  {c(f'Errors: {done-sent}', Fore.RED)}  ")
            sys.stdout.flush()
        print()
    except KeyboardInterrupt: print(f"\n  {YELLOW}Interrupted.{RESET}")
    el = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} {c(str(sent), Fore.CYAN)} reqs in {c(f'{el:.1f}s', Fore.CYAN)} ({c(f'{sent/el:.1f} req/s', Fore.MAGENTA)})\n")


def ip_worker(ip, port, results, idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0); s.connect((ip, port)); s.sendall(b"GET / HTTP/1.0\r\n\r\n"); s.close(); results[idx] = 1
    except: results[idx] = 0


def ip_flood_worker(ip, ports, results, idx):
    return ip_worker(ip, ports[idx % len(ports)], results, idx)


def stress_ip():
    header_box("IP Flood Test", Fore.RED)
    ip = input(f"  {c(f'Target IP {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not ip: return
    try: socket.inet_aton(ip)
    except: print(f"  {RED}Invalid IP.{RESET}"); return
    print(f"  {c('Ports:', Fore.CYAN)} [a]uto ({len(STRESS_PORTS)}) [m]anual")
    if input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() == "m":
        p_in = input(f"  {c(f'Ports (comma) {SYM_PROMPT} ', Fore.CYAN)}").strip()
        try: ports = [int(x.strip()) for x in p_in.split(",") if x.strip()]
        except: ports = STRESS_PORTS[:]
    else: ports = STRESS_PORTS[:]
    n_in = input(f"  {c(f'Conn/port (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    nc = int(n_in) if n_in.isdigit() else 500
    tw = nc * len(ports); sent = 0; done = 0; bs = 1600; start = time.time()
    try:
        for b in range(0, tw, bs):
            be = min(b + bs, tw); batch = list(range(b, be)); br = {}
            with ThreadPoolExecutor(max_workers=200) as ex:
                fs = {ex.submit(ip_flood_worker, ip, ports, br, i): i for i in batch}
                for f in as_completed(fs): f.result()
            for v in br.values(): sent += v; done += 1
            sys.stdout.write(f"\r{progress_bar(min(done, tw), tw)}  {c(f'OK: {sent}', Fore.GREEN)}  {c(f'Errors: {done-sent}', Fore.RED)}  ")
            sys.stdout.flush()
        print()
    except KeyboardInterrupt: print(f"\n  {YELLOW}Interrupted.{RESET}")
    el = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} {c(str(sent), Fore.CYAN)} conns x {c(str(len(ports)), Fore.MAGENTA)} ports in {c(f'{el:.1f}s', Fore.CYAN)} ({c(f'{sent/el:.1f} conn/s', Fore.MAGENTA)})\n")


# ── OSINT Tools ────────────────────────────────────

def osint_phone():
    header_box("Phone Number Deep OSINT", Fore.YELLOW)
    num = input(f"  {c(f'Phone (+CC) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not num: return
    cleaned = re.sub(r'[^\d+]', '', num)
    if not cleaned.startswith('+'): cleaned = '+' + cleaned
    print(f"\n  {c('Analyzing:', Fore.GREEN)} {cleaned}")
    detected = "Unknown"
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code): detected = country; break
    digits = cleaned.lstrip('+'); length = len(digits)
    lines = [f"  Number: {c(cleaned, Fore.GREEN)}", f"  Format: {c('E.164', Fore.CYAN)}", f"  Digits: {c(str(length), Fore.CYAN)}"]
    lines.append(f"  Country: {c(detected, Fore.YELLOW)}")
    lines.append(f"  Valid: {c(SYM_CHECK, Fore.GREEN) if (detected == 'India' and length == 12) or (detected == 'US/CA' and length == 11) or length >= 8 else c(SYM_X, Fore.RED)}")
    pattern_type = "Standard"
    if length >= 3 and len(set(digits[-6:])) <= 2: pattern_type = "Repeating Pattern (low entropy)"
    elif digits == digits[::-1]: pattern_type = "Palindrome"
    elif digits[-4:] in ("0000","1111","2222","3333","4444","5555","6666","7777","8888","9999"): pattern_type = "Golden Number / VIP Pattern"
    lines.append(f"  Pattern: {c(pattern_type, Fore.MAGENTA)}")
    if detected == "US/CA" and length == 11:
        npa = digits[1:4]; nxx = digits[4:7]; sub = digits[7:]
        city, state, tz = NPA_DB.get(npa, ("Unknown","Unknown","Unknown"))
        vzw = {"201","212","213","310","312","313","323","347","408","412","413","414","415","416","417","425","443","469","480","503","504","510","512","513","515","516","530","540","541","551","559","561","562","570","571","585","586","602","603","605","606","607","608","609","610","612","614","615","616","617","618","619","626","630","631","646","647","650","651","660","661","662","669","678","682","701","702","703","704","706","707","708","712","713","714","715","716","717","718","719","720","724","727","731","732","734","740","747","754","757","760","762","763","765","770","772","773","774","775","781","785","786","787","801","802","803","804","805","806","808","810","812","813","814","815","816","817","818","828","830","831","832","843","845","847","848","850","856","857","858","859","860","862","863","864","865","870","901","902","903","904","908","909","910","912","913","914","915","916","917","918","919","920","925","928","929","931","936","937","940","941","947","949","951","952","954","956","959","970","971","972","973","978","979","980","984","985"}
        carrier = "Verizon" if npa in vzw else "T-Mobile" if npa in {"917","646","347"} else "AT&T" if npa in {"214","469","682","713","726","737","817","830","832","903","915","940","956","972","979"} else "Regional"
        lt = "Toll-Free" if npa in TOLLFREE_PREFIXES else "VoIP" if nxx.startswith("2") else "Mobile"
        lines += [f"  NPA-NXX: {c(npa, Fore.MAGENTA)}-{c(nxx, Fore.MAGENTA)}-{c(sub, Fore.MAGENTA)}",
                  f"  Location: {c(f'{city}, {state}', Fore.CYAN)} [{c(tz, Fore.YELLOW)}]",
                  f"  Type: {c(lt, Fore.GREEN)}", f"  Carrier: {c(carrier, Fore.CYAN)}"]
        if carrier == "Verizon": lines.append(f"  Network: {c('CDMA/4G/5G', Fore.MAGENTA)}")
        elif carrier in ("T-Mobile","AT&T"): lines.append(f"  Network: {c('GSM/4G/5G', Fore.MAGENTA)}")
        lines.append(f"  Possible Owner: {c('Not publicly disclosed', Fore.YELLOW)} (search Truecaller/Spokeo)")
        lines.append(f"  Address Range: {c(f'{city}, {state} area', Fore.CYAN)}")
    elif detected == "India" and length == 12:
        nat = digits[2:]; ndc = nat[:4]; sub = nat[4:]
        ndc_info = INDIAN_NDC.get(ndc)
        lines.append(f"  National: {c(nat, Fore.MAGENTA)}  Type: {c('Mobile (Wireless)', Fore.GREEN)}")
        if ndc_info:
            ndc_city, ndc_state, ndc_circle = ndc_info
            lines.append(f"  NDC: {c(ndc, Fore.MAGENTA)} {SYM_ARROW} {c(ndc_city, Fore.CYAN)}, {c(ndc_state, Fore.GREEN)} ({c(ndc_circle, Fore.YELLOW)})")
            lines.append(f"  Geographic Region: {c(f'{ndc_city} area, {ndc_state}', Fore.CYAN)}")
        else:
            lines.append(f"  NDC: {c(ndc, Fore.MAGENTA)}  Sub: {c(sub, Fore.MAGENTA)}")
            lines.append(f"  Geographic Region: {c('Unknown (NDC not in local database)', Fore.YELLOW)}")
        try:
            tc_url = f"https://www.truecaller.com/search/{digits}"
            tc = requests.get(tc_url, timeout=5, headers={"User-Agent":"Mozilla/5.0"}, allow_redirects=True)
            if tc.status_code == 200 and "spam" in tc.text.lower():
                lines.append(f"  Truecaller: {c('Flagged as spam', Fore.RED)}")
            else:
                lines.append(f"  Truecaller: {c('Search on Truecaller for live data', Fore.YELLOW)}")
        except:
            lines.append(f"  Truecaller: {c('Check link below', Fore.YELLOW)}")
        lines.append(f"  Possible Owner: {c('Not publicly disclosed', Fore.YELLOW)} (try Truecaller link)")
    else:
        lines.append(f"  Type: {c('Standard Number', Fore.GREEN)}")
    info_box("Phone Intelligence", lines, Fore.YELLOW)
    su = cleaned.replace('+', '')
    print(f"  {c('OSINT Links:', Fore.CYAN)}")
    print(f"    {c('[1]', Fore.GREEN)} Truecaller:   https://www.truecaller.com/search/{su}")
    print(f"    {c('[2]', Fore.GREEN)} Google:       https://www.google.com/search?q={requests.utils.quote(cleaned)}")
    print(f"    {c('[3]', Fore.GREEN)} Numlookup:    https://www.numlookup.com/{su}")
    print(f"    {c('[4]', Fore.GREEN)} Spokeo:       https://www.spokeo.com/{su}")
    print(f"    {c('[5]', Fore.GREEN)} Whitepages:   https://www.whitepages.com/phone/{su}")
    print(f"    {c('[6]', Fore.GREEN)} Spydialer:    https://spydialer.com/default.aspx")
    print()
    info_box("Intelligence Notes", [
        f"  {c('Carrier/Operator:', Fore.YELLOW)} Use Truecaller link below — prefix-based detection is unreliable due to MNP.",
        f"  {c('Owner name:', Fore.YELLOW)}       Not publicly available from number alone.",
        f"  {c('Aadhar link:', Fore.RED)}         UIDAI database is restricted — not accessible.",
        f"  {c('IP from number:', Fore.RED)}      Requires SS7/carrier access — not publicly doable.",
        f"  {c('Truecaller:', Fore.YELLOW)}       May show name & carrier if the number is registered.",
    ], Fore.MAGENTA)
    print()


def osint_email():
    header_box("Email OSINT", Fore.YELLOW)
    email = input(f"  {c(f'Email {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not email or '@' not in email: return
    local, domain = email.split('@', 1)
    print(f"\n  {c('Analyzing:', Fore.GREEN)} {email}")
    mx = []; domain_ip = ""
    try:
        answers = socket.getaddrinfo(domain, 25, socket.AF_INET, socket.SOCK_STREAM)
        mx = list(set(a[4][0] for a in answers[:3]))
    except: pass
    try: domain_ip = socket.gethostbyname(domain)
    except: pass
    spf = ""
    if shutil.which("dig"):
        try:
            r = subprocess.run(["dig", "+short", "TXT", domain], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "v=spf1" in line: spf = line.strip()[:60]; break
        except: pass
    gravatar = ""
    try:
        import hashlib
        h = hashlib.md5(email.encode()).hexdigest()
        gr = requests.get(f"https://www.gravatar.com/avatar/{h}", timeout=5)
        if gr.status_code == 200 and len(gr.content) > 100: gravatar = "Found"
    except: pass
    lines = [f"  Email: {c(email, Fore.GREEN)}", f"  Domain: {c(domain, Fore.CYAN)}", f"  IP: {c(domain_ip, Fore.MAGENTA) if domain_ip else c('N/A', Fore.RED)}"]
    lines.append(f"  MX: {c(', '.join(mx[:2]), Fore.YELLOW) if mx else c('None', Fore.RED)}")
    lines.append(f"  SPF: {c(spf, Fore.GREEN) if spf else c('Not set', Fore.YELLOW)}")
    lines.append(f"  Gravatar: {c(gravatar, Fore.GREEN) if gravatar else c('None', Fore.YELLOW)}")
    info_box("Email Intel", lines, Fore.YELLOW)
    print(f"  {c('Links:', Fore.CYAN)} https://haveibeenpwned.com/account/{email}")
    print()


def osint_ipgeo():
    header_box("IP Geolocation", Fore.YELLOW)
    target = input(f"  {c(f'IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    try: socket.inet_aton(target); ip = target
    except:
        try: ip = socket.gethostbyname(target); print(f"  {c(SYM_CHECK, Fore.GREEN)} {target} {SYM_ARROW} {ip}")
        except: print(f"  {RED}Could not resolve.{RESET}"); return
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting", timeout=10)
        d = r.json()
        if d.get("status") == "success":
            lines = [f"  IP: {c(ip, Fore.GREEN)}", f"  Location: {c(d.get('city','?'), Fore.MAGENTA)}, {c(d.get('regionName','?'), Fore.CYAN)} {c(d.get('zip','?'), Fore.GREEN)}", f"  Country: {c(d.get('country','?'), Fore.YELLOW)}", f"  ISP: {c(d.get('isp','?'), Fore.CYAN)}", f"  ASN: {c(d.get('as','?'), Fore.MAGENTA)}", f"  Lat/Lon: {c(str(d.get('lat','?')), Fore.GREEN)}, {c(str(d.get('lon','?')), Fore.CYAN)}", f"  TZ: {c(d.get('timezone','?'), Fore.YELLOW)}", f"  Proxy/VPN: {c(SYM_CHECK, Fore.RED) if d.get('proxy') or d.get('hosting') else c('No', Fore.GREEN)}"]
            info_box("Geolocation", lines, Fore.YELLOW)
            print(f"  {c('Map:', Fore.CYAN)} https://www.google.com/maps?q={d.get('lat','0')},{d.get('lon','0')}")
        else: print(f"  {RED}Lookup failed.{RESET}")
    except Exception as e: print(f"  {RED}Error: {e}{RESET}")
    print()


def osint_dns():
    header_box("DNS Enumeration", Fore.YELLOW)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain: return
    has_dig = shutil.which("dig")
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
        records = []
        if has_dig:
            try:
                r = subprocess.run(["dig","+short",domain,rtype], capture_output=True, text=True, timeout=5)
                if r.stdout.strip(): records = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
            except: pass
        else:
            try:
                if rtype == "A": records = [socket.gethostbyname(domain)]
            except: pass
        if records:
            print(f"  {c(f'{rtype:5s}:', Fore.CYAN)} {c(', '.join(records[:3]), Fore.GREEN)}")
    print()


def osint_subdomain():
    header_box("Subdomain Discovery", Fore.YELLOW)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain: return
    print(f"  {c(f'Brute-forcing ({len(SUBDOMAIN_WORDLIST)} words)...', Fore.CYAN)}")
    found = []; total = len(SUBDOMAIN_WORDLIST)
    for i, sub in enumerate(SUBDOMAIN_WORDLIST):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append((fqdn, ip))
            print(f"  {c(SYM_CHECK, Fore.GREEN)} {c(fqdn, Fore.CYAN)} {SYM_ARROW} {c(ip, Fore.GREEN)}")
        except: pass
        if i % 20 == 0: sys.stdout.write(f"\r  {c(f'{i}/{total}', Fore.CYAN)}"); sys.stdout.flush()
    print(f"\n  {c(f'Found {len(found)} subdomains', Fore.GREEN)}\n")


def osint_social():
    header_box("Social Username Search", Fore.YELLOW)
    user = input(f"  {c(f'Username {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not user: return
    print(f"  {c(f'Checking {len(SOCIAL_PLATFORMS)} platforms...', Fore.CYAN)}")
    found = 0
    for platform, (tmpl, missing_indicator) in SOCIAL_PLATFORMS.items():
        url = tmpl.format(user)
        try:
            r = requests.get(url, timeout=6, headers={"User-Agent":"Mozilla/5.0 (compatible; DarkieV2)"}, allow_redirects=True)
            txt = r.text.lower()
            if missing_indicator.lower() in txt or r.status_code in (404, 410):
                continue
            if r.status_code == 200:
                found += 1
                print(f"  {c(SYM_CHECK, Fore.GREEN)} {c(platform+':', Fore.CYAN):16s} {c(url, Fore.GREEN)}")
        except: pass
    print(f"  {c(f'Found {found}/{len(SOCIAL_PLATFORMS)}', Fore.GREEN)}\n")


def osint_website():
    header_box("Website Tech Recon", Fore.YELLOW)
    url = input(f"  {c(f'URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url: return
    if not url.startswith("http"): url = "https://" + url
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "DarkieV2/1.0"})
        lines = [f"  URL: {c(r.url, Fore.GREEN)}", f"  Status: {c(str(r.status_code), Fore.YELLOW)}", f"  Size: {c(f'{len(r.content):,}B', Fore.MAGENTA)}"]
        for h, lbl in [("Server","Server"),("X-Powered-By","Powered"),("X-Frame-Options","XFO"),("Content-Security-Policy","CSP"),("Strict-Transport-Security","HSTS")]:
            if h in r.headers: lines.append(f"  {lbl:8s}: {c(r.headers[h][:40], Fore.GREEN)}")
        info_box("HTTP Recon", lines, Fore.YELLOW)
    except Exception as e: print(f"  {RED}Error: {e}{RESET}")
    print()


def osint_whois():
    header_box("Whois Lookup", Fore.YELLOW)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain: return
    if shutil.which("whois"):
        try:
            r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
            for line in r.stdout.splitlines():
                if any(line.lower().startswith(k) for k in ["domain name","registrar","creation date","expir","registrant","name server","dnssec","status"]):
                    print(f"  {c(line.strip(), Fore.GREEN)}")
        except: print(f"  {RED}Whois error.{RESET}")
    else: print(f"  {YELLOW}whois not installed.{RESET}")
    print()


# ── Telephone Tools ────────────────────────────────

def tel_analyze():
    header_box("Telephone Number Analysis", Fore.MAGENTA)
    num = input(f"  {c(f'Phone number {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not num: return
    cleaned = re.sub(r'[^\d+]', '', num)
    if not cleaned.startswith('+'): cleaned = '+' + cleaned
    lines = [f"  Number: {c(cleaned, Fore.GREEN)}"]
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code): lines.append(f"  Country: {c(country, Fore.YELLOW)}"); break
    info_box("Telephone Analysis", lines, Fore.MAGENTA); print()


def tel_country_codes():
    header_box("Country Codes", Fore.MAGENTA)
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: int(x[0])):
        print(f"    +{code:4s}  {c(country, Fore.GREEN)}")
    print()


def tel_format():
    header_box("Phone Formatter", Fore.MAGENTA)
    num = input(f"  {c(f'Number {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not num: return
    d = re.sub(r'[^\d]', '', num)
    print(f"  {c('Formats:', Fore.CYAN)}")
    print(f"    Raw: {c(d, Fore.GREEN)}")
    print(f"    International: {c('+'+d, Fore.GREEN)}")
    if len(d) == 11 and d.startswith('1'): print(f"    US: {c(f'+1 ({d[1:4]}) {d[4:7]}-{d[7:]}', Fore.GREEN)}")
    print()


# ── Legacy Network Utilities ───────────────────────

def legacy_portscan():
    header_box("TCP Port Scanner", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    try: socket.inet_aton(target); ip = target
    except:
        try: ip = socket.gethostbyname(target); print(f"  {c(SYM_CHECK, Fore.GREEN)} {target} {SYM_ARROW} {ip}")
        except: print(f"  {RED}Could not resolve.{RESET}"); return
    print(f"  {c('[1]', Fore.GREEN)} Top 30  [2] Top 1000  [3] Custom")
    ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if ch == "2": ports = list(range(1, 1025))
    elif ch == "3":
        try: r_in = input(f"  {c(f'Range (e.g. 1-1000) {SYM_PROMPT} ', Fore.CYAN)}").strip(); parts = r_in.split("-"); ports = list(range(int(parts[0]), int(parts[1])+1))
        except: ports = [22,80,443,8080,8443,3306,5432,6379,27017]
    else: ports = [22,21,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,9090,9200,27017]
    open_ports = []; total = len(ports)
    def chk(p, r, i):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.5)
        r[i] = p if s.connect_ex((ip, p)) == 0 else None; s.close()
    for i in range(0, total, 50):
        batch = ports[i:i+50]; br = {}
        with ThreadPoolExecutor(max_workers=100) as ex:
            fs = {ex.submit(chk, p, br, j): j for j, p in enumerate(batch)}
            for f in as_completed(fs): f.result()
        for idx in br:
            if br[idx] is not None: open_ports.append(br[idx])
        sys.stdout.write(f"\r  {c(f'{min(i+50, total)}/{total}', Fore.CYAN)}  Open: {c(len(open_ports), Fore.GREEN)}  "); sys.stdout.flush()
    print(f"\n  {c(SYM_CHECK + f' {len(open_ports)}/{total} open', Fore.GREEN)}")
    for p in sorted(open_ports):
        try: svc = socket.getservbyport(p)
        except: svc = "?"
        print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(f'{p:5d}', Fore.GREEN)} ({c(svc, Fore.CYAN)})")
    print()


def legacy_sslcheck():
    header_box("SSL/TLS Checker", Fore.BLUE)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain: return
    p_in = input(f"  {c(f'Port (443) {SYM_PROMPT} ', Fore.CYAN)}").strip(); port = int(p_in) if p_in.isdigit() else 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
        if cert:
            subj = dict(x[0] for x in cert.get("subject",[]))
            iss = dict(x[0] for x in cert.get("issuer",[]))
            na = cert.get("notAfter","")
            lines = [f"  Subject: {c(subj.get('commonName','?'), Fore.GREEN)}", f"  Issuer: {c(iss.get('organizationName','?'), Fore.YELLOW)}", f"  Valid until: {c(na, Fore.MAGENTA)}"]
            try:
                exp = dt.strptime(na, "%b %d %H:%M:%S %Y %Z"); days = (exp - dt.now()).days
                lines.append(f"  Days left: {c(str(days), Fore.RED if days < 30 else Fore.GREEN)}")
            except: pass
            san = cert.get("subjectAltName",[])
            if san: lines.append(f"  SANs: {c(', '.join(v for k,v in san if k=='DNS')[:3], Fore.CYAN)}")
            info_box("SSL Certificate", lines, Fore.BLUE)
        else: print(f"  {RED}No cert.{RESET}")
    except Exception as e: print(f"  {RED}Error: {e}{RESET}")
    print()


def legacy_httpheaders():
    header_box("HTTP Security Headers", Fore.BLUE)
    url = input(f"  {c(f'URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url: return
    if not url.startswith("http"): url = "https://" + url
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "DarkieV2/1.0"})
        lines = [f"  URL: {c(r.url, Fore.GREEN)}", f"  Status: {c(str(r.status_code), Fore.YELLOW)}"]
        sec_h = {"Strict-Transport-Security":"HSTS","Content-Security-Policy":"CSP","X-Frame-Options":"XFO","X-Content-Type-Options":"XCTO","X-XSS-Protection":"XXSS","Referrer-Policy":"Referrer","Permissions-Policy":"Permissions"}
        for h, lbl in sec_h.items():
            if h in r.headers: lines.append(f"  {lbl:10s}: {c(r.headers[h][:45], Fore.GREEN)}")
            else: lines.append(f"  {lbl:10s}: {c('Not set', Fore.RED)}")
        info_box("Security Headers", lines, Fore.BLUE)
        present = sum(1 for h in sec_h if h in r.headers); pct = present / len(sec_h) * 100
        grade = c(f"Grade: {'A' if pct>=70 else 'C' if pct>=40 else 'F'} ({pct:.0f}%)", Fore.GREEN if pct>=70 else Fore.YELLOW if pct>=40 else Fore.RED)
        print(f"  {c('Rating:', Fore.CYAN)} {grade}")
    except Exception as e: print(f"  {RED}Error: {e}{RESET}")
    print()


def legacy_ping():
    header_box("Ping", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    c_in = input(f"  {c(f'Count (4) {SYM_PROMPT} ', Fore.CYAN)}").strip(); cnt = int(c_in) if c_in.isdigit() else 4
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(["ping", param, str(cnt), target], capture_output=True, text=True, timeout=30)
        for line in (r.stdout or r.stderr).splitlines():
            if any(x in line.lower() for x in ["round-trip","rtt","min/avg/max","packets","transmitted","received","loss","ttl=","time="]):
                print(f"  {c(line, Fore.GREEN)}")
        if r.returncode == 0: print(f"\n  {c(SYM_CHECK + ' Host alive', Fore.GREEN)}")
        else: print(f"\n  {c(SYM_X + ' Host unreachable', Fore.RED)}")
    except Exception as e: print(f"  {RED}Error: {e}{RESET}")
    print()


def legacy_traceroute():
    header_box("Traceroute", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    cmd = ["tracert", "-d", "-h", "20"] if platform.system().lower() == "windows" else ["traceroute", "-n", "-m", "20"]
    cmd.append(target)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        for line in (r.stdout or r.stderr).splitlines()[:25]:
            if line.strip(): print(f"  {Fore.GREEN}{line}{Style.RESET_ALL}")
    except: print(f"  {YELLOW}traceroute not available.{RESET}")
    print()


def legacy_web_recon():
    header_box("Web Recon (Dir Brute + Ports)", Fore.YELLOW)
    target = input(f"  {c(f'Domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not target: return
    if not target.startswith("http"): target = "https://" + target
    base = target.rstrip('/')
    parsed = urlparse(base); domain = parsed.netloc or parsed.path

    # Port scan
    print(f"\n  {c('Phase 1: Port Scan', Fore.MAGENTA)}")
    open_ports = []
    if shutil.which("nmap"):
        try:
            r = subprocess.run(["nmap","-T4","-F","--open",domain], capture_output=True, text=True, timeout=120)
            for line in r.stdout.splitlines():
                m = re.match(r'^(\d+)/tcp\s+open', line)
                if m:
                    p = int(m.group(1))
                    try: svc = socket.getservbyport(p)
                    except: svc = "?"
                    open_ports.append((p, svc))
                    print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(f'{p}', Fore.GREEN)} ({c(svc, Fore.CYAN)})")
        except: pass
    for p, sn in [(80,"http"),(443,"https"),(8080,"http-proxy"),(8443,"https-alt")]:
        if not any(op[0] == p for op in open_ports):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
                if s.connect_ex((domain, p)) == 0: open_ports.append((p, sn))
                s.close()
            except: pass

    # Dir brute-force
    print(f"\n  {c('Phase 2: Dir Brute-Force', Fore.MAGENTA)}")
    found = []
    for i, path in enumerate(WEB_PATH_WORDLIST):
        url = f"{base}/{path}"
        try:
            r = requests.get(url, timeout=4, headers={"User-Agent":"DarkieV2/1.0"}, allow_redirects=False)
            if r.status_code in (200,301,302,403,401):
                found.append((path, r.status_code, len(r.content)))
                print(f"    {c(f'[{r.status_code}]', Fore.GREEN if r.status_code==200 else Fore.YELLOW)} {c(url, Fore.GREEN)}")
        except: pass
        if i % 20 == 0: sys.stdout.write(f"\r    {c(f'{i}/{len(WEB_PATH_WORDLIST)}', Fore.CYAN)} Found: {c(len(found), Fore.GREEN)}  "); sys.stdout.flush()

    print(f"\n\n  {c('Results:', Fore.GREEN)} Ports: {len(open_ports)}, Paths: {len(found)}")
    print()


# ── Legacy Menu Functions ─────────────────────────

def menu_stress():
    while True:
        header_box("Stress Testing", Fore.RED)
        print(f"  {c('[1]', Fore.GREEN)}  Minecraft Stress")
        print(f"  {c('[2]', Fore.GREEN)}  Web Stress")
        print(f"  {c('[3]', Fore.GREEN)}  IP Flood")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if ch == "b": break
        {"1": stress_minecraft, "2": stress_web, "3": stress_ip}.get(ch, lambda: None)()
        if ch not in ("1","2","3"): print(f"  {RED}Invalid.{RESET}")


def menu_osint():
    while True:
        header_box("OSINT Tools", Fore.YELLOW)
        print(f"  {c('[1]', Fore.GREEN)}  Phone Lookup")
        print(f"  {c('[2]', Fore.GREEN)}  Email Lookup")
        print(f"  {c('[3]', Fore.GREEN)}  IP Geolocation")
        print(f"  {c('[4]', Fore.GREEN)}  DNS Enumeration")
        print(f"  {c('[5]', Fore.GREEN)}  Subdomain Discovery")
        print(f"  {c('[6]', Fore.GREEN)}  Social Username Search")
        print(f"  {c('[7]', Fore.GREEN)}  Website Tech Recon")
        print(f"  {c('[8]', Fore.GREEN)}  Whois Lookup")
        print(f"  {c('[9]', Fore.GREEN)}  Web Recon (Dir Brute)")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if ch == "b": break
        ac = {"1": osint_phone, "2": osint_email, "3": osint_ipgeo, "4": osint_dns,
              "5": osint_subdomain, "6": osint_social, "7": osint_website, "8": osint_whois, "9": legacy_web_recon}
        if ch in ac: ac[ch]()
        else: print(f"  {RED}Invalid.{RESET}")


def menu_telephone():
    while True:
        header_box("Telephone Tools", Fore.MAGENTA)
        print(f"  {c('[1]', Fore.GREEN)}  Analyze Number")
        print(f"  {c('[2]', Fore.GREEN)}  Country Codes")
        print(f"  {c('[3]', Fore.GREEN)}  Format Number")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if ch == "b": break
        {"1": tel_analyze, "2": tel_country_codes, "3": tel_format}.get(ch, lambda: None)()
        if ch not in ("1","2","3"): print(f"  {RED}Invalid.{RESET}")


def menu_netutils():
    while True:
        header_box("Network Utilities", Fore.BLUE)
        print(f"  {c('[1]', Fore.GREEN)}  Port Scanner")
        print(f"  {c('[2]', Fore.GREEN)}  SSL/TLS Checker")
        print(f"  {c('[3]', Fore.GREEN)}  HTTP Security Headers")
        print(f"  {c('[4]', Fore.GREEN)}  Ping")
        print(f"  {c('[5]', Fore.GREEN)}  Traceroute")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if ch == "b": break
        ac = {"1": legacy_portscan, "2": legacy_sslcheck, "3": legacy_httpheaders, "4": legacy_ping, "5": legacy_traceroute}
        if ch in ac: ac[ch]()
        else: print(f"  {RED}Invalid.{RESET}")


# ──────────────────────────────────────────────────────────
#  MENU SYSTEM (v2)
# ──────────────────────────────────────────────────────────

def menu_network_threat():
    while True:
        header_box("Network & Threat Monitoring", Fore.RED)
        print(f"  {c('[1]', Fore.GREEN)}  Packet Capture & Analysis")
        print(f"  {c('[2]', Fore.GREEN)}  Real-time Traffic Monitor")
        print(f"  {c('[3]', Fore.GREEN)}  IDS Signature Detection")
        print(f"  {c('[4]', Fore.GREEN)}  ARP Spoofing Detector")
        print(f"  {c('[5]', Fore.GREEN)}  Port Scan Detector")
        print(f"  {c('[6]', Fore.GREEN)}  DDoS Detection")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if choice == "b": break
        actions = {"1": net_capture, "2": net_traffic_monitor, "3": net_ids,
                   "4": net_arp_detect, "5": net_portscan_detect, "6": net_ddos_detect}
        if choice in actions: actions[choice]()
        else: print(f"  {RED}Invalid choice.{RESET}")


def menu_endpoint():
    while True:
        header_box("Endpoint Security", Fore.MAGENTA)
        print(f"  {c('[1]', Fore.GREEN)}  Process Monitor")
        print(f"  {c('[2]', Fore.GREEN)}  Suspicious Process Detector")
        print(f"  {c('[3]', Fore.GREEN)}  File Integrity Checker")
        print(f"  {c('[4]', Fore.GREEN)}  Network Connection Monitor")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if choice == "b": break
        actions = {"1": ep_process_monitor, "2": ep_suspicious_processes,
                   "3": ep_file_integrity, "4": ep_network_connections}
        if choice in actions: actions[choice]()
        else: print(f"  {RED}Invalid choice.{RESET}")


def menu_vuln():
    while True:
        header_box("Vulnerability Management", Fore.BLUE)
        print(f"  {c('[1]', Fore.GREEN)}  Advanced Port Scanner")
        print(f"  {c('[2]', Fore.GREEN)}  CVE Lookup")
        print(f"  {c('[3]', Fore.GREEN)}  Vulnerability Assessment")
        print(f"  {c('[4]', Fore.GREEN)}  Security Config Checker")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if choice == "b": break
        actions = {"1": vuln_advanced_scan, "2": vuln_cve_lookup,
                   "3": vuln_assessment, "4": vuln_config_check}
        if choice in actions: actions[choice]()
        else: print(f"  {RED}Invalid choice.{RESET}")


def menu_data():
    while True:
        header_box("Data & Access Protection", Fore.YELLOW)
        print(f"  {c('[1]', Fore.GREEN)}  File Encryption / Decryption")
        print(f"  {c('[2]', Fore.GREEN)}  Password Strength Analyzer")
        print(f"  {c('[3]', Fore.GREEN)}  Brute-Force Detection")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if choice == "b": break
        actions = {"1": data_encrypt, "2": data_password_strength, "3": data_bruteforce_detect}
        if choice in actions: actions[choice]()
        else: print(f"  {RED}Invalid choice.{RESET}")


def menu_pentest():
    while True:
        header_box("Ethical Hacking & Pentest", Fore.GREEN)
        print(f"  {c('[1]', Fore.GREEN)}  SQL Injection Detector")
        print(f"  {c('[2]', Fore.GREEN)}  XSS Scanner")
        print(f"  {c('[3]', Fore.GREEN)}  Path Traversal Tester")
        print(f"  {c('[4]', Fore.GREEN)}  Subdomain Takeover Checker")
        print(f"  {c('[5]', Fore.GREEN)}  HTTP Methods Fuzzer")
        print(f"  {c('[6]', Fore.GREEN)}  Brute-Force Login Tester")
        print(f"  {c('[7]', Fore.MAGENTA)}  Instagram OSINT & Auth Tester")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if choice == "b": break
        actions = {"1": pentest_sqli, "2": pentest_xss, "3": pentest_path_traversal,
                   "4": pentest_subdomain_takeover, "5": pentest_http_methods, "6": pentest_bruteforce_login, "7": pentest_instagram}
        if choice in actions: actions[choice]()
        else: print(f"  {RED}Invalid choice.{RESET}")


def menu_siem():
    while True:
        header_box("SIEM & Log Analysis", Fore.CYAN)
        print(f"  {c('[1]', Fore.GREEN)}  Log File Analyzer")
        print(f"  {c('[2]', Fore.GREEN)}  Real-time Log Monitor")
        print(f"  {c('[3]', Fore.GREEN)}  Alert Dashboard ({c(len(LOG_ALERTS), Fore.YELLOW)} alerts)")
        print(f"  {c('[4]', Fore.GREEN)}  Threat Pattern Detection")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if choice == "b": break
        actions = {"1": siem_log_analyzer, "2": siem_realtime_monitor,
                   "3": siem_alert_viewer, "4": siem_threat_patterns}
        if choice in actions: actions[choice]()
        else: print(f"  {RED}Invalid choice.{RESET}")


def main():
    print_banner()
    while True:
        header_box("Darkie Security Suite v2 — Main Menu", Fore.CYAN)
        print(f"  {c('[1]', Fore.RED)}    Network & Threat Monitoring  {Fore.YELLOW}(Packet capture, IDS, ARP, DDoS){RESET}")
        print(f"  {c('[2]', Fore.MAGENTA)}  Endpoint Security  {Fore.YELLOW}(Process monitor, File integrity, Connections){RESET}")
        print(f"  {c('[3]', Fore.BLUE)}   Vulnerability Management  {Fore.YELLOW}(Port scan, CVE, Assessment, Config check){RESET}")
        print(f"  {c('[4]', Fore.YELLOW)}  Data & Access Protection  {Fore.YELLOW}(Encryption, Password, Brute-force detect){RESET}")
        print(f"  {c('[5]', Fore.GREEN)}   Ethical Hacking & Pentest  {Fore.YELLOW}(SQLi, XSS, Path traversal, Subdomain){RESET}")
        print(f"  {c('[6]', Fore.CYAN)}   SIEM & Log Analysis  {Fore.YELLOW}(Log analyzer, Real-time monitor, Alerts){RESET}")
        print(f"  {c('[7]', Fore.RED)}    Stress Testing  {Fore.YELLOW}(Minecraft, Web, IP flood){RESET}")
        print(f"  {c('[8]', Fore.YELLOW)}  OSINT Reconnaissance  {Fore.YELLOW}(Phone, Email, GeoIP, DNS, Subdomain, Social, Web){RESET}")
        print(f"  {c('[9]', Fore.MAGENTA)}  Telephone Tools  {Fore.YELLOW}(Analyze, Country codes, Format){RESET}")
        print(f"  {c('[10]', Fore.BLUE)}  Network Utilities  {Fore.YELLOW}(Port scan, SSL, HTTP headers, Ping, Traceroute){RESET}")
        print(f"  {c('[q]', Fore.RED)}    Quit")
        print()

        choice = input(f"  {c(f'Select module {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if choice == "1": menu_network_threat()
        elif choice == "2": menu_endpoint()
        elif choice == "3": menu_vuln()
        elif choice == "4": menu_data()
        elif choice == "5": menu_pentest()
        elif choice == "6": menu_siem()
        elif choice == "7": menu_stress()
        elif choice == "8": menu_osint()
        elif choice == "9": menu_telephone()
        elif choice == "10": menu_netutils()
        elif choice.lower() == "q":
            print(f"\n  {c('Goodbye! Stay secure and ethical.', Fore.GREEN)}\n")
            break
        else:
            print(f"  {RED}Invalid choice.{RESET}")


if __name__ == "__main__":
    main()
