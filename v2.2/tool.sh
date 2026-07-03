#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
#  Darkie Security Suite v2.2 — Launcher
#  Educational use only. Test only systems you own.
# ─────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
    echo -e "${GREEN}${BOLD}"
    cat << 'EOF'
  _____             _    _         _____ ___   ___  _     ____
 |  _ \  __ _ _ __| | _(_) ___   |_   _/ _ \ / _ \| |   / ___|
 | | | |/ _` | '__| |/ / |/ _ \    | || | | | | | | |   \___ \
 | |_| | (_| | |  |   <| |  __/    | || |_| | |_| | |___ ___) |
 |____/ \__,_|_|  |_|\_\_|\___|    |_| \___/ \___/|_____|____/
EOF
    echo -e "${RESET}"
    echo -e "  ${CYAN}${BOLD}v2.2 — Ultimate Cyber Toolkit${RESET}"
    echo -e "  ${YELLOW}Author: Darkie Tester | Educational use only${RESET}"
    echo -e "  ${RED}${BOLD}DISCLAIMER: Only test systems you OWN or have PERMISSION to test.${RESET}\n"
}

check_deps() {
    echo -e "${CYAN}[*] Checking dependencies...${RESET}"

    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[!] python3 not found. Install python3 first.${RESET}"
        exit 1
    fi

    if ! python3 -c "import colorama" 2>/dev/null; then
        echo -e "${YELLOW}[!] Installing colorama...${RESET}"
        python3 -m pip install colorama -q 2>/dev/null || true
    fi

    if ! python3 -c "import requests" 2>/dev/null; then
        echo -e "${YELLOW}[!] Installing requests...${RESET}"
        python3 -m pip install requests -q 2>/dev/null || true
    fi

    if ! python3 -c "import psutil" 2>/dev/null; then
        echo -e "${YELLOW}[!] Installing psutil...${RESET}"
        python3 -m pip install psutil -q 2>/dev/null || true
    fi

    if ! command -v node &>/dev/null; then
        echo -e "${YELLOW}[!] Node.js not found. Bot attacks will use raw TCP fallback.${RESET}"
    else
        if [ ! -d "$SCRIPT_DIR/node_modules/mineflayer" ]; then
            echo -e "${YELLOW}[!] Installing mineflayer...${RESET}"
            (cd "$SCRIPT_DIR" && npm install mineflayer --save 2>/dev/null) || true
        fi
    fi

    echo -e "${GREEN}[+] Dependencies OK${RESET}\n"
}

usage() {
    echo -e "${BOLD}Usage:${RESET}"
    echo -e "  $0                  Launch interactive CLI"
    echo -e "  $0 --gui            Launch GUI (tkinter)"
    echo -e "  $0 --mc <ip> [port] Quick Minecraft stress test"
    echo -e "  $0 --web <url>      Quick web stress test"
    echo -e "  $0 --ip <ip>        Quick IP flood test"
    echo -e "  $0 --realip <host>  Find real origin IP (bypass Cloudflare)"
    echo -e "  $0 --ports <ip>     Scan for Minecraft ports (Pterodactyl-aware)"
    echo -e "  $0 --help           Show this help\n"
}

main() {
    banner
    check_deps

    case "${1:-}" in
        --gui)
            if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
                echo -e "${YELLOW}[!] No display detected. Launching CLI instead.${RESET}"
                exec python3 "$SCRIPT_DIR/tool.py"
            fi
            echo -e "${CYAN}[*] Launching GUI...${RESET}"
            exec python3 "$SCRIPT_DIR/gui.py" "${@:2}"
            ;;
        --mc)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}[!] Usage: $0 --mc <ip> [port]${RESET}"
                exit 1
            fi
            MC_IP="$2"
            MC_PORT="${3:-25565}"
            echo -e "${CYAN}[*] Quick MC stress: $MC_IP:$MC_PORT${RESET}"
            python3 "$SCRIPT_DIR/tool.py" <<< "$(printf '6\n1\n%s\n%s\nr\n30\n500\n' "$MC_IP" "$MC_PORT")"
            ;;
        --web)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}[!] Usage: $0 --web <url>${RESET}"
                exit 1
            fi
            echo -e "${CYAN}[*] Quick web stress: $2${RESET}"
            python3 "$SCRIPT_DIR/tool.py" <<< "$(printf '6\n2\n%s\n\n500\n' "$2")"
            ;;
        --ip)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}[!] Usage: $0 --ip <ip>${RESET}"
                exit 1
            fi
            echo -e "${CYAN}[*] Quick IP flood: $2${RESET}"
            python3 "$SCRIPT_DIR/tool.py" <<< "$(printf '6\n3\n%s\na\n500\n' "$2")"
            ;;
        --realip)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}[!] Usage: $0 --realip <host>${RESET}"
                exit 1
            fi
            echo -e "${CYAN}[*] Finding real IP for: $2${RESET}"
            python3 -c "
import sys; sys.path.insert(0, '$SCRIPT_DIR')
from tool import find_real_ip
find_real_ip('$2')
"
            ;;
        --ports)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}[!] Usage: $0 --ports <ip>${RESET}"
                exit 1
            fi
            echo -e "${CYAN}[*] Scanning MC ports on: $2${RESET}"
            python3 -c "
import sys; sys.path.insert(0, '$SCRIPT_DIR')
from tool import mc_find_ports
mc_find_ports('$2')
"
            ;;
        --help|-h)
            usage
            ;;
        "")
            echo -e "${CYAN}[*] Launching interactive CLI...${RESET}"
            exec python3 "$SCRIPT_DIR/tool.py"
            ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${RESET}"
            usage
            exit 1
            ;;
    esac
}

main "$@"
