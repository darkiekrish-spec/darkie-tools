#!/bin/bash
# Darkie Suite — Universal installer/launcher (Linux/macOS/WSL)
# Piped:  curl -fsSL https://git.io/darkie | bash
#         wget -qO- https://git.io/darkie | bash
# Local:  ./darkie.sh
set -e
GH="https://github.com/darkiekrish-spec/darkie-tools"
RAW_BASE="https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main"

# Auto-detect latest version from repo
detect_latest() {
    local api="https://api.github.com/repos/darkiekrish-spec/darkie-tools/contents/"
    if command -v curl &>/dev/null; then
        curl -fsSL "$api" 2>/dev/null | grep -o '"name":"v[^"]*"' | grep -o 'v[0-9.]*' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1
    elif command -v wget &>/dev/null; then
        wget -qO- "$api" 2>/dev/null | grep -o '"name":"v[^"]*"' | grep -o 'v[0-9.]*' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1
    fi
}

VERSION=$(detect_latest)
[ -z "$VERSION" ] && VERSION="v3"
RAW="$RAW_BASE/$VERSION"

detect_os() {
    case "$(uname -s)" in
        Linux)
            if grep -qi microsoft /proc/version 2>/dev/null; then echo "wsl"; else echo "linux"; fi
            ;;
        Darwin) echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) echo "unknown" ;;
    esac
}

download() {
    local url="$1" out="$2"
    if command -v curl &>/dev/null; then curl -fsSL "$url" -o "$out"
    elif command -v wget &>/dev/null; then wget -q "$url" -O "$out"
    else echo "ERROR: Need curl or wget"; exit 1; fi
}

# If piped via curl|bash, use temp dir; else use script's dir
if [ -z "${BASH_SOURCE[0]:-}" ] || [ "$0" = "bash" ]; then
    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" EXIT
    cd "$TMPDIR"
else
    cd "$(dirname "$0")"
fi

case "$(detect_os)" in
    linux|macos)
        download "$RAW/tool.AppImage" "tool.AppImage"
        chmod +x tool.AppImage
        exec ./tool.AppImage
        ;;
    wsl)
        if command -v powershell.exe &>/dev/null; then
            download "$RAW/tool.exe" "tool.exe"
            exec powershell.exe -ExecutionPolicy Bypass -File "$(wslpath -w "$PWD/tool.exe")" "$@"
        fi
        download "$RAW/tool.AppImage" "tool.AppImage"
        chmod +x tool.AppImage
        exec ./tool.AppImage
        ;;
    windows)
        download "$RAW/tool.exe" "tool.exe"
        exec ./tool.exe "$@"
        ;;
    *)
        if command -v python3 &>/dev/null; then
            download "$RAW/tool.py" "tool.py"
            exec python3 tool.py "$@"
        fi
        echo "ERROR: Unsupported OS. Install Python 3 and run: python3 tool.py"
        exit 1
        ;;
esac
