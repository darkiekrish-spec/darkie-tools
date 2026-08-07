#!/usr/bin/env bash
# ============================================================================
#  Darkie TOOLS v5 — Universal launcher / installer (one file, all platforms)
#  ---------------------------------------------------------------------------
#    Local run:            ./tool.sh                (interactive menu)
#    Web Dashboard:        ./tool.sh --web [port]   (opens in your browser)
#    Desktop GUI:          ./tool.sh --gui          (tkinter window)
#    Full install:         ./tool.sh --install      (auto-install deps + make
#                                                    `darkie-tools` a command)
#    One-line install:
#      curl -fsSL https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v5/tool.sh | bash
#      wget -qO-  https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v5/tool.sh | bash
#  ---------------------------------------------------------------------------
#  Works on: Linux, macOS, WSL and Windows-GitBash.
#  On first run it auto-installs any missing system tools and Python packages.
# ============================================================================
set -e

GH="https://github.com/darkiekrish-spec/darkie-tools"
RAW_BASE="https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main"
INSTALL_DIR="${DARKIE_TOOLS_HOME:-$HOME/.darkie-tools}"
INSTALL_MODE="0"
UPDATE_MODE="0"
UNINSTALL_MODE="0"

# v_gt A B -> exit 0 (true) if numeric dotted version A > B
v_gt() {
    local a b i ad bd max
    IFS=. read -ra a <<< "${1#v}"
    IFS=. read -ra b <<< "${2#v}"
    max=${#a[@]}
    (( ${#b[@]} > max )) && max=${#b[@]}
    for (( i=0; i<max; i++ )); do
        ad=$(( 10${a[$i]:-0} ))
        bd=$(( 10${b[$i]:-0} ))
        (( ad > bd )) && return 0
        (( ad < bd )) && return 1
    done
    return 1
}

# Auto-detect the latest version folder from the repo (portable: macOS + GNU)
detect_latest() {
    local api="https://api.github.com/repos/darkiekrish-spec/darkie-tools/contents/"
    local list="" best="0" v ver
    if command -v curl &>/dev/null; then
        list="$(curl -fsSL "$api" 2>/dev/null)"
    elif command -v wget &>/dev/null; then
        list="$(wget -qO- "$api" 2>/dev/null)"
    fi
    [ -z "$list" ] && { printf 'v5\n'; return 0; }
    for v in $(printf '%s' "$list" | grep -oE '"name": ?"v[0-9.]+"' | grep -oE 'v[0-9.]+'); do
        [[ "$v" =~ ^v[0-9]+(\.[0-9]+)*$ ]] || continue
        ver="${v#v}"
        if v_gt "$ver" "$best"; then best="$ver"; fi
    done
    printf 'v%s\n' "$best"
}

# download <url> <out> -> 0 on success, non-zero otherwise
download() {
    if command -v curl &>/dev/null; then
        curl -fsSL "$1" -o "$2" 2>/dev/null && return 0
    elif command -v wget &>/dev/null; then
        wget -q "$1" -O "$2" 2>/dev/null && return 0
    else
        return 2
    fi
    return 1
}

need_cmd() {
    if command -v "$1" >/dev/null 2>&1; then return 0; else return 1; fi
}

# Reattach stdin to the controlling terminal when launched via `curl | bash`.
# Otherwise tool.py's input() reads from the already-consumed curl pipe and
# immediately hits EOF ("EOF when reading a line").
reattach_tty() {
    if [ -e /dev/tty ] && [ ! -t 0 ]; then
        exec "$@" < /dev/tty || true
    fi
    exec "$@"
}

usage() {
    cat <<EOF
Darkie TOOLS v5 — Ultimate Cyber Toolkit (educational, own-account only)

USAGE
  ./tool.sh               open the interactive menu
  ./tool.sh --web         open the Web Dashboard in your browser (port 5000)
  ./tool.sh --web 8080    Web Dashboard on a custom port
  ./tool.sh --gui         open the Desktop GUI (tkinter)
  ./tool.sh --host 0.0.0.0 --web   share the dashboard over your network
  ./tool.sh --install     install dependencies and add a global \`darkie-tools\` command
  ./tool.sh --update      download the newest version and update your local copy
  ./tool.sh --uninstall   remove darkie-tools and its installed files

On first run, missing system tools and Python packages are installed
automatically (may ask for your sudo/admin password). Python 3 is required.
EOF
    exit 0
}

for a in "$@"; do
    case "$a" in
        -h|--help) usage ;;
        --install) INSTALL_MODE="1" ;;
        -u|--update|-update) UPDATE_MODE="1" ;;
        --uninstall) UNINSTALL_MODE="1" ;;
    esac
done

# If piped via curl|bash there is no script dir; else use the script's own dir
if [ -n "${BASH_SOURCE[0]:-}" ] && [ "$0" != "bash" ]; then
    LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"
else
    LOCAL_DIR=""
fi

# 0) Uninstall: remove the global command + installed copy (no network needed).
#    Keeps ~/.darkie-tools unless the user explicitly wants it fully gone.
if [ "$UNINSTALL_MODE" = "1" ]; then
    echo ""
    echo "  Darkie TOOLS $VERSION — Uninstall"
    echo "  ---------------------------------------------------------"
    echo "  This will remove:"
    echo "    • the global \`darkie-tools\` command (if installed)"
    echo "    • ~/.darkie-tools (the installed copy, incl. wordlists)"
    echo ""
    if [ -t 0 ]; then
        read -r -p "  Remove everything? [y/N] " ans
    else
        ans=""
    fi
    if [[ "$ans" != "y" && "$ans" != "Y" && "$ans" != "yes" && "$ans" != "YES" ]]; then
        echo "  Uninstall cancelled."
        exit 0
    fi
    for link in /usr/local/bin/darkie-tools "$HOME/.local/bin/darkie-tools"; do
        if [ -e "$link" ] || [ -L "$link" ]; then
            if [ -w "$(dirname "$link")" ]; then
                rm -f "$link" && echo "  Removed $link"
            elif need_cmd sudo; then
                sudo rm -f "$link" && echo "  Removed $link (via sudo)"
            fi
        fi
    done
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        echo "  Removed $INSTALL_DIR"
    fi
    echo "  Darkie TOOLS uninstalled. Goodbye!"
    exit 0
fi

# Compare dotted versions: a >= b -> exit 0
_v_ge() {
    local a b i ad bd max
    IFS=. read -ra a <<< "$1"
    IFS=. read -ra b <<< "$2"
    max=${#a[@]}; (( ${#b[@]} > max )) && max=${#b[@]}
    for (( i=0; i<max; i++ )); do
        ad=$(( 10${a[$i]:-0} )); bd=$(( 10${b[$i]:-0} ))
        (( ad > bd )) && return 0
        (( ad < bd )) && return 1
    done
    return 0
}

# Read the VERSION embedded in a local tool.py copy (e.g. "5.0.0")
_cached_version() {
    local f="$1" v
    v="$(sed -n 's/^VERSION = "\([0-9][0-9.]*\)".*/\1/p' "$f" 2>/dev/null | head -1)"
    printf '%s' "$v"
}

# --------------------------------------------------------------------------
# 1) Resolve tool.py (local repo dir, cached copy, or download the latest)
# --------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
TOOL_PY=""
NEED_DL="0"
REFRESH_LAUNCHER="0"
VERSION="$(detect_latest)"; [ -z "$VERSION" ] && VERSION="v5"
NEWEST="${VERSION#v}"

if [ "$UPDATE_MODE" = "1" ]; then
    NEED_DL="1"                                      # --update: always refresh
elif [ -n "$LOCAL_DIR" ] && [ -f "$LOCAL_DIR/tool.py" ]; then
    if [ "$LOCAL_DIR" = "$INSTALL_DIR" ]; then
        # Running the installed launcher: verify the cached copy's version too
        CACHED="$(_cached_version "$LOCAL_DIR/tool.py")"
        if [ -n "$CACHED" ] && _v_ge "$CACHED" "$NEWEST"; then
            TOOL_PY="$LOCAL_DIR/tool.py"
        else
            echo "==> Local copy is out of date${CACHED:+ (v$CACHED)}. Updating to $VERSION ..."
            NEED_DL="1"
        fi
    else
        TOOL_PY="$LOCAL_DIR/tool.py"                 # run straight from repo dir
    fi
elif [ -f "$INSTALL_DIR/tool.py" ]; then
    CACHED="$(_cached_version "$INSTALL_DIR/tool.py")"
    if [ -n "$CACHED" ] && _v_ge "$CACHED" "$NEWEST"; then
        TOOL_PY="$INSTALL_DIR/tool.py"               # cached copy is current
    else
        # Cached copy is stale (e.g. v4 present while v5 is latest) -> refresh
        echo "==> Local copy is out of date${CACHED:+ (v$CACHED)}. Updating to $VERSION ..."
        NEED_DL="1"
    fi
else
    NEED_DL="1"
fi

if [ "$NEED_DL" = "1" ]; then
    # Prefer a prebuilt binary when a release build exists (no Python needed)
    if [ "$UPDATE_MODE" != "1" ] && download "$RAW_BASE/$VERSION/tool.AppImage" "$INSTALL_DIR/tool.AppImage"; then
        chmod +x "$INSTALL_DIR/tool.AppImage"
        reattach_tty "$INSTALL_DIR/tool.AppImage" "$@"
    fi
    echo "==> Downloading Darkie TOOLS $VERSION ..."
    if ! download "$RAW_BASE/$VERSION/tool.py" "$INSTALL_DIR/tool.py"; then
        echo "ERROR: Could not download tool.py. Check your internet connection."
        exit 1
    fi
    download "$RAW_BASE/$VERSION/requirements.txt" "$INSTALL_DIR/requirements.txt" || true
    download "$RAW_BASE/$VERSION/mc_bots.js" "$INSTALL_DIR/mc_bots.js" || true
    # Ship the bundled 14M-password rockyou wordlist (cracker DB)
    download "$RAW_BASE/$VERSION/wordlists/rockyou.txt.gz" "$INSTALL_DIR/wordlists/rockyou.txt.gz" || true
    # Refresh the stored launcher AFTER tool.py exits (can't overwrite the
    # currently-executing file mid-run — it would corrupt bash).
    REFRESH_LAUNCHER="1"
    TOOL_PY="$INSTALL_DIR/tool.py"
fi

# 2) Ensure Python 3 is available
PY=""
for c in python3 python; do
    if need_cmd "$c" && "$c" -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' 2>/dev/null; then
        PY="$c"; break
    fi
done
if [ -z "$PY" ]; then
    echo "ERROR: Python 3 is required but not installed (https://python.org)."
    echo "  Or clone it: git clone $GH && cd darkie-tools/v5 && ./tool.sh"
    exit 1
fi

# 3) Auto-install missing Python packages on first run (works on any OS).
#    DARKIE_SKIP_DEPS=1 skips this (used by the website playground for speed)
if [ "${DARKIE_SKIP_DEPS:-0}" != "1" ] && [ -f "$INSTALL_DIR/requirements.txt" ]; then
    echo "==> Installing Python dependencies (pip install -r requirements.txt) ..."
    "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
    # skip packaging-only pyinstaller for speed
    if command -v grep >/dev/null 2>&1; then
        grep -v -i '^[[:space:]]*pyinstaller' "$INSTALL_DIR/requirements.txt" > "$INSTALL_DIR/requirements.runtime.txt" 2>/dev/null || true
    fi
    if [ -s "$INSTALL_DIR/requirements.runtime.txt" ]; then
        "$PY" -m pip install --quiet --disable-pip-version-check --upgrade -r "$INSTALL_DIR/requirements.runtime.txt" >/dev/null 2>&1 \
            || "$PY" -m pip install --quiet --disable-pip-version-check -r "$INSTALL_DIR/requirements.txt" >/dev/null 2>&1 || true
    else
        "$PY" -m pip install --quiet --disable-pip-version-check --upgrade -r "$INSTALL_DIR/requirements.txt" >/dev/null 2>&1 || true
    fi
    rm -f "$INSTALL_DIR/requirements.runtime.txt"
fi

# 4) Full install: persist files + add a global `darkie-tools` command
if [ "$INSTALL_MODE" = "1" ]; then
    if [ -n "$LOCAL_DIR" ] && [ "$LOCAL_DIR" != "$INSTALL_DIR" ]; then
        cp "$LOCAL_DIR/tool.py" "$INSTALL_DIR/tool.py"
        cp -f "$LOCAL_DIR/tool.sh" "$INSTALL_DIR/tool.sh" 2>/dev/null || true
        cp -f "$LOCAL_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt" 2>/dev/null || true
    fi
    TOOL_PY="$INSTALL_DIR/tool.py"
    # Keep a fresh copy of this launcher so `darkie-tools --update` works later.
    # If we ARE the stored launcher, defer the refresh until after tool.py exits.
    VERSION="$(detect_latest)"; [ -z "$VERSION" ] && VERSION="v5"
    if [ "$0" = "$INSTALL_DIR/tool.sh" ]; then
        REFRESH_LAUNCHER="1"
    elif [ ! -f "$INSTALL_DIR/tool.sh" ] || [ "$UPDATE_MODE" = "1" ]; then
        download "$RAW_BASE/$VERSION/tool.sh" "$INSTALL_DIR/tool.sh" || true
    fi
    chmod +x "$INSTALL_DIR/tool.sh" 2>/dev/null || true
    cat > "$INSTALL_DIR/darkie-tools" <<EOS
#!/usr/bin/env bash
exec bash "$INSTALL_DIR/tool.sh" "\$@"
EOS
    chmod +x "$INSTALL_DIR/darkie-tools"
    if [ -w /usr/local/bin ]; then
        ln -sf "$INSTALL_DIR/darkie-tools" /usr/local/bin/darkie-tools
    elif need_cmd sudo && sudo -n true 2>/dev/null; then
        sudo ln -sf "$INSTALL_DIR/darkie-tools" /usr/local/bin/darkie-tools
    elif need_cmd sudo; then
        # Interactive: prompt for the sudo password right here so the global
        # `darkie-tools` command also works after `sudo su` / as root.
        if sudo -v 2>/dev/null && sudo ln -sf "$INSTALL_DIR/darkie-tools" /usr/local/bin/darkie-tools; then
            :
        else
            echo "  No access to /usr/local/bin. Linking into ~/.local/bin instead."
            mkdir -p "$HOME/.local/bin"
            ln -sf "$INSTALL_DIR/darkie-tools" "$HOME/.local/bin/darkie-tools"
            echo "  Added ~/.local/bin/darkie-tools — add ~/.local/bin to your PATH if needed."
        fi
    else
        mkdir -p "$HOME/.local/bin"
        ln -sf "$INSTALL_DIR/darkie-tools" "$HOME/.local/bin/darkie-tools"
        echo "  Added ~/.local/bin/darkie-tools — add ~/.local/bin to your PATH if needed."
    fi
    echo "==> Installed. Type \`darkie-tools\` from anywhere to launch."
fi

# Filter launcher-only flags out of the args we pass on to tool.py
ARGS=()
for a in "$@"; do
    case "$a" in
        --install|-u|--update|-update|--uninstall) ;;
        *) ARGS+=("$a") ;;
    esac
done

reattach_tty "$PY" "$TOOL_PY" "${ARGS[@]}"
_rc=$?

# Deferred launcher refresh: only now that the old script is done executing can
# we safely replace it (atomic tmp+mv).
if [ "$REFRESH_LAUNCHER" = "1" ]; then
    if download "$RAW_BASE/$VERSION/tool.sh" "$INSTALL_DIR/tool.sh.tmp" && mv -f "$INSTALL_DIR/tool.sh.tmp" "$INSTALL_DIR/tool.sh"; then
        chmod +x "$INSTALL_DIR/tool.sh" 2>/dev/null || true
        echo "==> Launcher updated to $VERSION (run \`darkie-tools\` to use it)."
    fi
fi

exit $_rc
