#!/usr/bin/env bash
# ============================================================================
#  DARKIE TOOLS — UNIVERSAL bootstrap installer
#  -------------------------------------------
#  ONE script for EVERY operating system. It detects the OS you are on and
#  automatically runs the right installer for it:
#
#      Linux / macOS / WSL   -> runs the Unix installer (install.sh flow)
#      Windows Git-Bash      -> detects Windows and delegates to install.ps1
#                               via powershell.exe
#
#  Short, clean URL (hosted on the portfolio / Vercel):
#      curl -fsSL https://darkifolio.vercel.app/darkie-tool/install | bash
#
#  It does NOT hard-code a version. It scans the version-folder list from the
#  darkie-tools repo (v1, v2, v3, v4, v5, ...) and runs the NEWEST one
#  automatically. So whenever a new version folder is published (v5, v5.1, ...)
#  this same URL keeps working — no releases needed.
#
#  This file stays tiny: it just picks the newest version and streams that
#  version's own launcher (e.g. <version>/tool.sh), which does the real
#  download + dependency install.
# ============================================================================
set -e

REPO="darkiekrish-spec/darkie-tools"
API="https://api.github.com/repos/$REPO/contents/"
RAW_PREFIX="https://raw.githubusercontent.com/$REPO/main"

# --- OS detection ------------------------------------------------------------
detect_os() {
    case "$(uname -s 2>/dev/null)" in
        Linux)  echo "linux" ;;
        Darwin) echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*|*_NT-*) echo "windows" ;;
        *)      echo "unix" ;;
    esac
}

# --- helpers ---------------------------------------------------------------
download_stdout() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        echo "ERROR: need 'curl' or 'wget' to fetch." >&2
        exit 1
    fi
}

# v_gt A B  -> exit 0 if numeric version A > B, else exit 1
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

# latest_version -> prints the newest folder name, e.g. "v5"
latest_version() {
    local list v best="0"
    list="$(download_stdout "$API")"
    for v in $(printf '%s' "$list" | grep -oE '"name": ?"v[0-9.]+"' | grep -oE 'v[0-9.]+'); do
        [[ "$v" =~ ^v[0-9]+(\.[0-9]+)*$ ]] || continue
        if v_gt "${v#v}" "$best"; then
            best="${v#v}"
        fi
    done
    printf 'v%s\n' "$best"
}

# --- main ------------------------------------------------------------------
OS="$(detect_os)"
echo "==> Darkie TOOLS — detected OS: $OS"

# Windows? Delegate to the PowerShell installer (also works from Git-Bash).
if [ "$OS" = "windows" ]; then
    echo "==> Delegating to install.ps1 (Windows PowerShell installer) ..."
    TMP_PS1="$(mktemp --suffix=.ps1 2>/dev/null || echo /tmp/darkie-install.ps1)"
    download_stdout "$RAW_PREFIX/darkie-tool/install.ps1" > "$TMP_PS1"
    if command -v powershell.exe >/dev/null 2>&1; then
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w "$TMP_PS1" 2>/dev/null || echo "$TMP_PS1")" "$@"
        rm -f "$TMP_PS1"
        exit $?
    elif command -v pwsh >/dev/null 2>&1; then
        pwsh -NoProfile -ExecutionPolicy Bypass -File "$TMP_PS1" "$@"
        rm -f "$TMP_PS1"
        exit $?
    fi
    echo "ERROR: PowerShell not found on this Windows system." >&2
    exit 1
fi

echo "==> Detecting newest version from repo ..."
VERSION="$(latest_version)"
[ -n "$VERSION" ] && [ "$VERSION" != "v0" ] || VERSION="v5"
echo "==> Newest version detected: $VERSION"
echo ""

# Ask the user how they want to use it (skipped when a flag is given).
MODE_ARGS=()
case "$1" in
    --install|-i)          echo "==> Installing Darkie TOOLS on your system ..."; MODE_ARGS=(--install); shift ;;
    --live|--run|-r)       echo "==> Running Darkie TOOLS live (no install) ..."; shift ;;
    *)
        if [ -t 0 ]; then
            echo "How do you want to use Darkie TOOLS?"
            echo "  1) Run live        — just launch it now, nothing installed"
            echo "  2) Install system  — adds a global \`darkie-tools\` command"
            printf 'Choose (1/2) [1]: '
            read -r ANS
        else
            printf 'How do you want to use Darkie TOOLS? (1=live, 2=install) [1]: ' >/dev/tty 2>/dev/null || true
            read -r ANS </dev/tty 2>/dev/null || ANS="1"
        fi
        case "$ANS" in
            2|[Ii]|[Ii]nstall) echo "    Installing on your system — after it finishes, run \`darkie-tools\` from anywhere."
                               MODE_ARGS=(--install) ;;
            *)                 echo "    Running live. To install later: curl -fsSL https://darkifolio.vercel.app/darkie-tool/install | bash -s -- --install" ;;
        esac
        ;;
esac

echo ""
echo "==> Launching $VERSION ..."

# Stream that version's own launcher with any install flags passed through.
download_stdout "$RAW_PREFIX/$VERSION/tool.sh" | bash -s -- "${MODE_ARGS[@]}" "$@"
