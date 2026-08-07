# ============================================================================
#  DARKIE TOOLS — UNIVERSAL bootstrap installer (PowerShell)
#  -------------------------------------------
#  ONE script for EVERY operating system. It detects the OS you are on and
#  automatically runs the right installer for it:
#
#      Windows                -> runs the Windows installer (tool.ps1 flow)
#      Linux / macOS (pwsh)   -> detects non-Windows and delegates to the
#                                Unix installer (install.sh) via bash
#
#  Short, clean URL (hosted on the portfolio / Vercel):
#      iex (iwr https://darkifolio.vercel.app/darkie-tool/install.ps1)
#
#  Auto-detects the NEWEST version folder in darkie-tools (v1 ... v5, ...)
#  then asks (or via flags) whether to run live or install a global
#  `darkie-tools` command. Works in Windows PowerShell 5.1+ and PowerShell 7.
# ============================================================================
$ErrorActionPreference = "Stop"

# --- OS detection ------------------------------------------------------------
function Test-IsWindows {
    if ($env:OS -like "*Windows*") { return $true }
    try {
        $p = [System.Environment]::OSVersion.Platform
        if ($p -eq [System.PlatformID]::Win32NT) { return $true }
        if ($p -eq [System.PlatformID]::Win32Windows) { return $true }
    } catch {}
    return $false
}

# Not on Windows? Delegate to the bash installer (also works from pwsh on Unix).
if (-not (Test-IsWindows)) {
    Write-Host "==> Darkie TOOLS - detected non-Windows OS. Delegating to install.sh ..."
    if (-not (Get-Command bash -ErrorAction SilentlyContinue)) {
        Write-Error "bash not found. Please run the installer with the shell of your OS."
        exit 1
    }
    $tmp = Join-Path $env:TEMP "darkie-install.sh"
    (New-Object System.Net.WebClient).DownloadFile(
        "https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/darkie-tool/install.sh",
        $tmp)
    & bash "$tmp" @args
    Remove-Item $tmp -ErrorAction SilentlyContinue
    exit $LASTEXITCODE
}

$repo  = "darkiekrish-spec/darkie-tools"
$api   = "https://api.github.com/repos/$repo/contents/"
$raw   = "https://raw.githubusercontent.com/$repo/main"

function Get-LatestVersion {
    try {
        $wc = New-Object System.Net.WebClient
        $json = $wc.DownloadString($api)
        $versions = @()
        foreach ($m in [regex]::Matches($json, '"name": ?"(v[\d.]+)"')) {
            $v = $m.Groups[1].Value
            if ($v -match '^v\d+(\.\d+)*$') { $versions += $v }
        }
        if ($versions.Count -eq 0) { return "v5" }
        return ($versions | Sort-Object { [version]($_.Substring(1)) })[-1]
    } catch { return "v5" }
}

Write-Host "==> Darkie TOOLS - detected OS: Windows"
Write-Host "==> Detecting the newest version from the repo ..."
$version = Get-LatestVersion
Write-Host "==> Newest version detected: $version"

# Resolve the mode: from a flag, else prompt the user.
$mode = ""
if ($args -contains "--install") { $mode = "install" }
elseif ($args -contains "--live") { $mode = "live" }
else {
    Write-Host ""
    Write-Host "How do you want to use Darkie TOOLS?"
    Write-Host "  1) Run live        - just launch it now, nothing installed"
    Write-Host "  2) Install system  - adds a global darkie-tools command"
    $ans = Read-Host "Choose (1/2) [1]"
    if ($ans.Trim() -eq "2" -or $ans -match "^[Ii]") { $mode = "install" } else { $mode = "live" }
}

# Download that version's Windows launcher and run it with the chosen mode.
$toolPs1 = "$raw/$version/tool.ps1"
$local = Join-Path $env:TEMP "darkie-tools-$version.ps1"
(New-Object System.Net.WebClient).DownloadFile($toolPs1, $local)

if ($mode -eq "install") {
    Write-Host ("==> Launching {0} installer ..." -f $version)
    & $local "--install"
} else {
    Write-Host ("==> Launching {0} ..." -f $version)
    & $local
}
Remove-Item $local -ErrorAction SilentlyContinue
