# ============================================================================
#  Darkie TOOLS v5 — Universal Windows launcher (PowerShell)
#  ---------------------------------------------------------------------------
#    Local run:            .\tool.ps1                 (interactive menu)
#    Web Dashboard:        .\tool.ps1 --web [port]    (opens in your browser)
#    Desktop GUI:          .\tool.ps1 --gui           (tkinter window)
#    Full install:         .\tool.ps1 --install       (auto-install deps + add
#                                                      a global `darkie-tools` command)
#    Update:               .\tool.ps1 --update        (fetch newest version)
#    One-line install:
#      iex (iwr https://darkifolio.vercel.app/darkie-tool/install.ps1)
#  ---------------------------------------------------------------------------
#  Works on: Windows PowerShell 5.1+ and PowerShell 7.
#  On first run it auto-installs any missing Python packages.
# ============================================================================

$repoApi = "https://api.github.com/repos/darkiekrish-spec/darkie-tools/contents/"
$repoRaw = "https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main"
$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $DIR) { $DIR = "." }
$InstallDir = Join-Path $HOME ".darkie-tools"
$installMode = ($args -contains "--install") -or ($args -contains "-i")
$updateMode  = ($args -contains "--update") -or ($args -contains "-u") -or ($args -contains "-update")
$launcherFlags = @("--install","-i","--update","-u","-update")

# Auto-detect the latest version folder from the repo
function Get-LatestVersion {
    try {
        $wc = New-Object System.Net.WebClient
        $json = $wc.DownloadString($repoApi)
        $versions = @()
        foreach ($m in [regex]::Matches($json, '"name": ?"(v[\d.]+)"')) {
            $v = $m.Groups[1].Value
            if ($v -match '^v\d+(\.\d+)*$') { $versions += $v }
        }
        if ($versions.Count -eq 0) { return "v5" }
        return ($versions | Sort-Object { [version]($_.Substring(1)) })[-1]
    } catch { return "v5" }
}

function Download-File {
    param($file, $url, [switch]$Force)
    if ((Test-Path $file) -and (-not $Force)) { return $true }
    try {
        (New-Object System.Net.WebClient).DownloadFile($url, $file)
        return $true
    } catch {
        return $false
    }
}

# Read the version string from a local tool.py ("" if unknown/absent)
function Get-CachedVersion {
    param($file)
    if (-not (Test-Path $file)) { return "" }
    try {
        $line = Get-Content $file -ErrorAction Stop | Select-String '^VERSION = "([0-9][0-9.]*)"' | Select-Object -First 1
        if ($line -and $line.Matches) { return $line.Matches[0].Groups[1].Value }
    } catch {}
    return ""
}

# Compare two dotted versions: true if $a >= $b
function Test-VersionGe {
    param($a, $b)
    $aa = $a -split '\.'; $bb = $b -split '\.'
    $max = [Math]::Max($aa.Count, $bb.Count)
    for ($i = 0; $i -lt $max; $i++) {
        $ad = 0; $bd = 0
        if ($i -lt $aa.Count) { [void][int]::TryParse($aa[$i], [ref]$ad) }
        if ($i -lt $bb.Count) { [void][int]::TryParse($bb[$i], [ref]$bd) }
        if ($ad -gt $bd) { return $true }
        if ($ad -lt $bd) { return $false }
    }
    return $true
}

# Real pip install of runtime deps (skips packaging-only pyinstaller)
function Invoke-PipInstall {
    param($py)
    $req = Join-Path $InstallDir "requirements.txt"
    if (-not (Test-Path $req)) { return }
    Write-Host "==> Installing Python dependencies (pip install -r requirements.txt) ..."
    $runtime = Join-Path $InstallDir "requirements.runtime.txt"
    Get-Content $req | Where-Object { $_ -notmatch '^\s*pyinstaller' } | Set-Content $runtime
    & $py -m ensurepip --upgrade *> $null
    & $py -m pip install --quiet --disable-pip-version-check --upgrade -r $runtime *> $null
    if ($LASTEXITCODE -ne 0) {
        & $py -m pip install --quiet --disable-pip-version-check -r $req *> $null
    }
    Remove-Item $runtime -ErrorAction SilentlyContinue
}

if ($args -contains "-h" -or $args -contains "--help") {
    Write-Host @"
Darkie TOOLS v5 - Ultimate Cyber Toolkit (educational, own-account only)

USAGE
  .\tool.ps1              open the interactive menu
  .\tool.ps1 --web        open the Web Dashboard in your browser (port 5000)
  .\tool.ps1 --web 8080   Web Dashboard on a custom port
  .\tool.ps1 --gui        open the Desktop GUI (tkinter)
  .\tool.ps1 --install    install dependencies and add a global darkie-tools command
  .\tool.ps1 --update     download the newest version and update your local copy

On first run, missing Python packages are installed automatically. Python 3 is required.
"@
    exit 0
}

$VERSION = Get-LatestVersion
$RAW = "$repoRaw/$VERSION"

# 1) Resolve tool.py (local source, cached copy, or download the latest)
$toolPy = ""
$needDownload = $updateMode
if (-not $updateMode) {
    $localPy = Join-Path $DIR "tool.py"
    if (Test-Path $localPy) { $toolPy = $localPy }
    else {
        $cachedPy = Join-Path $InstallDir "tool.py"
        if (Test-Path $cachedPy) {
            # Re-download if the cached copy is an older version (fixes stuck v4 -> v5)
            $cachedVer = Get-CachedVersion $cachedPy
            $latestVer = $VERSION.Substring(1)
            if ($cachedVer -ne "" -and (Test-VersionGe $cachedVer $latestVer)) {
                $toolPy = $cachedPy
            } else {
                $needDownload = $true
            }
        } else {
            $needDownload = $true
        }
    }
}

# 2) Prefer the prebuilt .exe when a release build exists (not during update)
if ((-not $toolPy) -and (-not $updateMode) -and (-not $needDownload)) {
    $exe = Join-Path $InstallDir "tool.exe"
    if (Download-File $exe "$RAW/tool.exe") {
        & $exe ($args | Where-Object { $launcherFlags -notcontains $_ })
        exit $LASTEXITCODE
    }
}

# 3) Fallback: fetch the source into the install dir
if ((-not $toolPy) -or $needDownload) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $toolPy = Join-Path $InstallDir "tool.py"
    Write-Host ("==> Downloading Darkie TOOLS {0} ..." -f $VERSION)
    Remove-Item $toolPy -ErrorAction SilentlyContinue
    if (-not (Download-File $toolPy "$RAW/tool.py")) {
        Write-Host "ERROR: Could not download tool.py. Check your internet connection."
        exit 1
    }
    [void](Download-File (Join-Path $InstallDir "requirements.txt") "$RAW/requirements.txt")
    [void](Download-File (Join-Path $InstallDir "mc_bots.js") "$RAW/mc_bots.js")
    # Also refresh the saved launcher so the installed `darkie-tools` stays current
    [void](Download-File (Join-Path $InstallDir "tool.ps1") "$RAW/tool.ps1" -Force)
}

# 4) Ensure Python 3 is available
$py = "python"
try {
    $ver = & $py -c "import sys; print(sys.version_info[0])"
    if ($ver -ne "3") { $py = $null }
} catch { $py = $null }
if (-not $py) {
    Write-Host "ERROR: Python 3 is required but not installed (https://python.org)."
    exit 1
}

# 5) Auto-install missing Python packages (skip with DARKIE_SKIP_DEPS=1)
if ($env:DARKIE_SKIP_DEPS -ne "1") {
    Invoke-PipInstall -py $py
}

# 6) Full install: persist files + add a global `darkie-tools` command
if ($installMode) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if ((Test-Path (Join-Path $DIR "tool.py")) -and (Join-Path $DIR "tool.py") -ne $toolPy) {
        Copy-Item (Join-Path $DIR "tool.py") $toolPy -Force
    }
    # Save this launcher next to tool.py so `darkie-tools --update` works later
    $myPs1 = $MyInvocation.MyCommand.Definition
    if ($myPs1 -and (Test-Path $myPs1)) {
        $savedPs1 = Join-Path $InstallDir "tool.ps1"
        if ((Split-Path $myPs1) -ne $InstallDir) {
            Copy-Item $myPs1 $savedPs1 -Force
        }
    }
    # darkie-tools.cmd routes through tool.ps1 so --install/--update still work
    $ps1Path = Join-Path $InstallDir "tool.ps1"
    $cmdPath = Join-Path $InstallDir "darkie-tools.cmd"
    "@echo off`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"$ps1Path`" %*`r`n" | Set-Content $cmdPath
    $binDir = Join-Path $InstallDir "bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    New-Item -ItemType HardLink -Path (Join-Path $binDir "darkie-tools.cmd") -Value $cmdPath -Force -ErrorAction SilentlyContinue
    $envPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($envPath -notlike "*$binDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$envPath;$binDir", "User")
    }
    Write-Host "==> Installed. Open a new terminal and type darkie-tools to launch from anywhere."
}

# 7) Run, stripping launcher-only flags (--install / --update / -u ...)
$toolArgs = @($args | Where-Object { $launcherFlags -notcontains $_ })
& $py $toolPy $toolArgs
exit $LASTEXITCODE