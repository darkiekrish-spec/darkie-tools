# ============================================================================
#  Darkie TOOLS v4 — Universal Windows launcher (PowerShell)
#  ---------------------------------------------------------------------------
#    Local run:            .\tool.ps1                 (interactive menu)
#    Web Dashboard:        .\tool.ps1 --web [port]    (opens in your browser)
#    Desktop GUI:          .\tool.ps1 --gui           (tkinter window)
#    Full install:         .\tool.ps1 --install       (auto-install deps + add
#                                                      a global `darkie-tools` command)
#    One-line install:
#      iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v4/tool.ps1'))
#  ---------------------------------------------------------------------------
#  Works on: Windows PowerShell 5.1+ and PowerShell 7.
#  On first run it auto-installs any missing system tools and Python packages.
# ============================================================================

$repoApi = "https://api.github.com/repos/darkiekrish-spec/darkie-tools/contents/"
$repoRaw = "https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main"
$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $DIR) { $DIR = "." }
$InstallDir = Join-Path $HOME ".darkie-tools"
$installMode = $args -contains "--install"

# Auto-detect the latest version folder from the repo
function Get-LatestVersion {
    try {
        $wc = New-Object System.Net.WebClient
        $json = $wc.DownloadString($repoApi)
        $matches = [regex]::Matches($json, '"name":"(v[\d.]+)"')
        $versions = $matches | ForEach-Object { $_.Groups[1].Value }
        $versions = $versions | Sort-Object { [version]$_.Substring(1) }
        return $versions[-1]
    } catch { return "v4" }
}

function Download-File {
    param($file, $url)
    if (Test-Path $file) { return $true }
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $file)
        return $true
    } catch {
        return $false
    }
}

function Invoke-AutoInstall {
    param($py, $toolPy)
    Write-Host "==> Checking dependencies (installs anything missing)..."
    $env:DARKIE_AUTOINSTALL = "1"
    & $py $toolPy "--deps" *> $null
    if ($LASTEXITCODE -ne 0) {
        & $py $toolPy "--deps"
    }
    Remove-Item Env:DARKIE_AUTOINSTALL -ErrorAction SilentlyContinue
}

if ($args -contains "-h" -or $args -contains "--help") {
    Write-Host @"
Darkie TOOLS v4 - Ultimate Cyber Toolkit (educational, own-account only)

USAGE
  .\tool.ps1              open the interactive menu
  .\tool.ps1 --web        open the Web Dashboard in your browser (port 5000)
  .\tool.ps1 --web 8080   Web Dashboard on a custom port
  .\tool.ps1 --gui        open the Desktop GUI (tkinter)
  .\tool.ps1 --install    install dependencies and add a global darkie-tools command

On first run, missing system tools and Python packages are installed
automatically (may ask for admin approval). Python 3 is required.
"@
    exit 0
}

$VERSION = Get-LatestVersion
$RAW = "$repoRaw/$VERSION"

# 1) Run from local source when available (cloned repo or already downloaded)
$toolPy = Join-Path $DIR "tool.py"
if (-not (Test-Path $toolPy)) {
    $cachedPy = Join-Path $InstallDir "tool.py"
    if (Test-Path $cachedPy) { $toolPy = $cachedPy }
}

# 2) Prefer the prebuilt .exe when a release build is available
if (-not (Test-Path $toolPy)) {
    $exe = Join-Path $InstallDir "tool.exe"
    if (Download-File $exe "$RAW/tool.exe") {
        & $exe $args
        exit $LASTEXITCODE
    }
}

# 3) Fallback: fetch the source into the install dir
if (-not (Test-Path $toolPy)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $toolPy = Join-Path $InstallDir "tool.py"
    if (-not (Download-File $toolPy "$RAW/tool.py")) {
        Write-Host "ERROR: Could not download tool.py. Check your internet connection."
        exit 1
    }
    [void](Download-File (Join-Path $InstallDir "requirements.txt") "$RAW/requirements.txt")
    [void](Download-File (Join-Path $InstallDir "mc_bots.js") "$RAW/mc_bots.js")
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

# 5) Auto-install missing system tools and Python packages
Invoke-AutoInstall -py $py -toolPy $toolPy

# 6) Full install: add a global `darkie-tools` command
if ($installMode) {
    if ($DIR -and (Test-Path (Join-Path $DIR "tool.py"))) {
        Copy-Item (Join-Path $DIR "tool.py") $toolPy -Force
    }
    $cmdPath = Join-Path $InstallDir "darkie-tools.cmd"
    "@echo off`r`n@python `"$toolPy`" %*`r`n" | Set-Content $cmdPath
    $binDir = Join-Path $InstallDir "bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    New-Item -ItemType HardLink -Path (Join-Path $binDir "darkie-tools.cmd") -Value $cmdPath -Force -ErrorAction SilentlyContinue
    $envPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($envPath -notlike "*$binDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$envPath;$binDir", "User")
    }
    Write-Host "==> Installed. Type darkie-tools from a new terminal to launch."
}

& $py $toolPy ($args | Where-Object { $_ -ne "--install" })
exit $LASTEXITCODE
