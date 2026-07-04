# Darkie Suite — Universal PowerShell launcher (Windows)
#   iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/darkie-ps1'))
# Or local:  .\darkie.ps1
$repoApi = "https://api.github.com/repos/darkiekrish-spec/darkie-tools/contents/"
$repoRaw = "https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main"
$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $DIR) { $DIR = "." }
Set-Location $DIR

# Auto-detect latest version
function Get-LatestVersion {
    try {
        $wc = New-Object System.Net.WebClient
        $json = $wc.DownloadString($repoApi)
        $matches = [regex]::Matches($json, '"name":"(v[\d.]+)"')
        $versions = $matches | ForEach-Object { $_.Groups[1].Value }
        $versions = $versions | Sort-Object { [version]$_.Substring(1) }
        return $versions[-1]
    } catch { return "v3" }
}
$VERSION = Get-LatestVersion
$RAW = "$repoRaw/$VERSION"

function Download-File {
    param($file, $url)
    if (-not (Test-Path $file)) {
        Write-Host "Downloading $file..."
        try {
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($url, $file)
        } catch {
            Write-Host "ERROR: Failed to download $file`n$_"
            exit 1
        }
    }
}

$exe = Join-Path $DIR "tool.exe"
Download-File $exe "$RAW/tool.exe"
if (Test-Path $exe) { & $exe $args; exit }

try { python tool.py $args; exit } catch {}
Write-Host "ERROR: No tool.exe or Python found. Install Python from python.org"
Read-Host "Press Enter to exit"
