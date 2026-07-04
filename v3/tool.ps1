# Darkie Suite v3 — Local Windows launcher (PowerShell, standalone)
$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $DIR

# 1) Try prebuilt .exe
$exe = Join-Path $DIR "tool.exe"
if (Test-Path $exe) {
    & $exe $args
    exit
}

# 2) Try python from source
try {
    python tool.py $args
    exit
} catch {
    # python not found
}

Write-Host "ERROR: No prebuilt binary (tool.exe) or Python found."
Write-Host "Place tool.exe in $DIR or install Python from python.org"
Read-Host "Press Enter to exit"
