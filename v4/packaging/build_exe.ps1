$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location (Join-Path $DIR "..")
New-Item -ItemType Directory -Force -Path "dist" | Out-Null
Write-Host "Building Darkie Suite v4 Windows executable..."
pip install pyinstaller
pyinstaller --onefile --name "DarkieSuite" tool.py
Write-Host ""
Write-Host "Build complete. Exe in dist\DarkieSuite.exe"
Write-Host "  DarkieSuite.exe             interactive menu"
Write-Host "  DarkieSuite.exe --web       Web Dashboard in your browser"
Write-Host "  DarkieSuite.exe --gui       Desktop GUI"
Read-Host "Press Enter to exit"
