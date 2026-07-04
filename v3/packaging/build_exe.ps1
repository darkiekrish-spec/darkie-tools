$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location (Join-Path $DIR "..")
New-Item -ItemType Directory -Force -Path "dist" | Out-Null
Write-Host "Building Darkie Suite Windows executable..."
pip install pyinstaller
pyinstaller --onefile --windowed --name "DarkieSuite" --icon NONE tool.py
Move-Item "dist\DarkieSuite.exe" "dist\DarkieSuite_CLI.exe" -Force
pyinstaller --onefile --windowed --name "DarkieSuiteGUI" --icon NONE gui/app.py
Move-Item "dist\DarkieSuiteGUI.exe" "dist\DarkieSuite_GUI.exe" -Force
Write-Host "Build complete. Exe files in dist/"
Read-Host "Press Enter to exit"
