@echo off
cd /d "%~dp0.."
if not exist dist mkdir dist
echo Building Darkie Suite Windows executable...
pip install pyinstaller
pyinstaller --onefile --windowed --name "DarkieSuite" --icon NONE tool.py
move dist\DarkieSuite.exe dist\DarkieSuite_CLI.exe
pyinstaller --onefile --windowed --name "DarkieSuiteGUI" --icon NONE gui\app.py
move dist\DarkieSuiteGUI.exe dist\DarkieSuite_GUI.exe
echo Build complete. Exe files in dist/
pause
