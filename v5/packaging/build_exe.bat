@echo off
cd /d "%~dp0.."
if not exist dist mkdir dist
echo Building Darkie Suite v5 Windows executable...
pip install pyinstaller
pyinstaller --onefile --name "DarkieSuite" tool.py
move dist\DarkieSuite.exe dist\DarkieSuite.exe 2>nul
echo Build complete. Exe file in dist\
pause
