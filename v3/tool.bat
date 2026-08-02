@echo off
rem ============================================================================
rem  Darkie TOOLS - Windows double-click launcher / installer
rem  Just double-click this file: it installs missing dependencies on first run
rem  and then opens the interactive menu.
rem ============================================================================
setlocal
cd /d "%~dp0"

rem Find a Python 3 interpreter
set "PY="
where python >nul 2>nul
if %errorlevel%==0 (
    python -c "import sys; sys.exit(0 if sys.version_info[0]==3 else 1)" >nul 2>nul
    if not errorlevel 1 set "PY=python"
)
if not defined PY (
    where py >nul 2>nul
    if %errorlevel%==0 set "PY=py"
)
if not defined PY (
    echo.
    echo Python 3 was not found. Install it from https://python.org
    echo ^(tick "Add Python to PATH" during install^), then run this again.
    echo.
    pause
    exit /b 1
)

rem Auto-install any missing system tools / Python packages (DARKIE_AUTOINSTALL=1)
set "DARKIE_AUTOINSTALL=1"
%PY% tool.py --deps
set "DARKIE_AUTOINSTALL="

%PY% tool.py %*
endlocal
