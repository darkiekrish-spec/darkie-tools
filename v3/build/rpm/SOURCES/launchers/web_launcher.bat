@echo off
cd /d "%~dp0.."
echo Starting Darkie Web GUI. Open http://localhost:5000 in your browser
python gui/web_app.py --host 0.0.0.0 --port 5000
pause
