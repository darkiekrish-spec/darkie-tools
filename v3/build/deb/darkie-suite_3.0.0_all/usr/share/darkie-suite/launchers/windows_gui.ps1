$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location (Join-Path $DIR "..")
python gui/app.py
Read-Host "Press Enter to exit"
