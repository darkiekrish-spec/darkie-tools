$DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location (Join-Path $DIR "..")
python tool.py
Read-Host "Press Enter to exit"
