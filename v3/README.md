# Darkie Suite v3 — Multi-OS Cyber Toolkit

One script, any OS. Zero dependencies.

## Install & Run (Latest Version)

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/darkie.sh | bash
wget -qO- https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/darkie.sh | bash
```

**Windows (PowerShell):**
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/darkiekrish-spec/darkie-tools/main/v3/darkie.ps1'))
```

**npm:**
```bash
npm install -g darkie-tools
darkie
```

**Or clone:**
```bash
git clone https://github.com/darkiekrish-spec/darkie-tools
cd darkie-tools/v3
./darkie.sh          # Linux/macOS
.\darkie.ps1         # Windows
```

## How It Works

`darkie.sh` / `darkie.ps1` auto-detects your OS and downloads the **latest** binary from GitHub releases:
- **Linux** → `tool.AppImage` 
- **macOS** → `tool.AppImage`
- **Windows** → `tool.exe`
- **Fallback** → runs `python3 tool.py` if Python available

## Prebuilt Binaries

| File | OS | Use |
|------|----|-----|
| `tool.AppImage` | Linux | `./tool.AppImage` |
| `tool.deb` | Debian/Ubuntu | `sudo dpkg -i tool.deb` |
| `tool.rpm` | Fedora/RHEL | `sudo rpm -ivh tool.rpm` |
| `tool.exe` | Windows | `tool.exe` |
| `tool.sh` | Linux/macOS | `./tool.sh` |
| `tool.ps1` | Windows | `.\tool.ps1` |
| `darkie.sh` | All (bash) | curl \| bash launcher |
| `darkie.ps1` | Windows | iex launcher |

## Run from Source
```bash
pip install -r requirements.txt
python3 tool.py                          # Terminal
python3 gui/app.py                       # Desktop GUI
python3 gui/web_app.py --host 0.0.0.0    # Web GUI
```

## License
Educational use only.
