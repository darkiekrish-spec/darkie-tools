# Darkie Tester

**Educational Network Stress Testing Tool v1.0**

A cross-platform stress testing utility for evaluating the resilience of Minecraft and web servers on your own infrastructure.

> ⚠ **WARNING**: This tool is for **educational purposes only**. Only use on systems you own or have explicit written permission to test. Unauthorized use may violate computer fraud laws.

---

## Features

- **Auto-dependency installer** — Detects your OS (Linux, macOS, Windows) and automatically installs missing Python/system packages
- **Two test modes** — Minecraft server stress test & web server stress test
- **Port scanning** — Uses nmap to discover open ports, with dedicated Minecraft port probing (25565, 25566, 25575, 19132, 19133)
- **DNS resolution** — Resolves domains to IPs and displays DNS records
- **Concurrent threading** — 50+ worker threads for meaningful throughput
- **Real-time progress** — Live progress bar with sent/error counts and packets-per-second stats
- **Loop mode** — Run multiple tests in a single session without restarting
- **Legal safeguards** — Built-in warnings and confirmation prompts at every stage

---

## Requirements

Detected and installed automatically on first run:

| Component | Linux | macOS | Windows |
|-----------|-------|-------|---------|
| Python 3 | system-python | system-python | python.org |
| nmap | apt/dnf/pacman/apk | brew | choco |
| host (DNS) | dnsutils/bind-utils | bind | N/A |
| figlet | apt/dnf/pacman/apk | brew | choco |
| colorama | pip | pip | pip |
| requests | pip | pip | pip |

---

## Quick Start

```bash
chmod +x stress_test.py
python3 stress_test.py
```

The script will check for all dependencies and prompt to install any missing ones before showing the menu.

---

## Usage

```
  [1]  Minecraft Server Stress Test
  [2]  Web Server Stress Test
```

### Minecraft Mode
1. Accept the legal warning by typing `YES`
2. Enter the server IP or domain
3. Port scan runs automatically
4. Select a port (or accept default 25565)
5. Choose packet count (default 500)
6. Confirm and watch real-time results

### Web Mode
1. Accept the legal warning by typing `YES`
2. Enter the target URL
3. Choose request count (default 500)
4. Confirm and watch real-time results

After each test completes, you can run another test or quit.

---

## Example Output

```
  ✓ Open Ports Found:
    ├─ 22 (ssh)
    ├─ 80 (http)
    ├─ 25565 (unknown) [MINECRAFT]

    [████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 250/500  Sent: 245  Errors: 5

  ✓ Complete! Sent 245 packets in 4.2s (58.3 pkt/s)
```

---

## Directory Structure

```
.
├── stress_test.py   Main script
├── README.md        This file
└── project/         Reserved directory
```

---

## License

Open source — free to use, modify, and distribute for educational purposes.
