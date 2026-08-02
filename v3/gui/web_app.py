#!/usr/bin/env python3
"""Darkie Security Suite v3 — Web GUI for VPS / remote access (Flask)"""

import io
import os
import sys
import threading
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tool import *

try:
    from flask import Flask, jsonify
except ImportError:
    print("Flask required. Install: pip install flask")
    sys.exit(1)

app = Flask(__name__)
output_queue = Queue()
current_output = []
running_threads = {}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Darkie Security Suite v3 — Web GUI</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Courier New', monospace; background: #0d0d1a; color: #eee; padding: 20px; }
  h1 { color: #e94560; border-bottom: 2px solid #533483; padding-bottom: 10px; margin-bottom: 20px; }
  .module-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; margin-bottom: 20px; }
  .module-btn { background: #16213e; color: #eee; border: 1px solid #533483; padding: 10px 16px; cursor: pointer; font-family: inherit; font-size: 13px; text-align: left; border-radius: 4px; transition: all 0.2s; }
  .module-btn:hover { background: #533483; border-color: #e94560; }
  .module-btn.running { background: #e94560; color: #fff; }
  #output { background: #1a1a2e; border: 1px solid #533483; border-radius: 4px; padding: 15px; height: 50vh; overflow-y: auto; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
  #output .info { color: #888; }
  #output .success { color: #00ff88; }
  #output .error { color: #ff4444; }
  #output .warn { color: #ffaa00; }
  ::-webkit-scrollbar { width: 8px; background: #0d0d1a; }
  ::-webkit-scrollbar-thumb { background: #533483; border-radius: 4px; }
  .status { color: #888; font-size: 12px; margin: 5px 0; }
  .clear-btn { background: #333; color: #eee; border: 1px solid #555; padding: 6px 14px; cursor: pointer; border-radius: 4px; float: right; }
  .clear-btn:hover { background: #e94560; }
</style>
</head>
<body>
<h1>Darkie Security Suite v3 — Web GUI</h1>
<div class="status">Connected. Select a module to run.</div>
<div class="module-grid" id="modules"></div>
<button class="clear-btn" onclick="clearOutput()">Clear Output</button>
<h3 style="margin-top:10px;color:#00ccff;">Output</h3>
<pre id="output"></pre>
<script>
const modules = MODULES_PLACEHOLDER;
const grid = document.getElementById('modules');
modules.forEach(m => {
  const btn = document.createElement('button');
  btn.className = 'module-btn';
  btn.textContent = m.name;
  btn.onclick = () => runModule(m.id, btn);
  grid.appendChild(btn);
});
function runModule(id, btn) {
  btn.classList.add('running');
  btn.disabled = true;
  const out = document.getElementById('output');
  out.innerHTML += '<span class="info">[+] Running ' + id + '...</span>\\n';
  out.scrollTop = out.scrollHeight;
  fetch('/run/' + id).then(r => r.json()).then(d => {
    btn.classList.remove('running');
    btn.disabled = false;
    if (d.error) out.innerHTML += '<span class="error">[!] ' + d.error + '</span>\\n';
  });
}
let lastLen = 0;
setInterval(() => {
  fetch('/output').then(r => r.json()).then(d => {
    const out = document.getElementById('output');
    if (d.lines && d.lines.length > lastLen) {
      for (let i = lastLen; i < d.lines.length; i++) {
        const cls = d.tags[i] || 'info';
        out.innerHTML += '<span class="' + cls + '">' + escapeHtml(d.lines[i]) + '</span>\\n';
      }
      lastLen = d.lines.length;
      out.scrollTop = out.scrollHeight;
    }
  });
}, 300);
function clearOutput() {
  document.getElementById('output').innerHTML = '';
  fetch('/clear').then(r => r.json());
  lastLen = 0;
}
function escapeHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
</script>
</body>
</html>"""


@app.route("/")
def index():
    return HTML_TEMPLATE.replace("MODULES_PLACEHOLDER", jsonify(get_modules()).get_data(as_text=True))


def get_modules():
    return [{"id": "menu_network_threat", "name": "Network Threat Monitoring"},
            {"id": "menu_endpoint", "name": "Endpoint Security"},
            {"id": "menu_vuln", "name": "Vulnerability Management"},
            {"id": "menu_data", "name": "Data Protection"},
            {"id": "menu_pentest", "name": "Penetration Testing"},
            {"id": "menu_siem", "name": "SIEM & Log Analysis"},
            {"id": "menu_stress", "name": "Stress Testing"},
            {"id": "menu_osint", "name": "OSINT Reconnaissance"},
            {"id": "menu_telephone", "name": "Telephone Tools"},
            {"id": "menu_netutils", "name": "Network Utilities"},
            {"id": "menu_hash_crypto", "name": "Hash & Crypto"},
            {"id": "menu_system_audit", "name": "System Audit"},
            {"id": "menu_adv_network", "name": "Advanced Network"},
            {"id": "menu_adv_osint", "name": "Advanced OSINT"},
            {"id": "menu_wifi", "name": "WiFi & Wireless"},
            {"id": "menu_reports", "name": "Reports"},
            {"id": "osint_censys_search", "name": "Censys Search"},
            {"id": "osint_recon_engine", "name": "Recon Engine"}]


@app.route("/run/<module_id>")
def run_module(module_id):
    func = globals().get(module_id)
    if not func:
        return jsonify({"error": f"Module {module_id} not found"})

    def wrapper():
        old_out = sys.stdout
        buf = io.StringIO()
        sys.stdout = buf
        try:
            func()
        except Exception as e:
            print(f"Error: {e}")
        sys.stdout = old_out
        current_output.append(("info", f"[+] {module_id} completed"))

    t = threading.Thread(target=wrapper, daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/output")
def get_output():
    lines = []
    tags = []
    for tag, line in current_output[-500:]:
        lines.append(line)
        tags.append(tag)
    return jsonify({"lines": lines, "tags": tags})


@app.route("/clear")
def clear_output():
    global current_output
    current_output = []
    return jsonify({"status": "ok"})


def main(host="0.0.0.0", port=5000, debug=False):
    print("  Darkie Security Suite v3 — Web GUI")
    print(f"  Access at http://{host}:{port}")
    print("  Press Ctrl+C to stop")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Darkie Web GUI")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()
    main(host=args.host, port=args.port, debug=args.debug)
