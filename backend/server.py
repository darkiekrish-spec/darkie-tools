#!/usr/bin/env python3
"""
Darkie Tools — local playground backend.
Serves the static website AND lets the playground run the real tool
non-interactively by calling `v4/tool.sh --run <tool> <args...>`.

Usage:
    python3 server.py [port]          # default 8000
    PORT=9000 python3 server.py
"""
import argparse
import html
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))          # website/
REPO = os.path.dirname(ROOT)                               # repo root
TOOL_SH = os.path.join(REPO, "v4", "tool.sh")
TOOL_PY = os.path.join(REPO, "v4", "tool.py")
PY = sys.executable

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mp4": "video/mp4",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".ico": "image/x-icon",
}

# tools the playground is allowed to call, in the format
# { "name": "osint_ipgeo", "args": ["8.8.8.8"], "desc": "IP geolocation" }
PLAYGROUND_TOOLS = [
    {"name": "osint_ipgeo", "args": ["8.8.8.8"], "desc": "IP geolocation (ipwho.is)"},
    {"name": "osint_dns", "args": ["example.com"], "desc": "DNS enumeration"},
    {"name": "osint_subdomain", "args": ["example.com"], "desc": "Subdomain discovery"},
    {"name": "osint_email", "args": ["test@example.com"], "desc": "Email OSINT + pwned check"},
    {"name": "vuln_cve_lookup", "args": ["CVE-2024-3094"], "desc": "CVE lookup (CIRCL)"},
    {"name": "legacy_sslcheck", "args": ["example.com", "443"], "desc": "SSL/TLS certificate check"},
    {"name": "legacy_httpheaders", "args": ["example.com"], "desc": "HTTP security headers"},
    {"name": "legacy_portscan", "args": ["127.0.0.1", "1"], "desc": "Port scan (local)"},
    {"name": "legacy_ping", "args": ["127.0.0.1", "3"], "desc": "ICMP ping"},
    {"name": "legacy_traceroute", "args": ["127.0.0.1", "1"], "desc": "Traceroute"},
    {"name": "hash_generator", "args": ["darkie-tools"], "desc": "Hash generator (MD5/SHA)"},
    {"name": "tel_analyze", "args": ["+919876543210"], "desc": "Phone number analysis"},
    {"name": "password_generator", "args": ["20"], "desc": "Strong password generator"},
]


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


# CORS: allow the static site on Vercel to call the backend on Render.
# Override with env var, e.g. CORS_ORIGIN=https://darkie-tools.vercel.app
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")


def run_tool(tool, args):
    """Run the real tool via v4/tool.sh --run. Returns (exit_code, text_output)."""
    cmd = [TOOL_SH, "--run", tool] + args
    env = dict(os.environ)
    env["DARKIE_SKIP_DEPS"] = "1"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45,
                           cwd=REPO, errors="replace", env=env)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return 124, "error: tool timed out after 45s"
    except FileNotFoundError:
        return 127, "error: could not locate v4/tool.sh"
    except Exception as e:
        return 1, f"error: {e}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code, obj):
        self._send(code, json.dumps(obj).encode("utf-8"), MIME[".json"])

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            path = "/index.html"
        if path == "/api/tools":
            self._send_json(200, PLAYGROUND_TOOLS)
            return
        if path == "/api/version":
            self._send_json(200, {"version": "v4.0", "ok": True})
            return
        # static files only inside the website dir (no traversal)
        rel = path.lstrip("/")
        target = os.path.normpath(os.path.join(ROOT, rel))
        if not target.startswith(ROOT) or not os.path.isfile(target):
            self._send(404, b"not found", MIME[".html"])
            return
        ext = os.path.splitext(target)[1].lower()
        with open(target, "rb") as f:
            self._send(200, f.read(), MIME.get(ext, "application/octet-stream"))

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/run":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._send_json(400, {"error": "bad request"})
            return
        name = str(data.get("tool", ""))
        args = [str(a) for a in data.get("args", [])][:8]
        # restrict to the whitelist
        tool = next((t for t in PLAYGROUND_TOOLS if t["name"] == name), None)
        if not tool:
            self._send_json(400, {"error": f"unknown tool: {name}"})
            return
        code, out = run_tool(name, args)
        self._send_json(200, {"exit": code, "output": out})


def main():
    parser = argparse.ArgumentParser(description="Darkie Tools local website + playground server")
    parser.add_argument("port", nargs="?", type=int, default=int(os.environ.get("PORT", 8000)))
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    args = parser.parse_args()
    # On Render we must bind 0.0.0.0; locally keep 127.0.0.1.
    host = "0.0.0.0" if os.environ.get("RENDER") else args.host
    httpd = ThreadingHTTPServer((host, args.port), Handler)
    print(f"  Darkie Tools website + live playground on http://{host}:{args.port}")
    print(f"  Playground runs the real tool via v4/tool.sh (allowlisted tools only).")
    print(f"  Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
