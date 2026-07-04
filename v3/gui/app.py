#!/usr/bin/env python3
"""Darkie Security Suite v3 — Cross-Platform Desktop GUI (tkinter)"""

import io
import os
import sys
import re
import threading
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tool import *

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext
except ImportError:
    print("tkinter not found. Install: apt install python3-tk / brew install python-tk")
    sys.exit(1)

BG = "#1a1a2e"
BG2 = "#16213e"
FG = "#e94560"
ACCENT = "#533483"
TEXT = "#eee"
DIM = "#888"
GREEN = "#00ff88"
RED = "#ff4444"
YELLOW = "#ffaa00"
CYAN = "#00ccff"

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def strip_ansi(text):
    return ANSI_RE.sub('', text)


def run_in_thread(target, args=(), kwargs=None, callback=None):
    kwargs = kwargs or {}
    t = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True)
    t.start()
    return t


class OutputRedirect(io.StringIO):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def write(self, s):
        if s.strip():
            self.queue.put(strip_ansi(s))
        super().write(s)

    def flush(self):
        pass


class DarkieGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Darkie Security Suite v3")
        self.root.geometry("1100x780")
        self.root.configure(bg=BG)
        self.root.minsize(900, 650)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG2, foreground=TEXT, padding=[10, 5], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", FG)])
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TButton", background=ACCENT, foreground=TEXT, font=("Segoe UI", 10, "bold"), padding=[8, 4])
        style.map("TButton", background=[("active", FG)])
        style.configure("TEntry", fieldcolor=BG2, foreground=TEXT, insertcolor=TEXT, font=("Consolas", 11))
        style.configure("TLabelframe", background=BG, foreground=TEXT)
        style.configure("TLabelframe.Label", background=BG, foreground=CYAN, font=("Segoe UI", 10, "bold"))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tabs = {}
        self.out_queues = {}
        self.stop_events = {}

        modules = [
            ("Network Threat", self._build_network_threat),
            ("Endpoint", self._build_endpoint),
            ("Vulnerability", self._build_vuln),
            ("Data Protection", self._build_data),
            ("Pentest", self._build_pentest),
            ("SIEM", self._build_siem),
            ("Stress Test", self._build_stress),
            ("OSINT", self._build_osint),
            ("Telephone", self._build_telephone),
            ("Net Utils", self._build_netutils),
            ("Hash & Crypto", self._build_hash_crypto),
            ("Security Audit", self._build_audit),
            ("Adv Network", self._build_adv_network),
            ("Adv OSINT", self._build_adv_osint),
            ("WiFi", self._build_wifi),
            ("Reports", self._build_reports),
            ("Console", self._build_console),
        ]
        for name, builder in modules:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=f" {name} ")
            self.tabs[name] = frame
            self.out_queues[name] = Queue()
            self.stop_events[name] = threading.Event()
            builder(frame)

        self._poll_queues()

    def _output_widget(self, parent):
        txt = scrolledtext.ScrolledText(parent, wrap=tk.WORD, height=12,
                                         bg=BG2, fg=TEXT, insertbackground=TEXT,
                                         font=("Consolas", 10), state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        return txt

    def _add_output(self, parent, label="Output"):
        frame = ttk.LabelFrame(parent, text=f" {label} ")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        return self._output_widget(frame)

    def _add_button_row(self, parent, buttons, row_frame=None):
        if row_frame is None:
            row_frame = ttk.Frame(parent)
        row_frame.pack(fill=tk.X, padx=5, pady=3)
        for text, cmd in buttons:
            b = ttk.Button(row_frame, text=text, command=cmd)
            b.pack(side=tk.LEFT, padx=3)

    def _poll_queues(self):
        for name, q in self.out_queues.items():
            try:
                while True:
                    line = q.get_nowait()
                    tab = self.tabs.get(name)
                    if tab:
                        for child in tab.winfo_children():
                            if isinstance(child, ttk.LabelFrame):
                                for sub in child.winfo_children():
                                    if isinstance(sub, scrolledtext.ScrolledText):
                                        sub.configure(state=tk.NORMAL)
                                        sub.insert(tk.END, line + "\n")
                                        sub.see(tk.END)
                                        sub.configure(state=tk.DISABLED)
            except:
                pass
        self.root.after(100, self._poll_queues)

    def _run_module(self, name, func):
        self.out_queues[name] = Queue()
        old_stdout = sys.stdout
        sys.stdout = OutputRedirect(self.out_queues[name])

        def wrapper():
            try:
                func()
            except Exception as e:
                print(f"Error: {e}")
            finally:
                sys.stdout = old_stdout

        run_in_thread(wrapper)

    def _make_entry(self, parent, label, default="", row=0, col=0, label_col=0):
        f = ttk.Frame(parent)
        f.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(f, text=label, width=20).pack(side=tk.LEFT)
        var = tk.StringVar(value=default)
        e = ttk.Entry(f, textvariable=var)
        e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        return var

    # ── Module: Network Threat ──
    def _build_network_threat(self, parent):
        self._add_button_row(parent, [
            ("Capture", lambda: self._run_module("Network Threat", net_capture)),
            ("Traffic Monitor", lambda: self._run_module("Network Threat", net_traffic_monitor)),
            ("IDS", lambda: self._run_module("Network Threat", net_ids)),
            ("ARP Detect", lambda: self._run_module("Network Threat", net_arp_detect)),
            ("Port Scan Detect", lambda: self._run_module("Network Threat", net_portscan_detect)),
            ("DDoS Detect", lambda: self._run_module("Network Threat", net_ddos_detect)),
        ])
        self._add_output(parent)

    # ── Module: Endpoint ──
    def _build_endpoint(self, parent):
        self._add_button_row(parent, [
            ("Process Monitor", lambda: self._run_module("Endpoint", ep_process_monitor)),
            ("Suspicious Procs", lambda: self._run_module("Endpoint", ep_suspicious_processes)),
            ("File Integrity", lambda: self._run_module("Endpoint", ep_file_integrity)),
            ("Net Connections", lambda: self._run_module("Endpoint", ep_network_connections)),
        ])
        self._add_output(parent)

    # ── Module: Vulnerability ──
    def _build_vuln(self, parent):
        self._add_button_row(parent, [
            ("Advanced Scan", lambda: self._run_module("Vulnerability", vuln_advanced_scan)),
            ("CVE Lookup", lambda: self._run_module("Vulnerability", vuln_cve_lookup)),
            ("Assessment", lambda: self._run_module("Vulnerability", vuln_assessment)),
            ("Config Check", lambda: self._run_module("Vulnerability", vuln_config_check)),
        ])
        self._add_output(parent)

    # ── Module: Data Protection ──
    def _build_data(self, parent):
        self._add_button_row(parent, [
            ("Encrypt", lambda: self._run_module("Data Protection", data_encrypt)),
            ("Decrypt", lambda: self._run_module("Data Protection", data_decrypt)),
            ("Hash File", lambda: self._run_module("Data Protection", data_hash_file)),
            ("Secure Delete", lambda: self._run_module("Data Protection", data_secure_delete)),
        ])
        self._add_output(parent)

    # ── Module: Pentest ──
    def _build_pentest(self, parent):
        self._add_button_row(parent, [
            ("Port Scan", lambda: self._run_module("Pentest", pentest_port_scan)),
            ("Service Enum", lambda: self._run_module("Pentest", pentest_service_enum)),
            ("Brute Force", lambda: self._run_module("Pentest", pentest_brute_force)),
            ("SQL Injection", lambda: self._run_module("Pentest", pentest_sqli)),
            ("XSS", lambda: self._run_module("Pentest", pentest_xss)),
        ])
        self._add_output(parent)

    # ── Module: SIEM ──
    def _build_siem(self, parent):
        self._add_button_row(parent, [
            ("Log Collector", lambda: self._run_module("SIEM", siem_log_collector)),
            ("Analyze", lambda: self._run_module("SIEM", siem_analyze)),
            ("Correlate", lambda: self._run_module("SIEM", siem_correlate)),
            ("Dashboard", lambda: self._run_module("SIEM", siem_dashboard)),
        ])
        self._add_output(parent)

    # ── Module: Stress Test ──
    def _build_stress(self, parent):
        self._add_button_row(parent, [
            ("Menu", lambda: self._run_module("Stress Test", menu_stress)),
            ("TCP Flood", lambda: self._run_module("Stress Test", mc_tcp_flood_worker)),
            ("UDP Flood", lambda: self._run_module("Stress Test", mc_udp_flood_worker)),
            ("Find Ports", lambda: self._run_module("Stress Test", mc_find_ports)),
            ("Bot Attack", lambda: self._run_module("Stress Test", _mc_bot_worker)),
        ])
        self._add_output(parent)

    # ── Module: OSINT ──
    def _build_osint(self, parent):
        self._add_button_row(parent, [
            ("Menu", lambda: self._run_module("OSINT", menu_osint)),
            ("Shodan", lambda: self._run_module("OSINT", osint_shodan)),
            ("Censys", lambda: self._run_module("OSINT", osint_censys)),
            ("CT Log", lambda: self._run_module("OSINT", osint_ct_log)),
            ("DNS History", lambda: self._run_module("OSINT", osint_dns_history)),
            ("Wayback", lambda: self._run_module("OSINT", osint_wayback)),
        ])
        self._add_output(parent)

    # ── Module: Telephone ──
    def _build_telephone(self, parent):
        self._add_button_row(parent, [
            ("Menu", lambda: self._run_module("Telephone", menu_telephone)),
        ])
        self._add_output(parent)

    # ── Module: Net Utils ──
    def _build_netutils(self, parent):
        self._add_button_row(parent, [
            ("Menu", lambda: self._run_module("Net Utils", menu_netutils)),
            ("Ping", lambda: self._run_module("Net Utils", net_ping)),
            ("Traceroute", lambda: self._run_module("Net Utils", net_traceroute)),
            ("DNS Lookup", lambda: self._run_module("Net Utils", net_dns_lookup)),
            ("Whois", lambda: self._run_module("Net Utils", net_whois)),
        ])
        self._add_output(parent)

    # ── Module: Hash & Crypto ──
    def _build_hash_crypto(self, parent):
        self._add_button_row(parent, [
            ("Menu", lambda: self._run_module("Hash & Crypto", menu_hash_crypto)),
        ])
        self._add_output(parent)

    # ── Module: Security Audit ──
    def _build_audit(self, parent):
        self._add_button_row(parent, [
            ("Menu", lambda: self._run_module("Security Audit", menu_system_audit)),
        ])
        self._add_output(parent)

    # ── Module: Adv Network ──
    def _build_adv_network(self, parent):
        self._add_button_row(parent, [
            ("Menu", lambda: self._run_module("Adv Network", menu_adv_network)),
        ])
        self._add_output(parent)

    # ── Module: Adv OSINT ──
    def _build_adv_osint(self, parent):
        self._add_button_row(parent, [
            ("Recon Engine", lambda: self._run_module("Adv OSINT", osint_recon_engine)),
            ("Censys Search", lambda: self._run_module("Adv OSINT", osint_censys_search)),
        ])
        self._add_output(parent)

    # ── Module: WiFi ──
    def _build_wifi(self, parent):
        self._add_button_row(parent, [
            ("Menu", lambda: self._run_module("WiFi", menu_wifi)),
        ])
        self._add_output(parent)

    # ── Module: Reports ──
    def _build_reports(self, parent):
        self._add_button_row(parent, [
            ("Generate", lambda: self._run_module("Reports", menu_reports)),
        ])
        self._add_output(parent)

    # ── Module: Console (terminal simulation) ──
    def _build_console(self, parent):
        console_frame = ttk.Frame(parent)
        console_frame.pack(fill=tk.BOTH, expand=True)
        self.console_text = self._output_widget(console_frame)
        self.console_text.configure(state=tk.DISABLED)
        entry_frame = ttk.Frame(console_frame)
        entry_frame.pack(fill=tk.X, padx=5, pady=3)
        self.console_var = tk.StringVar()
        entry = ttk.Entry(entry_frame, textvariable=self.console_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry.bind("<Return>", self._console_exec)
        ttk.Button(entry_frame, text="Run", command=self._console_exec).pack(side=tk.RIGHT, padx=5)
        self.console_queue = self.out_queues["Console"]

    def _console_exec(self, event=None):
        cmd = self.console_var.get().strip()
        if not cmd:
            return
        self.console_var.set("")
        self.console_text.configure(state=tk.NORMAL)
        self.console_text.insert(tk.END, f"> {cmd}\n")
        self.console_text.configure(state=tk.DISABLED)

        def run_cmd():
            try:
                exec(cmd, globals())
            except Exception as e:
                self.console_text.configure(state=tk.NORMAL)
                self.console_text.insert(tk.END, f"Error: {e}\n")
                self.console_text.see(tk.END)
                self.console_text.configure(state=tk.DISABLED)

        run_in_thread(run_cmd)


def main():
    root = tk.Tk()
    DarkieGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
