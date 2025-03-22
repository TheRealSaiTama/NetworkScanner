#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import os
import sys
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx
from typing import List, Dict, Any, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import scan_network, scan_target
from src.utils import (
    validate_ip_range, validate_port_range, export_to_csv, export_to_json,
    save_session, load_session, get_common_ports, ensure_directory_exists,
    get_network_interfaces
)

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        self.ip_range_var = tk.StringVar(value="192.168.1.0/24")
        self.port_range_var = tk.StringVar(value="1-1024")
        self.threads_var = tk.IntVar(value=10)
        self.use_common_ports_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")
        self.filter_var = tk.StringVar()
        self.sort_var = tk.StringVar()
        
        self.scan_results = []
        self.scan_settings = {}
        self.scan_thread = None
        self.is_scanning = False
        
        self.create_menu()
        self.create_main_frame()
        
        ensure_directory_exists("results")
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Scan", command=self.reset_scan)
        file_menu.add_command(label="Load Session", command=self.load_session_dialog)
        file_menu.add_command(label="Save Session", command=self.save_session_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Export Results (CSV)", command=lambda: self.export_results("csv"))
        file_menu.add_command(label="Export Results (JSON)", command=lambda: self.export_results("json"))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Network Graph", command=self.show_network_graph)
        view_menu.add_command(label="Port Distribution", command=self.show_port_distribution)
        menubar.add_cascade(label="View", menu=view_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_main_frame(self):
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        settings_frame = ttk.LabelFrame(main_frame, text="Scan Settings", padding=10)
        settings_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(settings_frame, text="IP Range:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(settings_frame, textvariable=self.ip_range_var, width=30).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        interfaces = get_network_interfaces()
        if interfaces:
            ttk.Label(settings_frame, text="Interface:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
            interface_combo = ttk.Combobox(settings_frame, width=15)
            interface_combo['values'] = [f"{iface['name']} ({iface['ip']})" for iface in interfaces]
            interface_combo.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
            interface_combo.bind("<<ComboboxSelected>>", self.on_interface_selected)
        
        ttk.Label(settings_frame, text="Port Range:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(settings_frame, textvariable=self.port_range_var, width=30).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Checkbutton(settings_frame, text="Use Common Ports", variable=self.use_common_ports_var, command=self.toggle_common_ports).grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(settings_frame, text="Threads:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(settings_frame, from_=1, to=50, textvariable=self.threads_var, width=5).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        scan_button = ttk.Button(settings_frame, text="Start Scan", command=self.start_scan)
        scan_button.grid(row=2, column=2, padx=5, pady=5)
        
        stop_button = ttk.Button(settings_frame, text="Stop Scan", command=self.stop_scan)
        stop_button.grid(row=2, column=3, padx=5, pady=5)
        
        filter_frame = ttk.Frame(main_frame, padding=5)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(filter_frame, textvariable=self.filter_var, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Sort by:").pack(side=tk.LEFT, padx=5)
        sort_combo = ttk.Combobox(filter_frame, textvariable=self.sort_var, width=10)
        sort_combo['values'] = ["ip", "mac", "ports"]
        sort_combo.pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply Sort", command=self.apply_sort).pack(side=tk.LEFT, padx=5)
        
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_tree = ttk.Treeview(results_frame, columns=("ip", "mac", "status", "hostname", "ports"), show="headings")
        self.results_tree.heading("ip", text="IP Address")
        self.results_tree.heading("mac", text="MAC Address")
        self.results_tree.heading("status", text="Status")
        self.results_tree.heading("hostname", text="Hostname")
        self.results_tree.heading("ports", text="Open Ports")
        
        self.results_tree.column("ip", width=120)
        self.results_tree.column("mac", width=150)
        self.results_tree.column("status", width=80)
        self.results_tree.column("hostname", width=150)
        self.results_tree.column("ports", width=300)
        
        y_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=y_scrollbar.set)
        
        x_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(xscrollcommand=x_scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.results_tree.bind("<Double-1>", self.show_host_details)
        
        status_bar = ttk.Frame(main_frame)
        status_bar.pack(fill=tk.X, pady=5)
        
        self.progress_bar = ttk.Progressbar(status_bar, mode="indeterminate", length=200)
        self.progress_bar.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(status_bar, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
    
    def on_interface_selected(self, event):
        selected = event.widget.get()
        if "(" in selected and ")" in selected:
            ip = selected.split("(")[1].split(")")[0]
            if ip.count(".") == 3:
                network = ".".join(ip.split(".")[:3]) + ".0/24"
                self.ip_range_var.set(network)
    
    def toggle_common_ports(self):
        if self.use_common_ports_var.get():
            self.port_range_var.set("Common ports")
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Scan Settings":
                            for grandchild in child.winfo_children():
                                if isinstance(grandchild, ttk.Entry) and grandchild.grid_info()["row"] == 1:
                                    grandchild.configure(state="disabled")
        else:
            self.port_range_var.set("1-1024")
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Scan Settings":
                            for grandchild in child.winfo_children():
                                if isinstance(grandchild, ttk.Entry) and grandchild.grid_info()["row"] == 1:
                                    grandchild.configure(state="normal")
    
    def start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already in progress.")
            return
        
        ip_range = self.ip_range_var.get()
        if not validate_ip_range(ip_range):
            messagebox.showerror("Invalid Input", f"Invalid IP range: {ip_range}")
            return
        
        if self.use_common_ports_var.get():
            common_ports = get_common_ports()
            all_ports = []
            for category, ports in common_ports.items():
                all_ports.extend(ports)
            port_ranges = ",".join(map(str, sorted(set(all_ports))))
        else:
            port_ranges = self.port_range_var.get()
            if not validate_port_range(port_ranges):
                messagebox.showerror("Invalid Input", f"Invalid port range: {port_ranges}")
                return
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.status_var.set("Scanning...")
        self.progress_bar.start()
        
        self.is_scanning = True
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(ip_range, port_ranges, self.threads_var.get())
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def run_scan(self, ip_range, port_ranges, threads):
        try:
            self.root.after(0, lambda: self.status_var.set(f"Starting scan of {ip_range}..."))

            start_time = time.time()

            self.root.after(1000, lambda: self.status_var.set(f"Discovering hosts in {ip_range}..."))

            self.scan_results = scan_network(ip_range, port_ranges, threads)

            self.scan_settings = {
                'ip_range': ip_range,
                'ports': port_ranges,
                'threads': threads
            }

            scan_time = time.time() - start_time

            self.root.after(0, self.update_results, scan_time)
        except Exception as e:
            self.root.after(0, self.show_error, str(e))
    
    def update_results(self, scan_time):
        self.progress_bar.stop()
        
        self.status_var.set(f"Scan completed in {scan_time:.2f} seconds. Found {len(self.scan_results)} hosts.")
        
        for result in self.scan_results:
            ip = result["ip"]
            mac = result.get("mac", "N/A")
            status = result["status"]
            hostname = result.get("hostname", "N/A") or "N/A"
            open_ports = ", ".join(map(str, result.get("open_ports", []))) or "None"
            
            self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, open_ports))
        
        self.is_scanning = False
    
    def show_error(self, error_message):
        self.progress_bar.stop()
        self.status_var.set("Error")
        self.is_scanning = False
        messagebox.showerror("Scan Error", f"An error occurred during the scan:\n{error_message}")
    
    def stop_scan(self):
        if not self.is_scanning:
            return
        
        self.status_var.set("Stopping scan...")
        messagebox.showinfo("Stopping Scan", "The scan will stop after the current operations complete.")
    
    def reset_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "Cannot reset while a scan is in progress.")
            return
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.ip_range_var.set("192.168.1.0/24")
        self.port_range_var.set("1-1024")
        self.threads_var.set(10)
        self.use_common_ports_var.set(False)
        self.status_var.set("Ready")
        self.filter_var.set("")
        self.sort_var.set("")
        
        self.scan_results = []
        self.scan_settings = {}
    
    def apply_filter(self):
        filter_text = self.filter_var.get()
        if not filter_text:
            return
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        filtered_results = self.scan_results.copy()
        
        if "port=" in filter_text:
            port_to_filter = int(filter_text.split("=")[1])
            filtered_results = [r for r in filtered_results if port_to_filter in r.get('open_ports', [])]
        
        elif "status=" in filter_text:
            status_to_filter = filter_text.split("=")[1]
            filtered_results = [r for r in filtered_results if r['status'] == status_to_filter]
        
        elif "mac=" in filter_text:
            mac_to_filter = filter_text.split("=")[1].lower()
            filtered_results = [r for r in filtered_results if r.get('mac', '').lower() == mac_to_filter]
        
        elif "ip=" in filter_text:
            ip_to_filter = filter_text.split("=")[1]
            filtered_results = [r for r in filtered_results if r['ip'] == ip_to_filter]
        
        for result in filtered_results:
            ip = result["ip"]
            mac = result.get("mac", "N/A")
            status = result["status"]
            hostname = result.get("hostname", "N/A") or "N/A"
            open_ports = ", ".join(map(str, result.get("open_ports", []))) or "None"
            
            self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, open_ports))
        
        self.status_var.set(f"Filtered results: {len(filtered_results)} hosts")
    
    def apply_sort(self):
        sort_by = self.sort_var.get()
        if not sort_by:
            return
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        sorted_results = self.scan_results.copy()
        
        if sort_by == "ip":
            sorted_results = sorted(sorted_results, key=lambda x: [int(part) for part in x['ip'].split('.')])
        elif sort_by == "mac":
            sorted_results = sorted(sorted_results, key=lambda x: x.get('mac', ''))
        elif sort_by == "ports":
            sorted_results = sorted(sorted_results, key=lambda x: len(x.get('open_ports', [])), reverse=True)
        
        for result in sorted_results:
            ip = result["ip"]
            mac = result.get("mac", "N/A")
            status = result["status"]
            hostname = result.get("hostname", "N/A") or "N/A"
            open_ports = ", ".join(map(str, result.get("open_ports", []))) or "None"
            
            self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, open_ports))
        
        self.status_var.set(f"Sorted results by {sort_by}")
    
    def show_host_details(self, event):
        item = self.results_tree.selection()[0]
        values = self.results_tree.item(item, "values")
        
        if not values:
            return
        
        ip = values[0]
        
        host = None
        for result in self.scan_results:
            if result["ip"] == ip:
                host = result
                break
        
        if not host:
            return
        
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Host Details: {ip}")
        details_window.geometry("500x400")
        details_window.minsize(400, 300)
        
        details_frame = ttk.Frame(details_window, padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        info_frame = ttk.LabelFrame(details_frame, text="Host Information", padding=10)
        info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(info_frame, text=f"IP Address: {host['ip']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"MAC Address: {host.get('mac', 'N/A')}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Status: {host['status']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Hostname: {host.get('hostname', 'N/A') or 'N/A'}").pack(anchor=tk.W)
        
        ports_frame = ttk.LabelFrame(details_frame, text="Open Ports", padding=10)
        ports_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ports_tree = ttk.Treeview(ports_frame, columns=("port", "service"), show="headings")
        ports_tree.heading("port", text="Port")
        ports_tree.heading("service", text="Service")
        
        ports_tree.column("port", width=100)
        ports_tree.column("service", width=200)
        
        scrollbar = ttk.Scrollbar(ports_frame, orient=tk.VERTICAL, command=ports_tree.yview)
        ports_tree.configure(yscrollcommand=scrollbar.set)
        
        ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        for port in host.get("open_ports", []):
            service = host.get("services", {}).get(port, "unknown")
            ports_tree.insert("", tk.END, values=(port, service))
        
        ttk.Button(details_frame, text="Close", command=details_window.destroy).pack(pady=10)
    
    def show_network_graph(self):
        if not self.scan_results:
            messagebox.showinfo("No Data", "No scan results to visualize.")
            return
        
        graph_window = tk.Toplevel(self.root)
        graph_window.title("Network Graph")
        graph_window.geometry("800x600")
        
        graph_frame = ttk.Frame(graph_window, padding=10)
        graph_frame.pack(fill=tk.BOTH, expand=True)
        
        fig = plt.Figure(figsize=(10, 8), dpi=100)
        ax = fig.add_subplot(111)
        
        G = nx.Graph()
        
        router_ip = ".".join(self.scan_results[0]["ip"].split(".")[:3]) + ".1"
        G.add_node(router_ip, type="router")
        
        for result in self.scan_results:
            if result["status"] in ["up", "up (ICMP)"]:
                G.add_node(result["ip"], type="host")
                G.add_edge(router_ip, result["ip"])
                
                for port in result.get("open_ports", []):
                    port_node = f"{result['ip']}:{port}"
                    G.add_node(port_node, type="port")
                    G.add_edge(result["ip"], port_node)
        
        pos = nx.spring_layout(G, seed=42)
        
        router_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "router"]
        host_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "host"]
        port_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "port"]
        
        nx.draw_networkx_nodes(G, pos, nodelist=router_nodes, node_color="red", node_size=500, ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=host_nodes, node_color="skyblue", node_size=300, ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=port_nodes, node_color="green", node_size=100, ax=ax)
        
        nx.draw_networkx_edges(G, pos, ax=ax)
        
        router_labels = {n: n for n in router_nodes}
        host_labels = {n: n for n in host_nodes}
        port_labels = {n: n.split(":")[-1] for n in port_nodes}
        
        nx.draw_networkx_labels(G, pos, labels=router_labels, font_size=10, ax=ax)
        nx.draw_networkx_labels(G, pos, labels=host_labels, font_size=8, ax=ax)
        nx.draw_networkx_labels(G, pos, labels=port_labels, font_size=6, ax=ax)
        
        ax.plot([], [], "ro", label="Router")
        ax.plot([], [], "o", color="skyblue", label="Host")
        ax.plot([], [], "go", label="Open Port")
        ax.legend()
        
        ax.set_axis_off()
        
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(graph_frame, text="Close", command=graph_window.destroy).pack(pady=10)
    
    def show_port_distribution(self):
        if not self.scan_results:
            messagebox.showinfo("No Data", "No scan results to visualize.")
            return
        
        all_ports = []
        for result in self.scan_results:
            all_ports.extend(result.get("open_ports", []))
        
        if not all_ports:
            messagebox.showinfo("No Data", "No open ports found in scan results.")
            return
        
        port_counts = {}
        for port in all_ports:
            port_counts[port] = port_counts.get(port, 0) + 1
        
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
        
        graph_window = tk.Toplevel(self.root)
        graph_window.title("Port Distribution")
        graph_window.geometry("800x600")
        
        graph_frame = ttk.Frame(graph_window, padding=10)
        graph_frame.pack(fill=tk.BOTH, expand=True)
        
        fig = plt.Figure(figsize=(10, 8), dpi=100)
        ax = fig.add_subplot(111)
        
        ports = [p[0] for p in sorted_ports[:15]]
        counts = [p[1] for p in sorted_ports[:15]]
        
        bars = ax.bar(ports, counts, color="skyblue")
        
        ax.set_xlabel("Port Number")
        ax.set_ylabel("Number of Hosts")
        ax.set_title("Top Open Ports Distribution")
        
        for bar, port in zip(bars, ports):
            service = "unknown"
            try:
                import socket
                service = socket.getservbyport(port)
            except (socket.error, OSError):
                pass
            
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    service, ha="center", va="bottom", rotation=45)
        
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(graph_frame, text="Close", command=graph_window.destroy).pack(pady=10)
    
    def load_session_dialog(self):
        filename = filedialog.askopenfilename(
            title="Load Session",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            self.scan_results, self.scan_settings = load_session(filename)
            
            self.ip_range_var.set(self.scan_settings.get("ip_range", "192.168.1.0/24"))
            self.port_range_var.set(self.scan_settings.get("ports", "1-1024"))
            self.threads_var.set(self.scan_settings.get("threads", 10))
            
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            
            for result in self.scan_results:
                ip = result["ip"]
                mac = result.get("mac", "N/A")
                status = result["status"]
                hostname = result.get("hostname", "N/A") or "N/A"
                open_ports = ", ".join(map(str, result.get("open_ports", []))) or "None"
                
                self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, open_ports))
            
            self.status_var.set(f"Loaded session from {filename}")
            messagebox.showinfo("Session Loaded", f"Successfully loaded session from {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load session: {e}")
    
    def save_session_dialog(self):
        if not self.scan_results:
            messagebox.showinfo("No Data", "No scan results to save.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Session",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            save_session(self.scan_results, self.scan_settings, filename)
            self.status_var.set(f"Saved session to {filename}")
            messagebox.showinfo("Session Saved", f"Successfully saved session to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save session: {e}")
    
    def export_results(self, format_type):
        if not self.scan_results:
            messagebox.showinfo("No Data", "No scan results to export.")
            return
        
        ensure_directory_exists("results")
        
        if format_type == "csv":
            filename = filedialog.asksaveasfilename(
                title="Export Results as CSV",
                defaultextension=".csv",
                filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
                initialdir="results"
            )
            
            if not filename:
                return
            
            try:
                export_to_csv(self.scan_results, filename)
                self.status_var.set(f"Exported results to {filename}")
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
        
        elif format_type == "json":
            filename = filedialog.asksaveasfilename(
                title="Export Results as JSON",
                defaultextension=".json",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
                initialdir="results"
            )
            
            if not filename:
                return
            
            try:
                export_to_json(self.scan_results, filename)
                self.status_var.set(f"Exported results to {filename}")
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
    
    def show_about(self):
        about_text = """
        Network Scanner

        A comprehensive network scanner application capable of discovering devices,
        identifying their MAC addresses, and detecting open ports within a specified IP range.

        Features:
        - ARP/ICMP scanning for host discovery
        - TCP port scanning
        - Network visualization
        - Export results to CSV/JSON
        - Save/load scanning sessions

        Created with Python and Scapy
        """
        
        messagebox.showinfo("About Network Scanner", about_text)

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
