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
        
        self.createmenu()
        self.createmainframe()
        
        ensure_directory_exists("results")
    
    def createmenu(self):
        menubar = tk.Menu(self.root)
        
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="New Scan", command=self.resetscan)
        filemenu.add_command(label="Load Session", command=self.loadsessiondialog)
        filemenu.add_command(label="Save Session", command=self.savesessiondialog)
        filemenu.add_separator()
        filemenu.add_command(label="Export Results (CSV)", command=lambda: self.exportresults("csv"))
        filemenu.add_command(label="Export Results (JSON)", command=lambda: self.exportresults("json"))
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        
        viewmenu = tk.Menu(menubar, tearoff=0)
        viewmenu.add_command(label="Network Graph", command=self.shownetgraph)
        viewmenu.add_command(label="Port Distribution", command=self.showportdist)
        menubar.add_cascade(label="View", menu=viewmenu)
        
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.showabout)
        menubar.add_cascade(label="Help", menu=helpmenu)
        
        self.root.config(menu=menubar)
    
    def createmainframe(self):
        mainframe = ttk.Frame(self.root, padding=10)
        mainframe.pack(fill=tk.BOTH, expand=True)
        
        settingsframe = ttk.LabelFrame(mainframe, text="Scan Settings", padding=10)
        settingsframe.pack(fill=tk.X, pady=5)
        
        ttk.Label(settingsframe, text="IP Range:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(settingsframe, textvariable=self.ip_range_var, width=30).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ifaces = get_network_interfaces()
        if ifaces:
            ttk.Label(settingsframe, text="Interface:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
            ifacecombo = ttk.Combobox(settingsframe, width=15)
            ifacecombo['values'] = [f"{iface['name']} ({iface['ip']})" for iface in ifaces]
            ifacecombo.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
            ifacecombo.bind("<<ComboboxSelected>>", self.onifaceselected)
        
        ttk.Label(settingsframe, text="Port Range:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(settingsframe, textvariable=self.port_range_var, width=30).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Checkbutton(settingsframe, text="Use Common Ports", variable=self.use_common_ports_var, command=self.togglecommonports).grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(settingsframe, text="Threads:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Spinbox(settingsframe, from_=1, to=50, textvariable=self.threads_var, width=5).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        scanbtn = ttk.Button(settingsframe, text="Start Scan", command=self.startscan)
        scanbtn.grid(row=2, column=2, padx=5, pady=5)
        
        stopbtn = ttk.Button(settingsframe, text="Stop Scan", command=self.stopscan)
        stopbtn.grid(row=2, column=3, padx=5, pady=5)
        
        filterframe = ttk.Frame(mainframe, padding=5)
        filterframe.pack(fill=tk.X, pady=5)
        
        ttk.Label(filterframe, text="Filter:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(filterframe, textvariable=self.filter_var, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(filterframe, text="Apply Filter", command=self.applyfilter).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filterframe, text="Sort by:").pack(side=tk.LEFT, padx=5)
        sortcombo = ttk.Combobox(filterframe, textvariable=self.sort_var, width=10)
        sortcombo['values'] = ["ip", "mac", "ports"]
        sortcombo.pack(side=tk.LEFT, padx=5)
        ttk.Button(filterframe, text="Apply Sort", command=self.applysort).pack(side=tk.LEFT, padx=5)
        
        resultsframe = ttk.LabelFrame(mainframe, text="Scan Results", padding=10)
        resultsframe.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_tree = ttk.Treeview(resultsframe, columns=("ip", "mac", "status", "hostname", "ports"), show="headings")
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
        
        yscrollbar = ttk.Scrollbar(resultsframe, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=yscrollbar.set)
        
        xscrollbar = ttk.Scrollbar(resultsframe, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(xscrollcommand=xscrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        xscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.results_tree.bind("<Double-1>", self.showhostdetails)
        
        statusbar = ttk.Frame(mainframe)
        statusbar.pack(fill=tk.X, pady=5)
        
        self.progress_bar = ttk.Progressbar(statusbar, mode="indeterminate", length=200)
        self.progress_bar.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(statusbar, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
    
    def onifaceselected(self, event):
        selected = event.widget.get()
        if "(" in selected and ")" in selected:
            ip = selected.split("(")[1].split(")")[0]
            if ip.count(".") == 3:
                network = ".".join(ip.split(".")[:3]) + ".0/24"
                self.ip_range_var.set(network)
    
    def togglecommonports(self):
        if self.use_common_ports_var.get():
            self.port_range_var.set("Common ports")
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Scan Settings":
                            for gchild in child.winfo_children():
                                if isinstance(gchild, ttk.Entry) and gchild.grid_info()["row"] == 1:
                                    gchild.configure(state="disabled")
        else:
            self.port_range_var.set("1-1024")
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Scan Settings":
                            for gchild in child.winfo_children():
                                if isinstance(gchild, ttk.Entry) and gchild.grid_info()["row"] == 1:
                                    gchild.configure(state="normal")
    
    def startscan(self):
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already in progress.")
            return
        
        iprange = self.ip_range_var.get()
        if not validate_ip_range(iprange):
            messagebox.showerror("Invalid Input", f"Invalid IP range: {iprange}")
            return
        
        if self.use_common_ports_var.get():
            commonports = get_common_ports()
            allports = []
            for category, ports in commonports.items():
                allports.extend(ports)
            portranges = ",".join(map(str, sorted(set(allports))))
        else:
            portranges = self.port_range_var.get()
            if not validate_port_range(portranges):
                messagebox.showerror("Invalid Input", f"Invalid port range: {portranges}")
                return
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.status_var.set("Scanning...")
        self.progress_bar.start()
        
        self.is_scanning = True
        self.scan_thread = threading.Thread(
            target=self.runscan,
            args=(iprange, portranges, self.threads_var.get())
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def runscan(self, iprange, portranges, threads):
        try:
            self.root.after(0, lambda: self.status_var.set(f"Starting scan of {iprange}..."))

            starttime = time.time()

            self.root.after(1000, lambda: self.status_var.set(f"Discovering hosts in {iprange}..."))

            self.scan_results = scan_network(iprange, portranges, threads)

            self.scan_settings = {
                'ip_range': iprange,
                'ports': portranges,
                'threads': threads
            }

            scantime = time.time() - starttime

            self.root.after(0, self.updateresults, scantime)
        except Exception as e:
            self.root.after(0, self.showerror, str(e))
    
    def updateresults(self, scantime):
        self.progress_bar.stop()
        
        self.status_var.set(f"Scan completed in {scantime:.2f} seconds. Found {len(self.scan_results)} hosts.")
        
        for result in self.scan_results:
            ip = result["ip"]
            mac = result.get("mac", "N/A")
            status = result["status"]
            hostname = result.get("hostname", "N/A") or "N/A"
            openports = ", ".join(map(str, result.get("open_ports", []))) or "None"
            
            self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, openports))
        
        self.is_scanning = False
    
    def showerror(self, errmsg):
        self.progress_bar.stop()
        self.status_var.set("Error")
        self.is_scanning = False
        messagebox.showerror("Scan Error", f"An error occurred during the scan:\n{errmsg}")
    
    def stopscan(self):
        if not self.is_scanning:
            return
        
        self.status_var.set("Stopping scan...")
        messagebox.showinfo("Stopping Scan", "The scan will stop after the current operations complete.")
    
    def resetscan(self):
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
    
    def applyfilter(self):
        filtertext = self.filter_var.get()
        if not filtertext:
            return
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        filtered = self.scan_results.copy()
        
        if "port=" in filtertext:
            portfilter = int(filtertext.split("=")[1])
            filtered = [r for r in filtered if portfilter in r.get('open_ports', [])]
        
        elif "status=" in filtertext:
            statusfilter = filtertext.split("=")[1]
            filtered = [r for r in filtered if r['status'] == statusfilter]
        
        elif "mac=" in filtertext:
            macfilter = filtertext.split("=")[1].lower()
            filtered = [r for r in filtered if r.get('mac', '').lower() == macfilter]
        
        elif "ip=" in filtertext:
            ipfilter = filtertext.split("=")[1]
            filtered = [r for r in filtered if r['ip'] == ipfilter]
        
        for result in filtered:
            ip = result["ip"]
            mac = result.get("mac", "N/A")
            status = result["status"]
            hostname = result.get("hostname", "N/A") or "N/A"
            openports = ", ".join(map(str, result.get("open_ports", []))) or "None"
            
            self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, openports))
        
        self.status_var.set(f"Filtered results: {len(filtered)} hosts")
    
    def applysort(self):
        sortby = self.sort_var.get()
        if not sortby:
            return
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        sorted_results = self.scan_results.copy()
        
        if sortby == "ip":
            sorted_results = sorted(sorted_results, key=lambda x: [int(part) for part in x['ip'].split('.')])
        elif sortby == "mac":
            sorted_results = sorted(sorted_results, key=lambda x: x.get('mac', ''))
        elif sortby == "ports":
            sorted_results = sorted(sorted_results, key=lambda x: len(x.get('open_ports', [])), reverse=True)
        
        for result in sorted_results:
            ip = result["ip"]
            mac = result.get("mac", "N/A")
            status = result["status"]
            hostname = result.get("hostname", "N/A") or "N/A"
            openports = ", ".join(map(str, result.get("open_ports", []))) or "None"
            
            self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, openports))
        
        self.status_var.set(f"Sorted results by {sortby}")
    
    def showhostdetails(self, event):
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
        
        detailwin = tk.Toplevel(self.root)
        detailwin.title(f"Host Details: {ip}")
        detailwin.geometry("500x400")
        detailwin.minsize(400, 300)
        
        detailframe = ttk.Frame(detailwin, padding=10)
        detailframe.pack(fill=tk.BOTH, expand=True)
        
        infoframe = ttk.LabelFrame(detailframe, text="Host Information", padding=10)
        infoframe.pack(fill=tk.X, pady=5)
        
        ttk.Label(infoframe, text=f"IP Address: {host['ip']}").pack(anchor=tk.W)
        ttk.Label(infoframe, text=f"MAC Address: {host.get('mac', 'N/A')}").pack(anchor=tk.W)
        ttk.Label(infoframe, text=f"Status: {host['status']}").pack(anchor=tk.W)
        ttk.Label(infoframe, text=f"Hostname: {host.get('hostname', 'N/A') or 'N/A'}").pack(anchor=tk.W)
        
        portsframe = ttk.LabelFrame(detailframe, text="Open Ports", padding=10)
        portsframe.pack(fill=tk.BOTH, expand=True, pady=5)
        
        portstree = ttk.Treeview(portsframe, columns=("port", "service"), show="headings")
        portstree.heading("port", text="Port")
        portstree.heading("service", text="Service")
        
        portstree.column("port", width=100)
        portstree.column("service", width=200)
        
        scrollbar = ttk.Scrollbar(portsframe, orient=tk.VERTICAL, command=portstree.yview)
        portstree.configure(yscrollcommand=scrollbar.set)
        
        portstree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        for port in host.get("open_ports", []):
            service = host.get("services", {}).get(port, "unknown")
            portstree.insert("", tk.END, values=(port, service))
        
        ttk.Button(detailframe, text="Close", command=detailwin.destroy).pack(pady=10)
    
    def shownetgraph(self):
        if not self.scan_results:
            messagebox.showinfo("No Data", "No scan results to visualize.")
            return
        
        graphwin = tk.Toplevel(self.root)
        graphwin.title("Network Graph")
        graphwin.geometry("800x600")
        
        graphframe = ttk.Frame(graphwin, padding=10)
        graphframe.pack(fill=tk.BOTH, expand=True)
        
        fig = plt.Figure(figsize=(10, 8), dpi=100)
        ax = fig.add_subplot(111)
        
        G = nx.Graph()
        
        routerip = ".".join(self.scan_results[0]["ip"].split(".")[:3]) + ".1"
        G.add_node(routerip, type="router")
        
        for result in self.scan_results:
            if result["status"] in ["up", "up (ICMP)"]:
                G.add_node(result["ip"], type="host")
                G.add_edge(routerip, result["ip"])
                
                for port in result.get("open_ports", []):
                    portnode = f"{result['ip']}:{port}"
                    G.add_node(portnode, type="port")
                    G.add_edge(result["ip"], portnode)
        
        pos = nx.spring_layout(G, seed=42)
        
        routernodes = [n for n, d in G.nodes(data=True) if d.get("type") == "router"]
        hostnodes = [n for n, d in G.nodes(data=True) if d.get("type") == "host"]
        portnodes = [n for n, d in G.nodes(data=True) if d.get("type") == "port"]
        
        nx.draw_networkx_nodes(G, pos, nodelist=routernodes, node_color="red", node_size=500, ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=hostnodes, node_color="skyblue", node_size=300, ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=portnodes, node_color="green", node_size=100, ax=ax)
        
        nx.draw_networkx_edges(G, pos, ax=ax)
        
        routerlabels = {n: n for n in routernodes}
        hostlabels = {n: n for n in hostnodes}
        portlabels = {n: n.split(":")[-1] for n in portnodes}
        
        nx.draw_networkx_labels(G, pos, labels=routerlabels, font_size=10, ax=ax)
        nx.draw_networkx_labels(G, pos, labels=hostlabels, font_size=8, ax=ax)
        nx.draw_networkx_labels(G, pos, labels=portlabels, font_size=6, ax=ax)
        
        ax.plot([], [], "ro", label="Router")
        ax.plot([], [], "o", color="skyblue", label="Host")
        ax.plot([], [], "go", label="Open Port")
        ax.legend()
        
        ax.set_axis_off()
        
        canvas = FigureCanvasTkAgg(fig, master=graphframe)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(graphframe, text="Close", command=graphwin.destroy).pack(pady=10)
    
    def showportdist(self):
        if not self.scan_results:
            messagebox.showinfo("No Data", "No scan results to visualize.")
            return
        
        allports = []
        for result in self.scan_results:
            allports.extend(result.get("open_ports", []))
        
        if not allports:
            messagebox.showinfo("No Data", "No open ports found in scan results.")
            return
        
        portcounts = {}
        for port in allports:
            portcounts[port] = portcounts.get(port, 0) + 1
        
        sortedports = sorted(portcounts.items(), key=lambda x: x[1], reverse=True)
        
        graphwin = tk.Toplevel(self.root)
        graphwin.title("Port Distribution")
        graphwin.geometry("800x600")
        
        graphframe = ttk.Frame(graphwin, padding=10)
        graphframe.pack(fill=tk.BOTH, expand=True)
        
        fig = plt.Figure(figsize=(10, 8), dpi=100)
        ax = fig.add_subplot(111)
        
        ports = [p[0] for p in sortedports[:15]]
        counts = [p[1] for p in sortedports[:15]]
        
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
        
        canvas = FigureCanvasTkAgg(fig, master=graphframe)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(graphframe, text="Close", command=graphwin.destroy).pack(pady=10)
    
    def loadsessiondialog(self):
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
                openports = ", ".join(map(str, result.get("open_ports", []))) or "None"
                
                self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, openports))
            
            self.status_var.set(f"Loaded session from {filename}")
            messagebox.showinfo("Session Loaded", f"Successfully loaded session from {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load session: {e}")
    
    def savesessiondialog(self):
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
    
    def exportresults(self, formattype):
        if not self.scan_results:
            messagebox.showinfo("No Data", "No scan results to export.")
            return
        
        ensure_directory_exists("results")
        
        if formattype == "csv":
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
        
        elif formattype == "json":
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
    
    def showabout(self):
        abouttext = """
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
        
        messagebox.showinfo("About Network Scanner", abouttext)

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
