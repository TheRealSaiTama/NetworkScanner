#!/usr/bin/env python3
import sys
import os
import tkinter as tk
import threading
import time
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.scanner import scan_target
from src.gui import NetworkScannerGUI

class TestNetworkScannerGUI(NetworkScannerGUI):
    def __init__(self, root):
        super().__init__(root)
        self.ip_range_var.set("127.0.0.1")
        self.port_range_var.set("22,80,443,8080,3000,3306,5432")
        self.threads_var.set(5)
        self.root.after(1000, self.runtestscan)
    
    def runtestscan(self):
        self.status_var.set("Running test scan of localhost...")
        threading.Thread(target=self.testscan, daemon=True).start()
    
    def testscan(self):
        try:
            result = scan_target("127.0.0.1", "22,80,443,8080,3000,3306,5432")
            self.scan_results = [result]
            self.scan_settings = {
                'ip_range': "127.0.0.1",
                'ports': "22,80,443,8080,3000,3306,5432",
                'threads': 5
            }
            self.root.after(0, self.updateresults)
        except Exception as e:
            self.root.after(0, lambda: self.show_error(str(e)))
    
    def updateresults(self):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.status_var.set("Test scan completed. GUI is ready for use.")
        self.progress_bar.stop()
        for result in self.scan_results:
            ip = result["ip"]
            mac = result.get("mac", "N/A")
            status = result["status"]
            hostname = result.get("hostname", "N/A") or "N/A"
            openports = ", ".join(map(str, result.get("open_ports", []))) or "None"
            self.results_tree.insert("", tk.END, values=(ip, mac, status, hostname, openports))
        self.root.after(500, self.showcompletemsg)
    
    def showcompletemsg(self):
        from tkinter import messagebox
        messagebox.showinfo(
            "Test Complete", 
            "The GUI test is complete. The scanner is now ready for use.\n\n"
            "You can now try scanning your network by changing the IP range\n"
            "and clicking the 'Start Scan' button."
        )

def main():
    root = tk.Tk()
    app = TestNetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
