#!/usr/bin/env python3
"""
Network Scanner - Utility functions

This module contains utility functions for the network scanner,
such as IP parsing, result formatting, and data export.
"""

import ipaddress
import csv
import json
import socket
import os
from typing import List, Dict, Any, Tuple, Optional

def validate_ip_range(ip_range: str) -> bool:
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def validate_port_range(port_range: str) -> bool:
    try:
        for part in port_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                if start < 1 or end > 65535 or start > end:
                    return False
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    return False
        return True
    except ValueError:
        return False

def parse_port_range(port_range: str) -> List[int]:
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(list(set(ports)))

def format_results_table(results: List[Dict[str, Any]]) -> str:
    if not results:
        return "No results found."

    for result in results:
        result["ip"] = str(result.get("ip", "N/A"))

        if result.get("mac") is None:
            result["mac"] = "N/A"
        else:
            result["mac"] = str(result["mac"])

        result["status"] = str(result.get("status", "Unknown"))

        if result.get("hostname") is None:
            result["hostname"] = "N/A"
        else:
            result["hostname"] = str(result["hostname"])

        if not result.get("open_ports"):
            result["open_ports_str"] = "None"
        else:
            result["open_ports_str"] = ", ".join(map(str, result["open_ports"]))

    ip_width = max(len("IP Address"), max(len(r["ip"]) for r in results))
    mac_width = max(len("MAC Address"), max(len(r["mac"]) for r in results))
    status_width = max(len("Status"), max(len(r["status"]) for r in results))
    hostname_width = max(len("Hostname"), max(len(r["hostname"]) for r in results))

    header = f"{'IP Address':<{ip_width}} | {'MAC Address':<{mac_width}} | {'Status':<{status_width}} | {'Hostname':<{hostname_width}} | Open Ports"
    separator = "-" * len(header)

    table = [header, separator]
    for result in results:
        row = f"{result['ip']:<{ip_width}} | {result['mac']:<{mac_width}} | {result['status']:<{status_width}} | {result['hostname']:<{hostname_width}} | {result['open_ports_str']}"
        table.append(row)

    return "\n".join(table)

def export_to_csv(results: List[Dict[str, Any]], filename: str) -> None:
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['ip', 'mac', 'status', 'hostname', 'open_ports', 'services']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            result_copy = result.copy()
            if 'open_ports' in result_copy:
                result_copy['open_ports'] = ','.join(map(str, result_copy['open_ports']))
            if 'services' in result_copy:
                services_str = ';'.join([f"{port}:{service}" for port, service in result_copy['services'].items()])
                result_copy['services'] = services_str
            
            writer.writerow(result_copy)

def export_to_json(results: List[Dict[str, Any]], filename: str) -> None:
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

def save_session(results: List[Dict[str, Any]], settings: Dict[str, Any], filename: str) -> None:
    session_data = {"results": results, "settings": settings}
    with open(filename, 'w') as f:
        json.dump(session_data, f, indent=4)

def load_session(filename: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    with open(filename, 'r') as f:
        session_data = json.load(f)
    return session_data['results'], session_data['settings']

def get_common_ports() -> Dict[str, List[int]]:
    return {
        "Web": [80, 443, 8080, 8443],
        "Email": [25, 110, 143, 465, 587, 993, 995],
        "File Transfer": [20, 21, 22, 69, 115, 989, 990],
        "Directory Services": [389, 636, 3268, 3269],
        "Databases": [1433, 1521, 3306, 5432, 6379, 27017],
        "Remote Access": [22, 23, 3389, 5900],
        "Name Resolution": [53, 137, 138, 139],
        "Other Common": [123, 161, 162, 179, 445, 514, 873]
    }

def ensure_directory_exists(directory: str) -> None:
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_interface_ip(interface_name: str) -> Optional[str]:
    try:
        import netifaces
        addresses = netifaces.ifaddresses(interface_name)
        if netifaces.AF_INET in addresses:
            return addresses[netifaces.AF_INET][0]['addr']
        return None
    except (ImportError, ValueError):
        import subprocess
        try:
            output = subprocess.check_output(['ip', 'addr', 'show', interface_name]).decode('utf-8')
            for line in output.split('\n'):
                if 'inet ' in line:
                    return line.split()[1].split('/')[0]
            return None
        except subprocess.SubprocessError:
            return None

def get_network_interfaces() -> List[Dict[str, str]]:
    try:
        import netifaces
        interfaces = []
        for iface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addresses:
                for addr in addresses[netifaces.AF_INET]:
                    interfaces.append({
                        "name": iface,
                        "ip": addr['addr'],
                        "netmask": addr.get('netmask', 'Unknown')
                    })
        return interfaces
    except ImportError:
        import subprocess
        try:
            output = subprocess.check_output(['ip', 'addr']).decode('utf-8')
            interfaces = []
            current_iface = None
            
            for line in output.split('\n'):
                if line.startswith(' ') and current_iface and 'inet ' in line:
                    parts = line.strip().split()
                    ip_with_prefix = parts[1]
                    ip = ip_with_prefix.split('/')[0]
                    interfaces.append({
                        "name": current_iface,
                        "ip": ip,
                        "netmask": "Unknown"
                    })
                elif not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) > 1:
                        current_iface = parts[1].strip()
            
            return interfaces
        except subprocess.SubprocessError:
            return []

if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    print("Import it and use its functions in your own scripts.")
