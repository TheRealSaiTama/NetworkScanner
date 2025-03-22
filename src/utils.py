#!/usr/bin/env python3
import ipaddress
import csv
import json
import socket
import os
from typing import List, Dict, Any, Tuple, Optional

def validate_ip_range(iprange: str) -> bool:
    try:
        ipaddress.ip_network(iprange, strict=False)
        return True
    except ValueError:
        return False

def validate_port_range(portrange: str) -> bool:
    try:
        for part in portrange.split(","):
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

def parse_port_range(portrange: str) -> List[int]:
    ports = []
    for part in portrange.split(","):
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

    ipwidth = max(len("IP Address"), max(len(r["ip"]) for r in results))
    macwidth = max(len("MAC Address"), max(len(r["mac"]) for r in results))
    statuswidth = max(len("Status"), max(len(r["status"]) for r in results))
    hostnamewidth = max(len("Hostname"), max(len(r["hostname"]) for r in results))

    header = f"{'IP Address':<{ipwidth}} | {'MAC Address':<{macwidth}} | {'Status':<{statuswidth}} | {'Hostname':<{hostnamewidth}} | Open Ports"
    separator = "-" * len(header)

    table = [header, separator]
    for result in results:
        row = f"{result['ip']:<{ipwidth}} | {result['mac']:<{macwidth}} | {result['status']:<{statuswidth}} | {result['hostname']:<{hostnamewidth}} | {result['open_ports_str']}"
        table.append(row)

    return "\n".join(table)

def export_to_csv(results: List[Dict[str, Any]], filename: str) -> None:
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['ip', 'mac', 'status', 'hostname', 'open_ports', 'services']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            resultcopy = result.copy()
            if 'open_ports' in resultcopy:
                resultcopy['open_ports'] = ','.join(map(str, resultcopy['open_ports']))
            if 'services' in resultcopy:
                servicesstr = ';'.join([f"{port}:{service}" for port, service in resultcopy['services'].items()])
                resultcopy['services'] = servicesstr
            
            writer.writerow(resultcopy)

def export_to_json(results: List[Dict[str, Any]], filename: str) -> None:
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

def save_session(results: List[Dict[str, Any]], settings: Dict[str, Any], filename: str) -> None:
    sessiondata = {"results": results, "settings": settings}
    with open(filename, 'w') as f:
        json.dump(sessiondata, f, indent=4)

def load_session(filename: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    with open(filename, 'r') as f:
        sessiondata = json.load(f)
    return sessiondata['results'], sessiondata['settings']

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

def get_interface_ip(ifacename: str) -> Optional[str]:
    try:
        import netifaces
        addresses = netifaces.ifaddresses(ifacename)
        if netifaces.AF_INET in addresses:
            return addresses[netifaces.AF_INET][0]['addr']
        return None
    except (ImportError, ValueError):
        import subprocess
        try:
            output = subprocess.check_output(['ip', 'addr', 'show', ifacename]).decode('utf-8')
            for line in output.split('\n'):
                if 'inet ' in line:
                    return line.split()[1].split('/')[0]
            return None
        except subprocess.SubprocessError:
            return None

def get_network_interfaces() -> List[Dict[str, str]]:
    try:
        import netifaces
        ifaces = []
        for iface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addresses:
                for addr in addresses[netifaces.AF_INET]:
                    ifaces.append({
                        "name": iface,
                        "ip": addr['addr'],
                        "netmask": addr.get('netmask', 'Unknown')
                    })
        return ifaces
    except ImportError:
        import subprocess
        try:
            output = subprocess.check_output(['ip', 'addr']).decode('utf-8')
            ifaces = []
            currentiface = None
            
            for line in output.split('\n'):
                if line.startswith(' ') and currentiface and 'inet ' in line:
                    parts = line.strip().split()
                    ipprefix = parts[1]
                    ip = ipprefix.split('/')[0]
                    ifaces.append({
                        "name": currentiface,
                        "ip": ip,
                        "netmask": "Unknown"
                    })
                elif not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) > 1:
                        currentiface = parts[1].strip()
            
            return ifaces
        except subprocess.SubprocessError:
            return []

if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    print("Import it and use its functions in your own scripts.")
