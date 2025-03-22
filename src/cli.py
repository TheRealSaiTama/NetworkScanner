#!/usr/bin/env python3
import argparse
import sys
import os
import time
from typing import List, Dict, Any

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import parallel_scan, parallel_port_scan, scan_network
from src.utils import (
    validate_ip_range, validate_port_range, format_results_table,
    export_to_csv, export_to_json, save_session, load_session,
    get_common_ports, ensure_directory_exists, get_network_interfaces
)

def parseargs():
    parser = argparse.ArgumentParser(
        description="Network Scanner - Discover devices and open ports on your network",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "iprange", 
        help="The IP range to scan (e.g., 192.168.1.0/24)"
    )
    
    parser.add_argument(
        "-p", "--ports", 
        help="Comma-separated port ranges (e.g., 22,80,1-1024)",
        default="1-1024"
    )
    parser.add_argument(
        "-t", "--threads", 
        help="Number of threads for parallel scanning",
        type=int, 
        default=10
    )
    parser.add_argument(
        "-o", "--output", 
        help="Output file name (without extension)"
    )
    parser.add_argument(
        "--format", 
        help="Output format (csv, json, or both)",
        choices=["csv", "json", "both"], 
        default="both"
    )
    parser.add_argument(
        "-s", "--sort", 
        help="Sort results by (ip, mac, ports)",
        choices=["ip", "mac", "ports"]
    )
    parser.add_argument(
        "-f", "--filter", 
        help="Filter results (e.g., port=80, status=up)"
    )
    parser.add_argument(
        "--save", 
        help="Save session to a file"
    )
    parser.add_argument(
        "--load", 
        help="Load session from a file"
    )
    parser.add_argument(
        "--list-interfaces", 
        help="List available network interfaces",
        action="store_true"
    )
    parser.add_argument(
        "--common-ports", 
        help="Use common ports instead of port range",
        action="store_true"
    )
    parser.add_argument(
        "-v", "--verbose", 
        help="Increase output verbosity",
        action="store_true"
    )
    
    return parser.parse_args()

def filterresults(results: List[Dict[str, Any]], filtercriteria: str) -> List[Dict[str, Any]]:
    filteredlist = results.copy()
    
    if "port=" in filtercriteria:
        portfilter = int(filtercriteria.split("=")[1])
        filteredlist = [r for r in filteredlist if portfilter in r.get('open_ports', [])]
    
    elif "status=" in filtercriteria:
        statusfilter = filtercriteria.split("=")[1]
        filteredlist = [r for r in filteredlist if r['status'] == statusfilter]
    
    elif "mac=" in filtercriteria:
        macfilter = filtercriteria.split("=")[1].lower()
        filteredlist = [r for r in filteredlist if r.get('mac', '').lower() == macfilter]
    
    elif "ip=" in filtercriteria:
        ipfilter = filtercriteria.split("=")[1]
        filteredlist = [r for r in filteredlist if r['ip'] == ipfilter]
    
    return filteredlist

def sortresults(results: List[Dict[str, Any]], sortby: str) -> List[Dict[str, Any]]:
    if sortby == "ip":
        return sorted(results, key=lambda x: [int(part) for part in x['ip'].split('.')])
    elif sortby == "mac":
        return sorted(results, key=lambda x: x.get('mac', ''))
    elif sortby == "ports":
        return sorted(results, key=lambda x: len(x.get('open_ports', [])), reverse=True)
    return results

def displayifaces():
    ifaces = get_network_interfaces()
    
    if not ifaces:
        print("No network interfaces found.")
        return
    
    print("\nAvailable Network Interfaces:")
    print("-" * 60)
    print(f"{'Interface':<15} | {'IP Address':<15} | {'Netmask':<15}")
    print("-" * 60)
    
    for iface in ifaces:
        print(f"{iface['name']:<15} | {iface['ip']:<15} | {iface['netmask']:<15}")
    
    print()

def main():
    args = parseargs()
    
    if args.list_interfaces:
        displayifaces()
        return
    
    ensure_directory_exists("results")
    
    if args.load:
        try:
            results, settings = load_session(args.load)
            print(f"Loaded session from {args.load}")
            print(f"Settings: {settings}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading session: {e}")
            return
    else:
        if not validate_ip_range(args.iprange):
            print(f"Invalid IP range: {args.iprange}")
            return
        
        if not args.common_ports and not validate_port_range(args.ports):
            print(f"Invalid port range: {args.ports}")
            return
        
        if args.common_ports:
            commonports = get_common_ports()
            allports = []
            for category, ports in commonports.items():
                allports.extend(ports)
            args.ports = ",".join(map(str, sorted(set(allports))))
            if args.verbose:
                print(f"Using common ports: {args.ports}")
        
        print(f"Scanning {args.iprange} with port range {args.ports}...")
        starttime = time.time()
        
        try:
            results = scan_network(args.iprange, args.ports, args.threads)
            settings = {
                'ip_range': args.iprange,
                'ports': args.ports,
                'threads': args.threads
            }
        except Exception as e:
            print(f"Error during scanning: {e}")
            return
        
        scantime = time.time() - starttime
        print(f"Scan completed in {scantime:.2f} seconds")
    
    if args.filter:
        results = filterresults(results, args.filter)
        print(f"Filtered results using: {args.filter}")
    
    if args.sort:
        results = sortresults(results, args.sort)
        print(f"Sorted results by: {args.sort}")
    
    print("\nScan Results:")
    print(format_results_table(results))
    
    if args.save:
        save_session(results, settings, args.save)
        print(f"Session saved to {args.save}")
    
    if args.output:
        if args.format in ["csv", "both"]:
            csvfile = f"results/{args.output}.csv"
            export_to_csv(results, csvfile)
            print(f"Results exported to {csvfile}")
        
        if args.format in ["json", "both"]:
            jsonfile = f"results/{args.output}.json"
            export_to_json(results, jsonfile)
            print(f"Results exported to {jsonfile}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
