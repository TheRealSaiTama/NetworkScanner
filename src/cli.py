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

def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Scanner - Discover devices and open ports on your network",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "ip_range", 
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

def filter_results(results: List[Dict[str, Any]], filter_criteria: str) -> List[Dict[str, Any]]:
    filtered_list = results.copy()
    
    if "port=" in filter_criteria:
        port_to_filter = int(filter_criteria.split("=")[1])
        filtered_list = [r for r in filtered_list if port_to_filter in r.get('open_ports', [])]
    
    elif "status=" in filter_criteria:
        status_to_filter = filter_criteria.split("=")[1]
        filtered_list = [r for r in filtered_list if r['status'] == status_to_filter]
    
    elif "mac=" in filter_criteria:
        mac_to_filter = filter_criteria.split("=")[1].lower()
        filtered_list = [r for r in filtered_list if r.get('mac', '').lower() == mac_to_filter]
    
    elif "ip=" in filter_criteria:
        ip_to_filter = filter_criteria.split("=")[1]
        filtered_list = [r for r in filtered_list if r['ip'] == ip_to_filter]
    
    return filtered_list

def sort_results(results: List[Dict[str, Any]], sort_by: str) -> List[Dict[str, Any]]:
    if sort_by == "ip":
        return sorted(results, key=lambda x: [int(part) for part in x['ip'].split('.')])
    elif sort_by == "mac":
        return sorted(results, key=lambda x: x.get('mac', ''))
    elif sort_by == "ports":
        return sorted(results, key=lambda x: len(x.get('open_ports', [])), reverse=True)
    return results

def display_interfaces():
    interfaces = get_network_interfaces()
    
    if not interfaces:
        print("No network interfaces found.")
        return
    
    print("\nAvailable Network Interfaces:")
    print("-" * 60)
    print(f"{'Interface':<15} | {'IP Address':<15} | {'Netmask':<15}")
    print("-" * 60)
    
    for iface in interfaces:
        print(f"{iface['name']:<15} | {iface['ip']:<15} | {iface['netmask']:<15}")
    
    print()

def main():
    args = parse_args()
    
    if args.list_interfaces:
        display_interfaces()
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
        if not validate_ip_range(args.ip_range):
            print(f"Invalid IP range: {args.ip_range}")
            return
        
        if not args.common_ports and not validate_port_range(args.ports):
            print(f"Invalid port range: {args.ports}")
            return
        
        if args.common_ports:
            common_ports = get_common_ports()
            all_ports = []
            for category, ports in common_ports.items():
                all_ports.extend(ports)
            args.ports = ",".join(map(str, sorted(set(all_ports))))
            if args.verbose:
                print(f"Using common ports: {args.ports}")
        
        print(f"Scanning {args.ip_range} with port range {args.ports}...")
        start_time = time.time()
        
        try:
            results = scan_network(args.ip_range, args.ports, args.threads)
            settings = {
                'ip_range': args.ip_range,
                'ports': args.ports,
                'threads': args.threads
            }
        except Exception as e:
            print(f"Error during scanning: {e}")
            return
        
        scan_time = time.time() - start_time
        print(f"Scan completed in {scan_time:.2f} seconds")
    
    if args.filter:
        results = filter_results(results, args.filter)
        print(f"Filtered results using: {args.filter}")
    
    if args.sort:
        results = sort_results(results, args.sort)
        print(f"Sorted results by: {args.sort}")
    
    print("\nScan Results:")
    print(format_results_table(results))
    
    if args.save:
        save_session(results, settings, args.save)
        print(f"Session saved to {args.save}")
    
    if args.output:
        if args.format in ["csv", "both"]:
            csv_file = f"results/{args.output}.csv"
            export_to_csv(results, csv_file)
            print(f"Results exported to {csv_file}")
        
        if args.format in ["json", "both"]:
            json_file = f"results/{args.output}.json"
            export_to_json(results, json_file)
            print(f"Results exported to {json_file}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
