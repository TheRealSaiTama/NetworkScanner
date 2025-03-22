#!/usr/bin/env python3
import scapy.all as scapy
import ipaddress
import concurrent.futures
import socket
import logging
import warnings
from typing import List, Dict, Any, Union, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*MAC address to reach destination not found.*")

def arp_scan(ip_range: str) -> List[Dict[str, str]]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def ping_scan(ip_address: str) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        icmp_request = scapy.IP(dst=ip_address) / scapy.ICMP()
        response = scapy.sr1(icmp_request, timeout=2, verbose=False)
    return response is not None

def scan_host(ip: Union[str, ipaddress.IPv4Address]) -> Dict[str, Any]:
    ip_str = str(ip)
    arp_result = arp_scan(ip_str)
    if arp_result:
        return {"ip": ip_str, "mac": arp_result[0]['mac'], "status": "up"}
    elif ping_scan(ip_str):
        return {"ip": ip_str, "mac": None, "status": "up (ICMP)"}
    else:
        return {"ip": ip_str, "mac": None, "status": "down"}

def parallel_scan(ip_range: str, max_workers: int = 10) -> List[Dict[str, Any]]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_host, ip): ip for ip in ipaddress.ip_network(ip_range).hosts()}
        results = []
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            results.append(result)
        return results

def send_syn(ip_address: str, port: int) -> Optional[scapy.packet.Packet]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ip = scapy.IP(dst=ip_address)
        tcp = scapy.TCP(dport=port, flags="S")
        packet = ip / tcp
        response = scapy.sr1(packet, timeout=1, verbose=False)
    return response

def is_port_open(ip_address: str, port: int) -> bool:
    response = send_syn(ip_address, port)
    if response and response.haslayer(scapy.TCP):
        if response[scapy.TCP].flags == "SA":
            rst_packet = scapy.IP(dst=ip_address) / scapy.TCP(
                dport=port, 
                sport=response[scapy.TCP].dport, 
                seq=response[scapy.TCP].ack, 
                ack=response[scapy.TCP].seq + 1, 
                flags="R"
            )
            scapy.send(rst_packet, verbose=False)
            return True
    return False

def is_port_open_with_retry(ip_address: str, port: int, retries: int = 3) -> bool:
    for _ in range(retries):
        if is_port_open(ip_address, port):
            return True
    return False

def scan_ports(ip_address: str, port_ranges: str) -> List[int]:
    open_ports = []
    for port_range in port_ranges.split(","):
        port_range = port_range.strip()
        if "-" in port_range:
            start_port, end_port = map(int, port_range.split("-"))
            for port in range(start_port, end_port + 1):
                if is_port_open(ip_address, port):
                    open_ports.append(port)
        else:
            port = int(port_range)
            if is_port_open(ip_address, port):
                open_ports.append(port)
    return open_ports

def parallel_port_scan(ip_address: str, port_ranges: str, max_workers: int = 20) -> List[int]:
    ports_to_scan = []
    for port_range in port_ranges.split(","):
        port_range = port_range.strip()
        if "-" in port_range:
            start_port, end_port = map(int, port_range.split("-"))
            ports_to_scan.extend(range(start_port, end_port + 1))
        else:
            ports_to_scan.append(int(port_range))
    
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(is_port_open, ip_address, port): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(future_to_port):
            if future.result():
                open_ports.append(future_to_port[future])
    
    return sorted(open_ports)

def ack_scan(ip_address: str, port: int) -> Optional[str]:
    ip = scapy.IP(dst=ip_address)
    tcp = scapy.TCP(dport=port, flags="A")
    packet = ip / tcp
    response = scapy.sr1(packet, timeout=1, verbose=False)

    if response is None:
        return "filtered"
    elif response.haslayer(scapy.TCP):
        if response[scapy.TCP].flags == "R":
            return "unfiltered"
    elif response.haslayer(scapy.ICMP):
        if response[scapy.ICMP].type == 3 and response[scapy.ICMP].code in [1, 2, 3, 9, 10, 13]:
            return "filtered"
    return None

def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except (socket.error, OSError):
        return "unknown"

def get_hostname(ip_address: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        return None

def scan_target(ip_address: str, port_ranges: str, max_workers: int = 20) -> Dict[str, Any]:
    try:
        host_result = scan_host(ip_address)
        if host_result["status"] in ["up", "up (ICMP)"]:
            try:
                open_ports = parallel_port_scan(ip_address, port_ranges, max_workers)
            except Exception as e:
                print(f"Error during port scan: {e}")
                open_ports = []

            services = {}
            for port in open_ports:
                try:
                    services[port] = get_service_name(port)
                except Exception:
                    services[port] = "unknown"

            try:
                hostname = get_hostname(ip_address)
            except Exception:
                hostname = None

            host_result["open_ports"] = open_ports
            host_result["services"] = services
            host_result["hostname"] = hostname
        else:
            host_result["open_ports"] = []
            host_result["services"] = {}
            host_result["hostname"] = None

        return host_result
    except Exception as e:
        print(f"Error scanning target {ip_address}: {e}")
        return {
            "ip": ip_address,
            "mac": None,
            "status": "error",
            "hostname": None,
            "open_ports": [],
            "services": {}
        }

def scan_network(ip_range: str, port_ranges: str, max_workers: int = 10) -> List[Dict[str, Any]]:
    try:
        print(f"Starting host discovery on {ip_range}...")
        host_results = parallel_scan(ip_range, max_workers)
        print(f"Found {len(host_results)} hosts. Starting port scans...")

        active_hosts = [h for h in host_results if h["status"] in ["up", "up (ICMP)"]]
        print(f"Active hosts: {len(active_hosts)}")

        for i, host in enumerate(host_results):
            if host["status"] in ["up", "up (ICMP)"]:
                print(f"Scanning ports on {host['ip']} ({i+1}/{len(active_hosts)})...")

                try:
                    open_ports = parallel_port_scan(host["ip"], port_ranges, max_workers)

                    services = {}
                    for port in open_ports:
                        try:
                            services[port] = get_service_name(port)
                        except Exception:
                            services[port] = "unknown"

                    try:
                        hostname = get_hostname(host["ip"])
                    except Exception:
                        hostname = None

                    host["open_ports"] = open_ports
                    host["services"] = services
                    host["hostname"] = hostname

                    if open_ports:
                        print(f"  Found {len(open_ports)} open ports: {', '.join(map(str, open_ports))}")
                    else:
                        print(f"  No open ports found")

                except Exception as e:
                    print(f"Error scanning ports on {host['ip']}: {e}")
                    host["open_ports"] = []
                    host["services"] = {}
                    host["hostname"] = None
            else:
                host["open_ports"] = []
                host["services"] = {}
                host["hostname"] = None

        return host_results
    except Exception as e:
        print(f"Error during network scan: {e}")
        return [{
            "ip": ip_range,
            "mac": None,
            "status": "error",
            "hostname": None,
            "open_ports": [],
            "services": {},
            "error": str(e)
        }]

if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    print("Import it and use its functions in your own scripts.")
