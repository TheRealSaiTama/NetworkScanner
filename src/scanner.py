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

def arp_scan(iprange: str) -> List[Dict[str, str]]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        arpreq = scapy.ARP(pdst=iprange)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arpreqbc = broadcast / arpreq
        answeredlist = scapy.srp(arpreqbc, timeout=5, verbose=False)[0]
    clientslist = []
    for element in answeredlist:
        clientdict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clientslist.append(clientdict)
    return clientslist

def ping_scan(ipaddress: str) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        icmpreq = scapy.IP(dst=ipaddress) / scapy.ICMP()
        response = scapy.sr1(icmpreq, timeout=2, verbose=False)
    return response is not None

def scan_host(ip: Union[str, ipaddress.IPv4Address]) -> Dict[str, Any]:
    ipstr = str(ip)
    arpresult = arp_scan(ipstr)
    if arpresult:
        return {"ip": ipstr, "mac": arpresult[0]['mac'], "status": "up"}
    elif ping_scan(ipstr):
        return {"ip": ipstr, "mac": None, "status": "up (ICMP)"}
    else:
        return {"ip": ipstr, "mac": None, "status": "down"}

def parallel_scan(iprange: str, maxworkers: int = 10) -> List[Dict[str, Any]]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=maxworkers) as executor:
        futuretoip = {executor.submit(scan_host, ip): ip for ip in ipaddress.ip_network(iprange).hosts()}
        results = []
        for future in concurrent.futures.as_completed(futuretoip):
            result = future.result()
            results.append(result)
        return results

def send_syn(ipaddr: str, port: int) -> Optional[scapy.packet.Packet]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ip = scapy.IP(dst=ipaddr)
        tcp = scapy.TCP(dport=port, flags="S")
        packet = ip / tcp
        response = scapy.sr1(packet, timeout=1, verbose=False)
    return response

def is_port_open(ipaddr: str, port: int) -> bool:
    response = send_syn(ipaddr, port)
    if response and response.haslayer(scapy.TCP):
        if response[scapy.TCP].flags == "SA":
            rstpacket = scapy.IP(dst=ipaddr) / scapy.TCP(
                dport=port, 
                sport=response[scapy.TCP].dport, 
                seq=response[scapy.TCP].ack, 
                ack=response[scapy.TCP].seq + 1, 
                flags="R"
            )
            scapy.send(rstpacket, verbose=False)
            return True
    return False

def is_port_open_with_retry(ipaddr: str, port: int, retries: int = 3) -> bool:
    for _ in range(retries):
        if is_port_open(ipaddr, port):
            return True
    return False

def scan_ports(ipaddr: str, portranges: str) -> List[int]:
    openports = []
    for portrange in portranges.split(","):
        portrange = portrange.strip()
        if "-" in portrange:
            startport, endport = map(int, portrange.split("-"))
            for port in range(startport, endport + 1):
                if is_port_open(ipaddr, port):
                    openports.append(port)
        else:
            port = int(portrange)
            if is_port_open(ipaddr, port):
                openports.append(port)
    return openports

def parallel_port_scan(ipaddr: str, portranges: str, maxworkers: int = 20) -> List[int]:
    portstoscan = []
    for portrange in portranges.split(","):
        portrange = portrange.strip()
        if "-" in portrange:
            startport, endport = map(int, portrange.split("-"))
            portstoscan.extend(range(startport, endport + 1))
        else:
            portstoscan.append(int(portrange))
    
    openports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=maxworkers) as executor:
        futuretoport = {executor.submit(is_port_open, ipaddr, port): port for port in portstoscan}
        for future in concurrent.futures.as_completed(futuretoport):
            if future.result():
                openports.append(futuretoport[future])
    
    return sorted(openports)

def ack_scan(ipaddr: str, port: int) -> Optional[str]:
    ip = scapy.IP(dst=ipaddr)
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

def get_hostname(ipaddr: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ipaddr)[0]
    except (socket.herror, socket.gaierror):
        return None

def scan_target(ipaddr: str, portranges: str, maxworkers: int = 20) -> Dict[str, Any]:
    try:
        hostresult = scan_host(ipaddr)
        if hostresult["status"] in ["up", "up (ICMP)"]:
            try:
                openports = parallel_port_scan(ipaddr, portranges, maxworkers)
            except Exception as e:
                print(f"Error during port scan: {e}")
                openports = []

            services = {}
            for port in openports:
                try:
                    services[port] = get_service_name(port)
                except Exception:
                    services[port] = "unknown"

            try:
                hostname = get_hostname(ipaddr)
            except Exception:
                hostname = None

            hostresult["open_ports"] = openports
            hostresult["services"] = services
            hostresult["hostname"] = hostname
        else:
            hostresult["open_ports"] = []
            hostresult["services"] = {}
            hostresult["hostname"] = None

        return hostresult
    except Exception as e:
        print(f"Error scanning target {ipaddr}: {e}")
        return {
            "ip": ipaddr,
            "mac": None,
            "status": "error",
            "hostname": None,
            "open_ports": [],
            "services": {}
        }

def scan_network(iprange: str, portranges: str, maxworkers: int = 10) -> List[Dict[str, Any]]:
    try:
        print(f"Starting host discovery on {iprange}...")
        hostresults = parallel_scan(iprange, maxworkers)
        print(f"Found {len(hostresults)} hosts. Starting port scans...")

        activehosts = [h for h in hostresults if h["status"] in ["up", "up (ICMP)"]]
        print(f"Active hosts: {len(activehosts)}")

        for i, host in enumerate(hostresults):
            if host["status"] in ["up", "up (ICMP)"]:
                print(f"Scanning ports on {host['ip']} ({i+1}/{len(activehosts)})...")

                try:
                    openports = parallel_port_scan(host["ip"], portranges, maxworkers)

                    services = {}
                    for port in openports:
                        try:
                            services[port] = get_service_name(port)
                        except Exception:
                            services[port] = "unknown"

                    try:
                        hostname = get_hostname(host["ip"])
                    except Exception:
                        hostname = None

                    host["open_ports"] = openports
                    host["services"] = services
                    host["hostname"] = hostname

                    if openports:
                        print(f"  Found {len(openports)} open ports: {', '.join(map(str, openports))}")
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

        return hostresults
    except Exception as e:
        print(f"Error during network scan: {e}")
        return [{
            "ip": iprange,
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
