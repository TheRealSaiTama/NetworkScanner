#!/usr/bin/env python3
import sys
import os
import socket
import time
import traceback

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner import scan_target, arp_scan
from src.utils import format_results_table

def getgateway():
    print("Trying to determine default gateway...")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        localip = s.getsockname()[0]
        s.close()

        gateway = ".".join(localip.split(".")[:3]) + ".1"
        print(f"Local IP: {localip}, Possible gateway: {gateway}")
        return gateway
    except Exception as e:
        print(f"Error determining gateway via socket: {e}")

    commongw = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "192.168.2.1"]
    for gw in commongw:
        print(f"Trying common gateway: {gw}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((gw, 80))
            s.close()
            if result == 0:
                print(f"Found potential gateway at {gw}")
                return gw
        except Exception as e:
            print(f"Error checking {gw}: {e}")

    try:
        print("Trying ARP scan to find devices...")
        for subnet in ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]:
            print(f"Scanning subnet {subnet}...")
            results = arp_scan(subnet)
            if results:
                print(f"Found {len(results)} devices via ARP")
                for device in results:
                    ip = device["ip"]
                    if ip.endswith(".1") or ip.endswith(".254"):
                        print(f"Found potential gateway: {ip}")
                        return ip
    except Exception as e:
        print(f"Error during ARP scan: {e}")

    print("Could not determine gateway")
    return None

def testlocalhost():
    print("\n=== Testing localhost scan ===")

    try:
        print("Scanning localhost (127.0.0.1)...")
        starttime = time.time()
        localhostresult = scan_target("127.0.0.1", "22,80,443,8080,3000,3306,5432")
        scantime = time.time() - starttime

        print(f"Scan completed in {scantime:.2f} seconds")
        print(format_results_table([localhostresult]))

        if localhostresult.get("open_ports"):
            print(f"SUCCESS: Found {len(localhostresult['open_ports'])} open ports on localhost")
        else:
            print("NOTE: No open ports found on localhost. This is normal if you're not running any services.")

        return True
    except Exception as e:
        print(f"ERROR scanning localhost: {e}")
        traceback.print_exc()
        return False

def testgateway(gateway):
    print(f"\n=== Testing gateway scan ({gateway}) ===")

    try:
        print(f"Scanning gateway ({gateway})...")
        starttime = time.time()
        gwresult = scan_target(gateway, "22,80,443,8080,53")
        scantime = time.time() - starttime

        print(f"Scan completed in {scantime:.2f} seconds")
        print(format_results_table([gwresult]))

        if gwresult["status"] in ["up", "up (ICMP)"]:
            print(f"SUCCESS: Gateway is up")

            if gwresult.get("open_ports"):
                print(f"SUCCESS: Found {len(gwresult['open_ports'])} open ports on gateway")
            else:
                print("NOTE: No open ports found on gateway. This might be due to firewall restrictions.")

            return True
        else:
            print(f"WARNING: Gateway appears to be down or not responding")
            return False
    except Exception as e:
        print(f"ERROR scanning gateway: {e}")
        traceback.print_exc()
        return False

def main():
    print("Network Scanner Test Script")
    print("==========================")
    print("This script will test basic functionality of the Network Scanner.")
    print("It will scan localhost and attempt to scan your default gateway.")
    print("\nStarting tests...")

    localhostsuccess = testlocalhost()

    gateway = getgateway()
    gwsuccess = False

    if gateway:
        gwsuccess = testgateway(gateway)
    else:
        print("\nCould not determine default gateway. Skipping gateway test.")

    print("\n=== Test Summary ===")
    print(f"Localhost scan: {'SUCCESS' if localhostsuccess else 'FAILED'}")
    if gateway:
        print(f"Gateway scan: {'SUCCESS' if gwsuccess else 'FAILED'}")
    else:
        print("Gateway scan: SKIPPED")

    if localhostsuccess or gwsuccess:
        print("\nAt least one test was successful! The scanner is working.")
        print("You can now try the full application with:")
        print("  python main.py")
    else:
        print("\nAll tests failed. There might be issues with your network configuration or permissions.")
        print("Make sure you're running the script with sufficient privileges (sudo on Linux).")
        print("Try running the full application with specific targets:")
        print("  sudo python main.py --cli 127.0.0.1 -p 80,443,22,8080")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)
