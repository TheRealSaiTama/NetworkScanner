#!/usr/bin/env python3
"""
Simple test script for the Network Scanner.
This script performs a basic scan of localhost and the default gateway.
"""

import sys
import os
import socket
import time
import traceback

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner import scan_target, arp_scan
from src.utils import format_results_table

def get_default_gateway():
    """Get the default gateway IP address."""
    print("Trying to determine default gateway...")

    # Method 1: Using socket connection
    try:
        # Create a socket that doesn't connect to anything
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Try to connect to an external IP (doesn't actually send anything)
        s.connect(("8.8.8.8", 80))
        # Get the local IP address assigned to the socket
        local_ip = s.getsockname()[0]
        s.close()

        # Guess the gateway from the local IP
        gateway = ".".join(local_ip.split(".")[:3]) + ".1"
        print(f"Local IP: {local_ip}, Possible gateway: {gateway}")
        return gateway
    except Exception as e:
        print(f"Error determining gateway via socket: {e}")

    # Method 2: Common gateway addresses
    common_gateways = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "192.168.2.1"]
    for gateway in common_gateways:
        print(f"Trying common gateway: {gateway}")
        try:
            # Try to connect to the gateway on port 80 (common for router web interfaces)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((gateway, 80))
            s.close()
            if result == 0:
                print(f"Found potential gateway at {gateway}")
                return gateway
        except Exception as e:
            print(f"Error checking {gateway}: {e}")

    # Method 3: Try ARP scan to find devices
    try:
        print("Trying ARP scan to find devices...")
        for subnet in ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]:
            print(f"Scanning subnet {subnet}...")
            results = arp_scan(subnet)
            if results:
                print(f"Found {len(results)} devices via ARP")
                # Look for potential gateways
                for device in results:
                    ip = device["ip"]
                    if ip.endswith(".1") or ip.endswith(".254"):
                        print(f"Found potential gateway: {ip}")
                        return ip
    except Exception as e:
        print(f"Error during ARP scan: {e}")

    print("Could not determine gateway")
    return None

def test_localhost():
    """Test scanning localhost."""
    print("\n=== Testing localhost scan ===")

    try:
        print("Scanning localhost (127.0.0.1)...")
        start_time = time.time()
        localhost_result = scan_target("127.0.0.1", "22,80,443,8080,3000,3306,5432")
        scan_time = time.time() - start_time

        print(f"Scan completed in {scan_time:.2f} seconds")
        print(format_results_table([localhost_result]))

        # Check if any ports were found
        if localhost_result.get("open_ports"):
            print(f"SUCCESS: Found {len(localhost_result['open_ports'])} open ports on localhost")
        else:
            print("NOTE: No open ports found on localhost. This is normal if you're not running any services.")

        return True
    except Exception as e:
        print(f"ERROR scanning localhost: {e}")
        traceback.print_exc()
        return False

def test_gateway(gateway):
    """Test scanning the gateway."""
    print(f"\n=== Testing gateway scan ({gateway}) ===")

    try:
        print(f"Scanning gateway ({gateway})...")
        start_time = time.time()
        gateway_result = scan_target(gateway, "22,80,443,8080,53")
        scan_time = time.time() - start_time

        print(f"Scan completed in {scan_time:.2f} seconds")
        print(format_results_table([gateway_result]))

        # Check if the gateway is up
        if gateway_result["status"] in ["up", "up (ICMP)"]:
            print(f"SUCCESS: Gateway is up")

            # Check if any ports were found
            if gateway_result.get("open_ports"):
                print(f"SUCCESS: Found {len(gateway_result['open_ports'])} open ports on gateway")
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
    """Run a simple test scan."""
    print("Network Scanner Test Script")
    print("==========================")
    print("This script will test basic functionality of the Network Scanner.")
    print("It will scan localhost and attempt to scan your default gateway.")
    print("\nStarting tests...")

    # Test 1: Scan localhost
    localhost_success = test_localhost()

    # Test 2: Try to scan the default gateway
    gateway = get_default_gateway()
    gateway_success = False

    if gateway:
        gateway_success = test_gateway(gateway)
    else:
        print("\nCould not determine default gateway. Skipping gateway test.")

    # Summary
    print("\n=== Test Summary ===")
    print(f"Localhost scan: {'SUCCESS' if localhost_success else 'FAILED'}")
    if gateway:
        print(f"Gateway scan: {'SUCCESS' if gateway_success else 'FAILED'}")
    else:
        print("Gateway scan: SKIPPED")

    if localhost_success or gateway_success:
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