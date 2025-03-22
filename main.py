#!/usr/bin/env python3

import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner - Discover devices and open ports on your network",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("--cli", action="store_true", help="Launch the command-line interface")
    parser.add_argument("--gui", action="store_true", help="Launch the graphical user interface")
    parser.add_argument("cliargs", nargs=argparse.REMAINDER, help="Arguments to pass to the CLI")
    
    args = parser.parse_args()
    
    if not args.cli and not args.gui:
        args.gui = True
    
    if args.cli:
        from src.cli import main as climain
        sys.argv = [sys.argv[0]] + args.cliargs
        climain()
    elif args.gui:
        try:
            from src.gui import main as guimain
            guimain()
        except ImportError as e:
            print(f"Error: {e}")
            print("GUI dependencies might be missing. Install them with:")
            print("pip install -r requirements.txt")
            sys.exit(1)

if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    
    try:
        main()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
