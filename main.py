#!/usr/bin/env python3
"""
Network Scanner - Main entry point

This script serves as the main entry point for the Network Scanner application.
It provides options to launch either the CLI or GUI version.
"""

import sys
import os
import argparse

def main():
    """Main function to start the application."""
    parser = argparse.ArgumentParser(
        description="Network Scanner - Discover devices and open ports on your network",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--cli", 
        action="store_true",
        help="Launch the command-line interface"
    )
    parser.add_argument(
        "--gui", 
        action="store_true",
        help="Launch the graphical user interface"
    )
    
    # Pass remaining arguments to the CLI
    parser.add_argument(
        "cli_args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to the CLI (if --cli is used)"
    )
    
    args = parser.parse_args()
    
    # If no interface is specified, default to GUI
    if not args.cli and not args.gui:
        args.gui = True
    
    # Launch the appropriate interface
    if args.cli:
        from src.cli import main as cli_main
        sys.argv = [sys.argv[0]] + args.cli_args
        cli_main()
    elif args.gui:
        try:
            from src.gui import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"Error: {e}")
            print("GUI dependencies might be missing. Install them with:")
            print("pip install -r requirements.txt")
            sys.exit(1)

if __name__ == "__main__":
    # Add the current directory to the path so we can import our modules
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    
    try:
        main()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)