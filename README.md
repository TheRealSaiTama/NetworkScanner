# Network Scanner

A comprehensive network scanner application for discovering devices, identifying MAC addresses, and detecting open ports within specified IP ranges. Built with Python and Scapy, this tool provides both command-line and graphical interfaces for network discovery and security assessment.

![Network Scanner](https://raw.githubusercontent.com/TheRealSaiTama/NetworkScanner/main/image.png)

## ✨ Features

- **🔍 Host Discovery**: Uses ARP and ICMP scanning to find active devices
- **🚪 Port Scanning**: Performs TCP SYN scans to detect open ports
- **⚡ Parallel Scanning**: Multi-threading for fast scanning of large networks
- **🔖 Service Identification**: Identifies common services on open ports
- **📊 Visualization**: Network topology and port distribution graphs
- **💾 Export Options**: Save results as CSV or JSON
- **📂 Session Management**: Save and load scan sessions for later analysis

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- Scapy library
- Network privileges (sudo/admin)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/TheRealSaiTama/NetworkScanner.git
cd NetworkScanner

# Install dependencies
pip install -r requirements.txt

# Linux/macOS: Set capabilities (alternative to running with sudo)
sudo setcap cap_net_raw+ep $(which python3)

# Windows: Install Npcap from https://npcap.com/
```

## 📋 Usage

### Command-Line Interface

```bash
python main.py --cli <ip_range> [options]
```

Options:
- `-p, --ports`: Port ranges (e.g., "22,80,1-1024")
- `-t, --threads`: Threads for parallel scanning
- `-o, --output`: Output filename
- `--format`: Output format (csv, json, both)
- `-s, --sort`: Sort by (ip, mac, ports)
- `-f, --filter`: Filter results
- `--common-ports`: Use predefined common ports
- `-v, --verbose`: Detailed output

Example:
```bash
python main.py --cli 192.168.1.0/24 -p 22,80,443 -t 20 -o scan_results
```

### Graphical Interface

```bash
python main.py --gui
# or simply
python main.py
```

## 🧪 Testing

Run basic tests to verify functionality:

```bash
python test_scan.py  # Test basic scanning functionality
python test_gui.py   # Test GUI components
```

## 📁 Project Structure

```
NetworkScanner/
├── src/               # Core source code
│   ├── scanner.py     # Scanning implementation
│   ├── utils.py       # Helper functions
│   ├── cli.py         # Command-line interface
│   └── gui.py         # Graphical interface
├── results/           # Scan results storage
├── main.py            # Entry point
├── test_scan.py       # Scanner tests
├── test_gui.py        # GUI tests
├── requirements.txt   # Dependencies
└── README.md          # Documentation
```

## ⚠️ Security Notice

This tool is intended for legitimate network administration and security testing. Unauthorized scanning of networks may be illegal. Always:

1. Get proper authorization before scanning any network
2. Be aware of scanning impact on network performance
3. Follow responsible disclosure practices for any vulnerabilities discovered

## 📄 License

[MIT License](https://github.com/TheRealSaiTama/NetworkScanner/blob/main/LICENSE)

## 🔗 Connect

- GitHub: [TheRealSaiTama](https://github.com/TheRealSaiTama)
- Report Issues: [GitHub Issues](https://github.com/TheRealSaiTama/NetworkScanner/issues)

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) for packet manipulation
- [Matplotlib](https://matplotlib.org/) for visualization
- [NetworkX](https://networkx.org/) for network topology graphs
