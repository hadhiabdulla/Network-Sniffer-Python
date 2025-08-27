# Network Sniffer Python

A Python-based network packet sniffer tool for network traffic analysis and packet capture.

## Description

This project provides a command-line network sniffer that captures and analyzes network packets in real-time using the Scapy library.

## Features

- Real-time packet capture
- Protocol analysis (TCP, UDP, ICMP)
- Source and destination IP filtering
- Packet header inspection
- Traffic statistics display
- Export captured data to files

## Requirements

- Python 3.7+
- Root/Administrator privileges (required for packet capture)
- scapy library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/hadhiabdulla/Network-Sniffer-Python.git
cd Network-Sniffer-Python
```

2. Install scapy:
```bash
pip install scapy
```

### Windows-Specific Setup

**For Windows users**, you may encounter libpcap/Npcap warnings. To resolve this:

1. Install Npcap (recommended) or WinPcap:
   - Download Npcap from: https://npcap.com/#download
   - During installation, make sure to check "Install Npcap in WinPcap API-compatible Mode"

2. If you still get warnings about missing libpcap, you can install an alternative:
   ```bash
   pip install scapy[complete]
   ```

## Usage

### Running with Administrator/Root Privileges

**On Linux/macOS:**
```bash
# Run with default settings (requires root privileges)
sudo python3 network_sniffer.py

# Capture packets on specific interface
sudo python3 network_sniffer.py -i eth0

# Filter by protocol
sudo python3 network_sniffer.py -p tcp

# Capture specific number of packets
sudo python3 network_sniffer.py -c 100
```

**On Windows:**
```cmd
# Open Command Prompt or PowerShell as Administrator
# Right-click -> "Run as administrator"

# Run with default settings
python network_sniffer.py

# Capture packets on specific interface
python network_sniffer.py -i "Ethernet"

# Filter by protocol
python network_sniffer.py -p tcp

# Capture specific number of packets
python network_sniffer.py -c 100
```

### Command Line Options

- `-i, --interface`: Network interface to sniff (default: auto-detect)
- `-c, --count`: Number of packets to capture (default: unlimited)
- `-p, --protocol`: Protocol filter (tcp, udp, icmp)
- `-o, --output`: Output file to save captured packets
- `-v, --verbose`: Verbose output mode

### Example Commands

**Linux/macOS:**
```bash
# Capture 50 TCP packets and save to file
sudo python3 network_sniffer.py -p tcp -c 50 -o captured_packets.txt

# Verbose mode with UDP filtering
sudo python3 network_sniffer.py -p udp -v
```

**Windows (as Administrator):**
```cmd
# Capture 50 TCP packets and save to file
python network_sniffer.py -p tcp -c 50 -o captured_packets.txt

# Verbose mode with UDP filtering
python network_sniffer.py -p udp -v
```

## File Structure

```
Network-Sniffer-Python/
├── network_sniffer.py      # Main sniffer script
├── README.md              # This file
└── .gitignore             # Git ignore file
```

## Platform Compatibility

This tool now supports cross-platform operation:

- **Linux**: Uses standard `sudo` for root privileges
- **macOS**: Uses standard `sudo` for root privileges  
- **Windows**: Automatically detects admin privileges using Windows API

The script will automatically detect your platform and provide appropriate error messages if administrator/root privileges are not available.

## Important Notes

⚠️ **Legal and Ethical Use Only**

- This tool should only be used on networks you own or have explicit permission to monitor
- Always comply with local laws and regulations
- Use responsibly for authorized testing purposes only
- Unauthorized network monitoring may be illegal in your jurisdiction

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is open source and available under the MIT License.

## Disclaimer

This software is provided as-is. The authors are not responsible for any misuse or damage caused by this program. Users are responsible for complying with all applicable laws and regulations.

## Contact

For questions or support, please open an issue on GitHub.
