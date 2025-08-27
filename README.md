# Network Sniffer Python

A simple Python-based network packet sniffer tool designed for educational cybersecurity purposes. This tool allows B.Tech CSE students to understand network traffic analysis and packet capture techniques.

## Description

This project provides a command-line network sniffer that captures and analyzes network packets in real-time. It's designed to help cybersecurity students learn about network protocols, traffic analysis, and packet inspection techniques.

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
- Required Python packages:
  - `scapy`
  - `argparse`
  - `datetime`

## Installation

1. Clone the repository:
```bash
git clone https://github.com/hadhiabdulla/Network-Sniffer-Python.git
cd Network-Sniffer-Python
```

2. Install required dependencies:
```bash
pip install scapy
```

## Usage

### Basic Usage

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

### Command Line Options

- `-i, --interface`: Network interface to sniff (default: auto-detect)
- `-c, --count`: Number of packets to capture (default: unlimited)
- `-p, --protocol`: Protocol filter (tcp, udp, icmp)
- `-o, --output`: Output file to save captured packets
- `-v, --verbose`: Verbose output mode

### Example Commands

```bash
# Capture 50 TCP packets and save to file
sudo python3 network_sniffer.py -p tcp -c 50 -o captured_packets.txt

# Verbose mode with UDP filtering
sudo python3 network_sniffer.py -p udp -v
```

## File Structure

```
Network-Sniffer-Python/
├── network_sniffer.py      # Main sniffer script
├── packet_analyzer.py      # Packet analysis utilities
├── utils.py               # Helper functions
├── README.md              # This file
├── requirements.txt       # Python dependencies
└── examples/              # Example usage scripts
    └── basic_sniff.py     # Basic usage example
```

## Educational Purpose

This tool is created for educational purposes to help students understand:

- Network packet structure
- Protocol analysis techniques
- Traffic monitoring concepts
- Cybersecurity fundamentals
- Ethical hacking basics

## Important Notes

⚠️ **Legal and Ethical Use Only**

- This tool should only be used on networks you own or have explicit permission to monitor
- Always comply with local laws and regulations
- Use responsibly for educational and authorized testing purposes only
- Unauthorized network monitoring may be illegal in your jurisdiction

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is open source and available under the MIT License.

## Disclaimer

This software is provided for educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Users are responsible for complying with all applicable laws and regulations.

## Contact

For questions or support, please open an issue on GitHub.

---

**Note:** This project is designed for B.Tech Computer Science Engineering students specializing in Cybersecurity. Always practice ethical hacking and follow responsible disclosure principles.
