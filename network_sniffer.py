#!/usr/bin/env python3
"""
Network Packet Sniffer
A minimal network packet sniffer tool using Scapy
"""
import argparse
import sys
import os
import platform
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: Scapy library not found.")
    print("Please install it using: pip install scapy")
    sys.exit(1)

def is_admin():
    """
    Cross-platform function to check for administrator/root privileges
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            # Unix-like systems (Linux, macOS)
            return os.geteuid() == 0
    except Exception:
        return False

def packet_callback(packet):
    """
    Callback function to process captured packets
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine protocol type
        if protocol == 6:  # TCP
            proto_name = "TCP"
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                print(f"[{timestamp}] {proto_name}: {ip_src}:{sport} -> {ip_dst}:{dport}")
            else:
                print(f"[{timestamp}] {proto_name}: {ip_src} -> {ip_dst}")
                
        elif protocol == 17:  # UDP
            proto_name = "UDP"
            if UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                print(f"[{timestamp}] {proto_name}: {ip_src}:{sport} -> {ip_dst}:{dport}")
            else:
                print(f"[{timestamp}] {proto_name}: {ip_src} -> {ip_dst}")
                
        elif protocol == 1:  # ICMP
            proto_name = "ICMP"
            print(f"[{timestamp}] {proto_name}: {ip_src} -> {ip_dst}")
            
        else:
            print(f"[{timestamp}] OTHER(proto={protocol}): {ip_src} -> {ip_dst}")

def verbose_packet_callback(packet):
    """
    Verbose packet callback with more details
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{timestamp}] " + "="*50)
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"IP: {ip_layer.src} -> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        print(f"TTL: {ip_layer.ttl}")
        print(f"Length: {ip_layer.len}")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP: {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"Flags: {tcp_layer.flags}")
            print(f"Seq: {tcp_layer.seq}, Ack: {tcp_layer.ack}")
            
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP: {udp_layer.sport} -> {udp_layer.dport}")
            print(f"Length: {udp_layer.len}")
            
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"ICMP: Type {icmp_layer.type}, Code {icmp_layer.code}")
    
    print("Raw packet:")
    print(packet.summary())

def save_packet_to_file(packet, output_file):
    """
    Save packet information to a file
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(output_file, 'a') as f:
        f.write(f"[{timestamp}] {packet.summary()}\n")
        
        if IP in packet:
            ip_layer = packet[IP]
            f.write(f"  IP: {ip_layer.src} -> {ip_layer.dst}\n")
            f.write(f"  Protocol: {ip_layer.proto}\n")
            
            if TCP in packet:
                tcp_layer = packet[TCP]
                f.write(f"  TCP: {tcp_layer.sport} -> {tcp_layer.dport}\n")
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                f.write(f"  UDP: {udp_layer.sport} -> {udp_layer.dport}\n")
        
        f.write("\n")

def create_filter_string(protocol):
    """
    Create BPF filter string based on protocol
    """
    if protocol:
        protocol = protocol.lower()
        if protocol in ['tcp', 'udp', 'icmp']:
            return protocol
        else:
            print(f"Warning: Unknown protocol '{protocol}'. Capturing all packets.")
            return None
    return None

def main():
    parser = argparse.ArgumentParser(description='Network Packet Sniffer using Scapy')
    parser.add_argument('-i', '--interface', type=str, help='Network interface to sniff on')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture (default: unlimited)')
    parser.add_argument('-p', '--protocol', type=str, choices=['tcp', 'udp', 'icmp'], 
                       help='Protocol to filter (tcp, udp, icmp)')
    parser.add_argument('-o', '--output', type=str, help='Output file to save captured packets')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output mode')
    
    args = parser.parse_args()
    
    # Check for administrator/root privileges (cross-platform)
    if not is_admin():
        if platform.system() == "Windows":
            print("Error: This script requires administrator privileges to capture packets.")
            print("Please run as administrator: Right-click Command Prompt/PowerShell -> 'Run as administrator'")
            print("Then run: python network_sniffer.py")
        else:
            print("Error: This script requires root privileges to capture packets.")
            print("Please run with sudo: sudo python3 network_sniffer.py")
        sys.exit(1)
    
    print("Network Packet Sniffer")
    print("=======================")
    print(f"Interface: {args.interface if args.interface else 'auto-detect'}")
    print(f"Protocol filter: {args.protocol if args.protocol else 'all'}")
    print(f"Packet count: {args.count if args.count else 'unlimited'}")
    print(f"Output file: {args.output if args.output else 'console only'}")
    print(f"Verbose mode: {'enabled' if args.verbose else 'disabled'}")
    print("\nStarting packet capture... Press Ctrl+C to stop\n")
    
    # Create filter string
    filter_str = create_filter_string(args.protocol)
    
    try:
        # Determine callback function
        if args.output:
            # Create output file callback
            def file_callback(packet):
                save_packet_to_file(packet, args.output)
                if args.verbose:
                    verbose_packet_callback(packet)
                else:
                    packet_callback(packet)
            callback_func = file_callback
        else:
            callback_func = verbose_packet_callback if args.verbose else packet_callback
        
        # Start packet capture
        sniff(
            iface=args.interface,
            filter=filter_str,
            prn=callback_func,
            count=args.count
        )
        
    except KeyboardInterrupt:
        print("\n\nPacket capture stopped by user.")
        if args.output:
            print(f"Captured packets saved to: {args.output}")
            
    except Exception as e:
        print(f"Error during packet capture: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
