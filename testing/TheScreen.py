"""
Module: Dashboard Logger
Purpose: Pretty-prints packet and flow data to the console.
"""
from colorama import Fore, Style, init
init(autoreset=True)

def log_packet(data):
    """Prints raw packet details (The Microscope Showcase)."""
    if data["proto"] == "TCP":
        print(f"{Fore.CYAN}[PKT] {data['src_ip']}:{data['sport']} -> {data['dst_ip']}:{data['dport']} | Flags: {data['flags']}")
    else:
        print(f"{Fore.WHITE}[PKT] {data['proto']} Packet detected")

def log_flow_update(key, stats):
    """Prints flow stats (The Analyzer Showcase)."""
    src, dst, port = key
    print(f"{Fore.YELLOW}--- Flow Update [{src} -> {dst}:{port}] ---")
    print(f"    Pkts: {stats['packet_count']} | Bytes: {stats['byte_count']}")
    print(f"    Flags: {dict(stats['flags'])}")

def log_alert(message):
    """Prints alerts (The Detector Showcase)."""
    print(f"{Fore.RED}{Style.BRIGHT}{message}{Style.RESET_ALL}")