"""
Module: Sniffer Core
Purpose: Wraps Scapy's sniff functionality and provides packet dissection.
"""
from scapy.all import sniff
from scapy.layers.inet import IP, TCP

def start_sniffing(interface=None, count=0, prn_callback=None, filter_exp="ip"):
    """Starts the capture loop."""
    print(f"[*] Starting Sniffer on {interface if interface else 'default'}...")
    # count=0 means infinite
    sniff(iface=interface, filter=filter_exp, prn=prn_callback, count=count)

def dissect_packet(packet):
    """Returns a simplified dict of the packet's layers."""
    data = {}
    
    if packet.haslayer(IP):
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst
        data["len"] = packet[IP].len
    
    if packet.haslayer(TCP):
        data["proto"] = "TCP"
        data["sport"] = packet[TCP].sport
        data["dport"] = packet[TCP].dport
        data["flags"] = packet[TCP].flags
        data["seq"] = packet[TCP].seq
    else:
        data["proto"] = "OTHER"
        
    return data