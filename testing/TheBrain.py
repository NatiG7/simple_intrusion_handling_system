"""
Module: Flow Analyzer
Purpose: Aggregates single packets into 'Flow' statistics.
"""
from collections import defaultdict

class FlowAnalyzer:
    def __init__(self):
        # Key: (SrcIP, DstIP, DstPort) -> Value: Stats Dict
        self.flows = {}

    def process_packet(self, packet_data):
        if packet_data["proto"] != "TCP":
            return None

        # Create a unique key for this connection
        flow_key = (packet_data["src_ip"], packet_data["dst_ip"], packet_data["dport"])

        # Initialize if new
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                "packet_count": 0,
                "byte_count": 0,
                "flags": defaultdict(int)
            }

        # Update stats
        stats = self.flows[flow_key]
        stats["packet_count"] += 1
        stats["byte_count"] += packet_data["len"]
        
        # Count flags (S=2, A=16, P=8, etc)
        # Simplified: Check string representation from Scapy
        flags_str = str(packet_data["flags"]) 
        for char in flags_str:
            stats["flags"][char] += 1

        return flow_key, stats