"""
Module: Simple Detector
Purpose: Applies basic rules to flow stats to detect anomalies.
"""

class SimpleDetector:
    def __init__(self):
        self.alerts = []

    def check_flow(self, flow_key, stats):
        src, dst, port = flow_key
        alerts = []

        # Rule 1: SYN Flood Detection
        # High SYN count but low ACK count implies scanning or flooding
        syn_count = stats["flags"].get("S", 0)
        ack_count = stats["flags"].get("A", 0)

        if syn_count > 10 and ack_count < 2:
            msg = f"[!] ALERT: Possible SYN Flood from {src} -> {dst}:{port} (SYN={syn_count})"
            alerts.append(msg)

        # Rule 2: Heavy Traffic
        if stats["packet_count"] > 100:
            msg = f"[!] INFO: Heavy Flow Detected {src} -> {dst} ({stats['packet_count']} pkts)"
            alerts.append(msg)

        return alerts