from collections import defaultdict
import statistics
import time
import traceback
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from backend.utils.validate_ip_chksum import *
from backend.utils.flow_utilities import *
from backend.utils.protocol_field_builder import *

class TrafficAnalysis:
    """ """

    def __init__(self):
        """ CTOR for TrafficAnalysis class."""
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(self._new_flow_entry)
        self.flow_stats_dst = defaultdict(self._new_flow_entry)
    
    def _new_flow_entry(self):
        """ Create a new flow statistics entry with initialized fields."""

        return {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": None,
            "last_time": None,
            "flow_duration": None,
            "iat": [],
            "source_ip_count": defaultdict(int),
            "destination_ip_count": defaultdict(int),
            "source_port_count": defaultdict(int),
            "destination_port_count": defaultdict(int),
            "tcp_flags_count": {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0},
            "sequence_numbers": [],
            "window_sizes": [],
            "header_lengths": [],
            "checksum_errors": 0,
            "identification_fields": [],
            "tcp_header_sizes": [],
            "reserved_bits": [],
            "tcp_checksum_errors": 0,
        }
    
    def cleanup_old_dst_flows(self, max_age: int = 3):
        # dst gc
        keys_to_delete = []
        now = time.time()
        for key, flow in self.flow_stats_dst.items():
            if flow["last_time"] and now - flow["last_time"] > max_age:
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            del self.flow_stats_dst[key]
            
        return len(keys_to_delete)
                
    def cleanup_old_flows(self, timeout: int = 60) -> int:
        # gc
        keys_to_delete = []
        curr_time = time.time()
        for flow_key, flow_data in self.flow_stats.items():
            if flow_data["last_time"] and (curr_time - flow_data["last_time"] > timeout):
                keys_to_delete.append(flow_key)
                
        for key in keys_to_delete:
            del self.flow_stats[key]
            
        return len(keys_to_delete)

    def analyze_packet(self, packet: Packet):
        """
        Analyze a single network packet and update flow statistics accordingly.

        This function extracts key IP and TCP header fields from the packet,
        constructs a unique flow key, and updates flow-related metrics such as
        packet count, byte count, duration, TCP flag counts, sequence numbers,
        and checksums.

        Parameters:
            packet (Packet): A Scapy Packet object containing IP and TCP layers.

        Returns:
            dict: A dictionary of extracted features based on the analyzed packet
                    and current flow statistics.

        Raises:
            Exception: Logs any exception that occurs during packet analysis.
        """
        if packet is not None and packet.haslayer(IP) and packet.haslayer(TCP):
            try:
                ip_layer = packet[IP]
                tcp_layer = packet[TCP]
                
                ip_fields = build_ip_fields(packet)
                tcp_fields = build_tcp_fields(packet)
                
                conn_key = build_flow_key(ip_fields, tcp_fields)
                dst_key = build_dst_flow_key(ip_fields, tcp_fields,timestamp=packet.time)

                conn_flow = self.flow_stats[conn_key]
                dst_flow = self.flow_stats_dst[dst_key]
                current_time = packet.time
                
                raw_ip_bytes = bytes(packet[IP])[:20]
                is_chksum_valid = validate_ip_checksum(raw_ip_bytes)

                for flow_data in (conn_flow, dst_flow):
                    # Time Updates
                    if flow_data["start_time"] is None:
                        flow_data["start_time"] = current_time
                    
                    if flow_data["last_time"] is not None:
                        delta = float(current_time - flow_data["last_time"])
                        if delta >= 0:
                            flow_data["iat"].append(delta)

                    flow_data["last_time"] = current_time
                    flow_data["flow_duration"] = float(current_time - flow_data["start_time"])
                    
                    # Volume Updates
                    flow_data["packet_count"] += 1
                    flow_data["byte_count"] += ip_fields["packet_length"]
                    
                    # Diversity Updates
                    flow_data["source_ip_count"][ip_fields["source_ip"]] += 1
                    flow_data["destination_ip_count"][ip_fields["destination_ip"]] += 1
                    flow_data["source_port_count"][tcp_fields["source_port"]] += 1
                    flow_data["destination_port_count"][tcp_fields["destination_port"]] += 1
                    
                    if not is_chksum_valid:
                        flow_data["checksum_errors"] += 1
                    
                    # Flag Updates (Critical for SYN Flood detection)
                    flags = tcp_fields["tcp_flags"]
                    if flags & 0x02: flow_data["tcp_flags_count"]["SYN"] += 1
                    if flags & 0x10: flow_data["tcp_flags_count"]["ACK"] += 1
                    if flags & 0x01: flow_data["tcp_flags_count"]["FIN"] += 1
                    if flags & 0x04: flow_data["tcp_flags_count"]["RST"] += 1

                # Track Sequence/Window only for the specific pair to detect hijacking/confusion
                conn_flow["sequence_numbers"].append(tcp_layer.seq)
                conn_flow["window_sizes"].append(tcp_layer.window)
                conn_flow["header_lengths"].append(ip_layer.ihl * 4)
                conn_flow["tcp_header_sizes"].append(tcp_layer.dataofs * 4)
                conn_flow["reserved_bits"].append(tcp_layer.reserved)

                micro_feat = self.extract_features(packet,conn_flow)
                macro_feat = self.extract_features(packet, dst_flow)
                
                return {
                    "micro": micro_feat,
                    "macro": macro_feat
                }

            except Exception:
                traceback.print_exc()

    def extract_features(self, packet: Packet, stats):
        """
        Extract statistical and protocol-based features from a network packet and its flow data.

        Computes various metrics such as packet and byte rates, TCP flag counts, average
        sequence numbers, header sizes, IP/port diversity, and checksum or reserved bit errors.

        Parameters:
            packet (Packet): A Scapy Packet object containing IP and TCP layers.
            stats (dict): A dictionary containing current statistics for the corresponding flow.

        Returns:
            dict: A dictionary of computed features for the given packet and flow.

        Raises:
            Exception: Logs any exception that occurs during feature extraction.
        """
        try:
            duration = stats["flow_duration"]
            if duration and duration > 0.000001:
                packet_rate = stats["packet_count"] / duration
                byte_rate = stats["byte_count"] / duration
            else:
                packet_rate = 0.0
                byte_rate = 0.0

            iat_list = stats["iat"]
            if iat_list:
                min_iat = min(iat_list)
                max_iat = max(iat_list)
                avg_iat = sum(iat_list) / len(iat_list)
                std_iat = statistics.stdev(iat_list) if len(iat_list) > 1 else 0.0
            else:
                min_iat = max_iat = avg_iat = std_iat = 0.0
            if packet:
                current_pkt_size = len(packet)
                current_win_size = packet[TCP].window if packet.haslayer(TCP) else 0
            else:
                current_pkt_size = stats["byte_count"] / stats["packet_count"] if stats["packet_count"] else 0
                current_win_size = stats["window_sizes"][-1] if stats["window_sizes"] else 0

            features = {
                # Basic features
                "packet_count": stats["packet_count"],
                "packet_size": current_pkt_size,
                "flow_duration": duration,

                # Normalized counters
                "packet_rate": packet_rate,
                "byte_rate": byte_rate,
                # TCP window size (last seen)
                "latest_window_size": current_win_size,
                # Flag counts
                "syn_count": stats["tcp_flags_count"].get("SYN", 0),
                "ack_count": stats["tcp_flags_count"].get("ACK", 0),
                "fin_count": stats["tcp_flags_count"].get("FIN", 0),
                "rst_count": stats["tcp_flags_count"].get("RST", 0),
                # IAT stats
                "min_iat": min_iat,
                "max_iat": max_iat,
                "avg_iat": avg_iat,
                "std_iat": std_iat,
                # Sequence and window statistics
                "avg_sequence_number": (
                    sum(stats["sequence_numbers"]) / len(stats["sequence_numbers"])
                    if stats["sequence_numbers"]
                    else 0
                ),
                "avg_window_size": (
                    sum(stats["window_sizes"]) / len(stats["window_sizes"])
                    if stats["window_sizes"]
                    else 0
                ),
                # Header statistics
                "avg_ip_header_length": (
                    sum(stats["header_lengths"]) / len(stats["header_lengths"])
                    if stats["header_lengths"]
                    else 0
                ),
                "avg_tcp_header_size": (
                    sum(stats["tcp_header_sizes"]) / len(stats["tcp_header_sizes"])
                    if stats["tcp_header_sizes"]
                    else 0
                ),
                # Port/IP diversity
                "unique_src_ips": len(stats["source_ip_count"]),
                "unique_dst_ips": len(stats["destination_ip_count"]),
                "unique_src_ports": len(stats["source_port_count"]),
                "unique_dst_ports": len(stats["destination_port_count"]),
                # Errors
                "ip_checksum_errors": stats["checksum_errors"],
                "tcp_checksum_errors": stats["tcp_checksum_errors"],
                # Reserved bits stats
                "reserved_bit_set_count": sum(
                    1 for b in stats["reserved_bits"] if b != 0
                ),
            }
            return features

        except Exception as e:
            print(f"[Extract Error] {e}")
            return {}
