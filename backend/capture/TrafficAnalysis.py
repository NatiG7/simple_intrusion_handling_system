from collections import defaultdict
import statistics
import time
import traceback
from collections import deque
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from backend.utils.validate_ip_chksum import *
from backend.utils.flow_utilities import *
from backend.utils.protocol_field_builder import *
from backend.utils.fast_packet_parse import parse_packet_fast

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
            "iat": deque(maxlen=50),
            "source_ip_count": defaultdict(int),
            "destination_ip_count": defaultdict(int),
            "source_port_count": defaultdict(int),
            "destination_port_count": defaultdict(int),
            "tcp_flags_count": {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0},
            "sequence_numbers": deque(maxlen=50),
            "window_sizes": deque(maxlen=50),
            "header_lengths": deque(maxlen=50),
            "checksum_errors": 0,
            "identification_fields": [],
            "tcp_header_sizes": deque(maxlen=50),
            "reserved_bits": deque(maxlen=50),
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

    def analyze_packet(self, packet_data, timestamp=None):
        """
        Modified to support FAST MODE (Raw Bytes) and LEGACY MODE (Scapy Objects).
        """
        ip_fields = None
        tcp_fields = None
        packet_obj = None # Will be None in Fast Mode

        try:
            # ==========================================
            #  BRANCH 1: FAST PATH (Raw Bytes)
            # ==========================================
            if isinstance(packet_data, bytes):
                current_time = timestamp if timestamp else time.time()
                
                # 1. Use Fast Parser
                ip_fields, tcp_fields, proto, ip_start = parse_packet_fast(packet_data)
                
                if ip_fields is None or tcp_fields is None:
                    return None 

                # 2. Slice Raw Bytes for Checksum (Fast)
                # Standard IP header check covers 20 bytes
                raw_ip_bytes = packet_data[ip_start : ip_start + 20] 
                
                # 3. Set Micro-Feature Variables directly from dict
                seq_num = tcp_fields['seq']
                win_size = tcp_fields['window']
                ip_ihl_bytes = ip_fields['header_length']
                tcp_dataofs_bytes = tcp_fields['dataofs']
                reserved = tcp_fields['reserved']
                
            # ==========================================
            #  BRANCH 2: SLOW PATH (Scapy Object)
            # ==========================================
            elif hasattr(packet_data, 'haslayer'):
                if not (packet_data.haslayer(IP) and packet_data.haslayer(TCP)):
                    return None
                
                current_time = packet_data.time
                packet_obj = packet_data # Keep reference for legacy extract
                
                # Use existing Scapy builders
                ip_fields = build_ip_fields(packet_data)
                tcp_fields = build_tcp_fields(packet_data)
                
                raw_ip_bytes = bytes(packet_data[IP])[:20]
                
                # Set variables from Scapy layers
                seq_num = packet_data[TCP].seq
                win_size = packet_data[TCP].window
                ip_ihl_bytes = packet_data[IP].ihl * 4
                tcp_dataofs_bytes = packet_data[TCP].dataofs * 4
                reserved = packet_data[TCP].reserved
            else:
                return None

            # ==========================================
            #  COMMON LOGIC (Shared by both)
            # ==========================================
            
            # 1. Build Keys
            conn_key = build_flow_key(ip_fields, tcp_fields)
            # Ensure we pass the timestamp so offline analysis works
            dst_key = build_dst_flow_key(ip_fields, tcp_fields, timestamp=current_time)

            conn_flow = self.flow_stats[conn_key]
            dst_flow = self.flow_stats_dst[dst_key]
            
            is_chksum_valid = True

            # 2. Update Flows
            for flow_data in (conn_flow, dst_flow):
                if flow_data["start_time"] is None:
                    flow_data["start_time"] = current_time
                
                if flow_data["last_time"] is not None:
                    delta = float(current_time - flow_data["last_time"])
                    if delta >= 0:
                        flow_data["iat"].append(delta)

                flow_data["last_time"] = current_time
                flow_data["flow_duration"] = float(current_time - flow_data["start_time"])
                
                flow_data["packet_count"] += 1
                flow_data["byte_count"] += ip_fields["packet_length"]
                
                flow_data["source_ip_count"][ip_fields["source_ip"]] += 1
                flow_data["destination_ip_count"][ip_fields["destination_ip"]] += 1
                flow_data["source_port_count"][tcp_fields["source_port"]] += 1
                flow_data["destination_port_count"][tcp_fields["destination_port"]] += 1
                
                if not is_chksum_valid:
                    flow_data["checksum_errors"] += 1
                
                # Flag Updates
                flags = tcp_fields["tcp_flags"]
                if flags & 0x02: flow_data["tcp_flags_count"]["SYN"] += 1
                if flags & 0x10: flow_data["tcp_flags_count"]["ACK"] += 1
                if flags & 0x01: flow_data["tcp_flags_count"]["FIN"] += 1
                if flags & 0x04: flow_data["tcp_flags_count"]["RST"] += 1

            # 3. Micro-Only Updates (Using the variables we set in the Branches)
            conn_flow["sequence_numbers"].append(seq_num)
            conn_flow["window_sizes"].append(win_size)
            conn_flow["header_lengths"].append(ip_ihl_bytes)
            conn_flow["tcp_header_sizes"].append(tcp_dataofs_bytes)
            conn_flow["reserved_bits"].append(reserved)

            # 4. Extract Features
            # Note: packet_obj will be None in Fast Mode.
            # Your extract_features function ALREADY handles None gracefully.
            micro_features = self.extract_features(packet_obj, conn_flow)
            macro_features = self.extract_features(packet_obj, dst_flow)

            return {
                "micro": micro_features,
                "macro": macro_features
            }

        except Exception:
            traceback.print_exc()
            return None

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
            len_iat = len(iat_list)
            if len_iat > 1:
                min_iat = min(iat_list)
                max_iat = max(iat_list)
                avg_iat = sum(iat_list) / len(iat_list)
                std_iat = statistics.stdev(iat_list)
            else:
                min_iat = max_iat = avg_iat = std_iat = 0.0
            if packet:
                current_pkt_size = len(packet)
                current_win_size = packet[TCP].window if packet.haslayer(TCP) else 0
            else:
                current_pkt_size = stats["byte_count"] / stats["packet_count"] if stats["packet_count"] else 0
                current_win_size = stats["window_sizes"][-1] if stats["window_sizes"] else 0
            def safe_avg(deque_obj):
                return sum(deque_obj) / len(deque_obj) if deque_obj else 0
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
                "avg_sequence_number": safe_avg(stats["sequence_numbers"]),
                "avg_window_size": safe_avg(stats["window_sizes"]),
                # Header statistics1
                "avg_ip_header_length": safe_avg(stats["header_lengths"]),
                "avg_tcp_header_size": safe_avg(stats["tcp_header_sizes"]),
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
