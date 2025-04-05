from collections import defaultdict

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class TrafficAnalysis:
    """ """

    def __init__(self):

        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(
            lambda: {
                "packet_count": 0,
                "byte_count": 0,
                "start_time": None,
                "last_time": None,
                "flow_duration": None,
                "source_ip_count": {},
                "destination_ip_count": {},
                "source_port_count": {},
                "destination_port_count": {},
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
        )

    def analyze_packet(self, packet: Packet):
        if packet is not None and IP in packet and TCP in packet:
            try:

                # modular_structure #
                # ip_fields = build_ip_fields(packet)
                # tcp_fields = build_tcp_fields(packet)
                # flow_key = build_flow_key(ip_fields,tcp_fields)
                # end modular_structure #

                # TODO build functions. code too long
                # IP fields for analysis
                IP_version = packet[IP].version
                header_length = packet[IP].ihl * 4  # to bytes
                packet_length = packet[IP].len
                identification_field = packet[IP].id
                header_checksum = packet[IP].chksum
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst

                # TCP fields for analysis
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                sequence_number = packet[TCP].seq
                tcp_header_size = packet[TCP].dataofs * 4  # to bytes
                reserved_bits = packet[TCP].reserved
                tcp_flags = packet[TCP].flags
                tcp_checksum = packet[TCP].chksum
                tcp_window_size = packet[TCP].window

                # Flow key
                flow_key = (
                    IP_version,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    "TCP",
                )

                # update stats

                # get packet time
                current_packet_time = packet.time

                # check if start time is set or init
                if not self.flow_stats[flow_key]["start_time"]:
                    self.flow_stats[flow_key]["start_time"] = current_packet_time

                # update last time
                self.flow_stats[flow_key]["last_time"] = current_packet_time

                # calc flow duration
                self.flow_stats[flow_key]["flow_duration"] = (
                    self.flow_stats[flow_key]["last_time"]
                    - self.flow_stats[flow_key]["start_time"]
                )
                # count packets and size
                self.flow_stats[flow_key]["packet_count"] += 1
                self.flow_stats[flow_key]["byte_count"] += packet_length

                # count src ip and dest ip
                self.flow_stats[flow_key]["source_ip_count"][source_ip] = (
                    self.flow_stats[flow_key]["source_ip_count"].get(source_ip, 0) + 1
                )
                self.flow_stats[flow_key]["destination_ip_count"][destination_ip] = (
                    self.flow_stats[flow_key]["destination_ip_count"].get(
                        destination_ip, 0
                    )
                    + 1
                )

                # count src port and dst port
                self.flow_stats[flow_key]["source_port_count"][source_port] = (
                    self.flow_stats[flow_key]["source_port_count"].get(source_port, 0)
                    + 1
                )
                self.flow_stats[flow_key]["destination_port_count"][
                    destination_port
                ] = (
                    self.flow_stats[flow_key]["destination_port_count"].get(
                        destination_port, 0
                    )
                    + 1
                )
                # TCP flag count
                # SYN
                if tcp_flags & 0x02:
                    self.flow_stats[flow_key]["tcp_flags_count"]["SYN"] += 1
                # ACK
                if tcp_flags & 0x10:
                    self.flow_stats[flow_key]["tcp_flags_count"]["ACK"] += 1
                # FIN
                if tcp_flags & 0x01:
                    self.flow_stats[flow_key]["tcp_flags_count"]["FIN"] += 1
                # RST
                if tcp_flags & 0x04:
                    self.flow_stats[flow_key]["tcp_flags_count"]["RST"] += 1

                # Sequence numbers and window sizes
                self.flow_stats[flow_key]["sequence_numbers"].append(sequence_number)
                self.flow_stats[flow_key]["window_sizes"].append(tcp_window_size)

                # Track the IP header length, identification field, and checksum errors
                self.flow_stats[flow_key]["header_lengths"].append(header_length)
                if header_checksum != 0:  # Simple checksum validation (basic example)
                    self.flow_stats[flow_key]["checksum_errors"] += 1
                self.flow_stats[flow_key]["identification_fields"].append(
                    identification_field
                )

                # Track TCP header size, reserved bits, and checksum errors
                self.flow_stats[flow_key]["tcp_header_sizes"].append(tcp_header_size)
                self.flow_stats[flow_key]["reserved_bits"].append(reserved_bits)
                if tcp_checksum != 0:  # Simple checksum validation (basic example)
                    self.flow_stats[flow_key]["tcp_checksum_errors"] += 1

                return self.extract_features(packet, self.flow_stats)

            except Exception as e:
                print(f"Error has occured :{e}")  # TODO obviously.

    def extract_features(self, packet: Packet, stats):
        try:
            duration = stats["flow_duration"]
            if duration == 0:
                # Avoid divide-by-zero
                duration = 1e-6

            features = {
                # Basic features
                "packet_size": len(packet),
                "flow_duration": duration,
                "packet_rate": stats["packet_count"] / duration,
                "byte_rate": stats["byte_count"] / duration,
                # TCP window size (last seen)
                "latest_window_size": packet[TCP].window,
                # Flag counts
                "syn_count": stats["tcp_flags_count"].get("SYN", 0),
                "ack_count": stats["tcp_flags_count"].get("ACK", 0),
                "fin_count": stats["tcp_flags_count"].get("FIN", 0),
                "rst_count": stats["tcp_flags_count"].get("RST", 0),
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
