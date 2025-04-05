from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


def analyze_packet(packet: Packet):
    if packet is not None and IP in packet and TCP in packet:
        try:

            # IP fields for analysis
            IP_version:int = packet[IP].version
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
            if flow_key not in features:
                features[flow_key] = {
                    "start_time": None,
                    "last_time": None,
                    "flow_duration": 0,
                    "packet_count": 0,
                    "byte_count": 0,
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
                    "tcp_checksum_errors": 0
                }
            # get packet time
            current_packet_time = packet.time

            # check if start time is set or init
            if not features[flow_key]["start_time"]:
                features[flow_key]["start_time"] = current_packet_time

            # update last time
            features[flow_key]["last_time"] = current_packet_time

            # calc flow duration
            features[flow_key]["flow_duration"] = (
                features[flow_key]["last_time"]
                - features[flow_key]["start_time"]
            )
            # count packets and size
            features[flow_key]["packet_count"] += 1
            features[flow_key]["byte_count"] += packet_length

            # count src ip and dest ip
            features[flow_key]["source_ip_count"][source_ip] = (
                features[flow_key]["source_ip_count"].get(source_ip, 0) + 1
            )
            features[flow_key]["destination_ip_count"][destination_ip] = (
                features[flow_key]["destination_ip_count"].get(
                    destination_ip, 0
                )
                + 1
            )

            # count src port and dst port
            features[flow_key]["source_port_count"][source_port] = (
                features[flow_key]["source_port_count"].get(source_port, 0)
                + 1
            )
            features[flow_key]["destination_port_count"][
                destination_port
            ] = (
                features[flow_key]["destination_port_count"].get(
                    destination_port, 0
                )
                + 1
            )
            # TCP flag count
            # SYN
            if tcp_flags & 0x02:
                features[flow_key]["tcp_flags_count"]["SYN"] += 1
            # ACK
            if tcp_flags & 0x10:
                features[flow_key]["tcp_flags_count"]["ACK"] += 1
            # FIN
            if tcp_flags & 0x01:
                features[flow_key]["tcp_flags_count"]["FIN"] += 1
            # RST
            if tcp_flags & 0x04:
                features[flow_key]["tcp_flags_count"]["RST"] += 1

            # Sequence numbers and window sizes
            features[flow_key]["sequence_numbers"].append(sequence_number)
            features[flow_key]["window_sizes"].append(tcp_window_size)

            # Track the IP header length, identification field, and checksum errors
            features[flow_key]["header_lengths"].append(header_length)
            if header_checksum != 0:  # Simple checksum validation (basic example)
                features[flow_key]["checksum_errors"] += 1
            features[flow_key]["identification_fields"].append(
                identification_field
            )

            # Track TCP header size, reserved bits, and checksum errors
            features[flow_key]["tcp_header_sizes"].append(tcp_header_size)
            features[flow_key]["reserved_bits"].append(reserved_bits)
            if tcp_checksum != 0:  # Simple checksum validation (basic example)
                features[flow_key]["tcp_checksum_errors"] += 1

            return features
        except Exception as e:
            print(f"Error has occured :{e}")

features = {}
# Capture and analyze a single packet
single_packet = sniff(count=1)
print(f"Captured {len(single_packet)}")
for packet in single_packet:
    analyze_packet(packet)

print(features)