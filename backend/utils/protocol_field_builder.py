from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


def build_ip_fields(packet: Packet) -> dict:
    return {
        "IP_version": packet[IP].version,
        "header_length": packet[IP].ihl * 4,  # to bytes
        "packet_length": packet[IP].len,
        "identification_field": packet[IP].id,
        "header_checksum": packet[IP].chksum,
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
    }


def build_tcp_fields(packet: Packet) -> dict:
    return {
        "source_port": packet[TCP].sport,
        "destination_port": packet[TCP].dport,
        "sequence_number": packet[TCP].seq,
        "tcp_header_size": packet[TCP].dataofs * 4,  # to bytes
        "reserved_bits": packet[TCP].reserved,
        "tcp_flags": packet[TCP].flags,
        "tcp_checksum": packet[TCP].chksum,
        "tcp_window_size": packet[TCP].window,
    }
