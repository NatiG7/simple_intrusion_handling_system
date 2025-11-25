from typing import Dict

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


def build_ip_fields(packet: Packet) -> Dict[str, int]:
    """
    Extract and return the IP layer fields from a given Scapy packet.

    Args:
        packet (Packet): The Scapy packet containing the IP layer.

    Returns:
        Dict[str, int]: A dictionary containing IP layer field names as keys
                        and their corresponding values from the packet.
    """
    return {
        "IP_version": packet[IP].version,
        "header_length": packet[IP].ihl * 4,  # to bytes (32bit word)
        "packet_length": packet[IP].len,
        "identification_field": packet[IP].id,
        "header_checksum": packet[IP].chksum,
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
    }


def build_tcp_fields(packet: Packet) -> Dict[str, int]:
    """
    Extract and return the TCP layer fields from a given Scapy packet.

    Args:
        packet (Packet): The Scapy packet containing the TCP layer.

    Returns:
        Dict[str, int]: A dictionary containing TCP layer field names as keys
                        and their corresponding values from the packet.
    """
    return {
        "source_port": packet[TCP].sport,
        "destination_port": packet[TCP].dport,
        "sequence_number": packet[TCP].seq,
        "tcp_header_size": packet[TCP].dataofs * 4,  # to bytes (32 bit word)
        "reserved_bits": packet[TCP].reserved,
        "tcp_flags": packet[TCP].flags,
        "tcp_checksum": packet[TCP].chksum,
        "tcp_window_size": packet[TCP].window,
    }
