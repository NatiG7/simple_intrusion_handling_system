from collections import defaultdict
import time

def initialize_flow_stats():
    return {
        "start_time": None,
        "last_time": None,
        "flow_duration": 0,
        "packet_count": 0,
        "byte_count": 0,
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


def build_flow_key(ip_fields: dict, tcp_fields: dict) -> tuple:
    return (
        ip_fields["version"],
        ip_fields["source_ip"],
        ip_fields["destination_ip"],
        tcp_fields["source_port"],
        tcp_fields["destination_port"],
        "TCP",
    )

def build_dst_flow_key(ip_fields: dict, tcp_fields: dict, window: int = 1) -> tuple:
    """
    Aggregate traffic per destination in fixed time windows.
    """
    time_bucket = int(time.time() // window)

    return (
        ip_fields["version"],
        ip_fields["destination_ip"],
        tcp_fields["destination_port"],
        "TCP",
        time_bucket,
    )

def update_flow_duration(flow_entry, current_time):
    if flow_entry["start_time"] is None:
        flow_entry["start_time"] = current_time
    flow_entry["last_time"] = current_time
    flow_entry["flow_duration"] = current_time - flow_entry["start_time"]


def count_tcp_flags(flow_entry, flags):
    if flags & 0x02:
        flow_entry["tcp_flags_count"]["SYN"] += 1
    if flags & 0x10:
        flow_entry["tcp_flags_count"]["ACK"] += 1
    if flags & 0x01:
        flow_entry["tcp_flags_count"]["FIN"] += 1
    if flags & 0x04:
        flow_entry["tcp_flags_count"]["RST"] += 1
