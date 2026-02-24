import struct
import socket

def parse_packet_fast(raw_data):
    """
    Parses Ethernet/IP/TCP headers directly from bytes.
    Returns dictionaries compatible with TrafficAnalysis.
    Speed: ~100x faster than Scapy.
    """
    try:
        # 1. Ethernet Header (14 bytes)
        # dest (6), src (6), type (2)
        eth_header = raw_data[:14]
        eth_proto = struct.unpack("!H", eth_header[12:14])[0]
        
        # Only process IPv4 (0x0800)
        if eth_proto != 2048:
            return None, None, None, None

        # 2. IP Header
        # IP header starts at byte 14
        # Version + IHL is the first byte (byte 14)
        ver_ihl = raw_data[14]
        version = ver_ihl >> 4
        ihl = ver_ihl & 0xF
        ip_header_len = ihl * 4
        
        # Total Length (byte 16-17)
        total_len = struct.unpack("!H", raw_data[16:18])[0]
        
        # Protocol (byte 23)
        protocol = raw_data[23]
        
        # Source/Dest IP (bytes 26-34)
        src_ip = socket.inet_ntoa(raw_data[26:30])
        dst_ip = socket.inet_ntoa(raw_data[30:34])

        ip_fields = {
            "version": version,
            "header_length": ip_header_len,
            "packet_length": len(raw_data), # Wire length
            "ttl": raw_data[22],
            "protocol": protocol,
            "source_ip": src_ip,
            "destination_ip": dst_ip
        }

        # Only process TCP (6)
        if protocol != 6:
            return ip_fields, None, None, 14

        # 3. TCP Header
        tcp_start = 14 + ip_header_len
        # Source Port (2), Dest Port (2), Seq (4), Ack (4), Offset/Flags (2)
        # We need the first 14 bytes of TCP header
        tcp_header_bytes = raw_data[tcp_start:tcp_start+14]
        src_port, dst_port, seq, ack, offset_flags = struct.unpack("!HHIIH", tcp_header_bytes)
        
        data_offset = (offset_flags >> 12) * 4
        flags = offset_flags & 0x3F
        
        # Window (next 2 bytes)
        window = struct.unpack("!H", raw_data[tcp_start+14:tcp_start+16])[0]

        tcp_fields = {
            "source_port": src_port,
            "destination_port": dst_port,
            "seq": seq,
            "ack": ack,
            "dataofs": data_offset,
            "reserved": (offset_flags >> 6) & 0x3F, # Approximation
            "tcp_flags": flags,
            "window": window,
        }
        ip_start_index = 14
        
        return ip_fields, tcp_fields, "TCP", ip_start_index

    except Exception:
        # Packet too short or malformed
        return None, None, None, None