def get_local_ip():
    """
    Detects the primary local IP address of this machine.
    Connects to an external IP (doesn't send data) to find the routing interface.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

import socket
import struct

# 1. Create a raw socket (Windows requires specific promiscuous mode commands, but let's try standard first)
# AF_INET = IPv4, SOCK_RAW = Raw Packets, IPPROTO_IP = IP Protocol
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

# Bind to your machine's local IP (Run 'ipconfig' to find it)
HOST = get_local_ip()
sniffer.bind((HOST, 0))

# Include IP headers in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Windows-specific: IOCTL to set Promiscuous mode ON
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print(f"[*] Sniffing on {HOST}...")

# 2. Receive a single packet (Buffer size 65565)
raw_buffer = sniffer.recvfrom(65565)[0]

# 3. Extract the first byte (The IP Header starts at byte 0)
# 'B' means unsigned char (1 byte)
first_byte = struct.unpack('!B', raw_buffer[0:1])[0]

# ----------------------------------------------------
# YOUR CHALLENGE:
# The first_byte contains both Version (4 bits) and IHL (4 bits).
# Use Bitwise operators (>> and &) to separate them.
# ----------------------------------------------------

version = first_byte >> 4
header_length = first_byte & 0x0F
raw_stuff = first_byte >> 20

print(f"Version: {version} | Header Length (32-bit words): {header_length}")
print(f"Rawbuffer : {raw_stuff}")

# Cleanup
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)