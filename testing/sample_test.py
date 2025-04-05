from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

# Example packet creation with SYN flag set
packet = IP(dst="1.2.3.4") / TCP(sport=12345, dport=80, flags="S")

# Printing the TCP flags
print("TCP Flags:", packet[TCP].flags)

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

# SYN packet (step 1 of the handshake)
syn_packet = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(
    sport=12345, dport=80, flags="S", seq=1000, window=8192
)

# SYN, ACK packet (step 2 of the handshake)
syn_ack_packet = IP(src="93.184.216.34", dst="192.168.1.10") / TCP(
    sport=80, dport=12345, flags="SA", seq=2000, ack=1001, window=8192
)

# ACK packet (step 3 of the handshake)
ack_packet = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(
    sport=12345, dport=80, flags="A", seq=1001, ack=2001, window=8192
)

# HTTP request packet (GET /index.html, step 4)
http_packet = (
    IP(src="192.168.1.10", dst="93.184.216.34")
    / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001, window=8192)
    / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
)

multi_flag_packet = (
    IP(src="192.168.1.10", dst="93.184.216.34")
    / TCP(sport=12345, dport=80, flags="SAP", seq=1001, ack=2001, window=8192)
    / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
)

# Print out the packet details to view the flags
print("SYN Packet Flags:", syn_packet[TCP].flags)  # Shows SYN flag (0x02)
print("SYN, ACK Packet Flags:", syn_ack_packet[TCP].flags)  # Shows SYN, ACK flag (0x12)
print("ACK Packet Flags:", ack_packet[TCP].flags)  # Shows ACK flag (0x10)
print("HTTP Request Packet Flags:", http_packet[TCP].flags) # Shows PSH,ACK flag (0x18)
print("Multiflag : packet flags (SYN, ACK, PSH):", multi_flag_packet[TCP].flags) # (0x1A)
