# Scapy Protocol Class Documentation

## IP Class

IP Class Documentation

IP class in Scapy is used for creating and manipulating IP packets. It is a subclass of the Packet class.
Fields of the IP Class:

    version: The IP version (4 for IPv4, 6 for IPv6).

    ihl: Internet Header Length (in 4-byte words).

    tos: Type of Service (ToS).

    len: Total length of the IP packet.

    id: Identification field.

    flags: Flags for fragmentation.

    frag: Fragment offset.

    ttl: Time to live.

    proto: Protocol (e.g., TCP, UDP).

    chksum: Checksum for IP header.

    src: Source IP address.

    dst: Destination IP address.

    options: Options field (rarely used).

Scapy automatically parses and sets these fields when receiving or creating IP packets.

## TCP Class

TCP Class Documentation

The TCP class in Scapy is used for creating and manipulating TCP packets. Like the IP class, it is also a subclass of the Packet class.
Fields of the TCP Class:

    sport: Source port number.

    dport: Destination port number.

    seq: Sequence number.

    ack: Acknowledgment number.

    dataofs: Data offset (size of TCP header).

    reserved: Reserved bits.

    flags: TCP flags (e.g., SYN, ACK, FIN).

    window: Window size.

    chksum: Checksum for TCP header.

    urgptr: Urgent pointer.

    options: Options field (e.g., maximum segment size, window scale).

Scapy also handles parsing of these fields when it receives a TCP packet.
