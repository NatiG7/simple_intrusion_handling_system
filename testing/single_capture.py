from scapy.all import sniff

icmp_types = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}


# Function to process the captured packet and print detailed info
def packet_callback(packet):
    print("\nPacket Captured:")
    print("=" * 60)

    # IP Layer (sorted)
    if packet.haslayer("IP"):
        ip = packet["IP"]
        print("IP Layer:")
        print(f"\tIP Version: {ip.version}")
        print(f"\tHeader Length: {ip.ihl * 4} bytes")
        print(f"\tType of Service (ToS): {ip.tos}")
        print(f"\tTotal Length: {ip.len} bytes")
        print(f"\tIdentification: {ip.id}")
        print(f"\tFlags:")
        print(f"\t\tDon't Fragment: {bool(ip.flags.DF)}")
        print(f"\t\tMore Fragments: {bool(ip.flags.MF)}")
        print(f"\tFragment Offset: {ip.frag}")
        print(f"\tTime To Live (TTL): {ip.ttl}")
        print(f"\tProtocol: {ip.proto}")
        print(f"\tHeader Checksum: {ip.chksum}")
        print(f"\tSource IP: {ip.src}")
        print(f"\tDestination IP: {ip.dst}")
        print("=" * 60)

    # TCP Layer (sorted)
    if packet.haslayer("TCP"):
        tcp = packet["TCP"]
        print("TCP Layer:")
        print(f"\tSource Port: {tcp.sport}")
        print(f"\tDestination Port: {tcp.dport}")
        print(f"\tSequence Number: {tcp.seq}")
        print(f"\tAcknowledgment Number: {tcp.ack}")
        print(f"\tHeader Size: {tcp.dataofs * 4} bytes")
        print(f"\tReserved Bits: {tcp.reserved}")
        print(f"\tWindow Size: {tcp.window}")
        print(f"\tUrgent Pointer: {tcp.urgptr}")
        print(f"\tChecksum: {tcp.chksum}")
        print(f"\tFlags (raw): {tcp.flags}")
        print(f"\tFlag Breakdown:")
        print(f"\t\tFIN: {bool(tcp.flags & 0x01)}")
        print(f"\t\tSYN: {bool(tcp.flags & 0x02)}")
        print(f"\t\tRST: {bool(tcp.flags & 0x04)}")
        print(f"\t\tPSH: {bool(tcp.flags & 0x08)}")
        print(f"\t\tACK: {bool(tcp.flags & 0x10)}")
        print(f"\t\tURG: {bool(tcp.flags & 0x20)}")
        print("=" * 60)

    # ICMP Layer (sorted)
    if packet.haslayer("ICMP"):
        icmp = packet["ICMP"]
        print("ICMP Layer:")
        print(f"\tType: {icmp.type} ({icmp_types.get(icmp.type, 'Unknown')})")
        print(f"\tCode: {icmp.code}")
        print(f"\tChecksum: {icmp.chksum}")
        if hasattr(icmp, "id"):
            print(f"\tIdentifier: {icmp.id}")
        if hasattr(icmp, "seq"):
            print(f"\tSequence Number: {icmp.seq}")
        print(f"\tRaw Payload: {bytes(icmp.payload)}")
        print("=" * 60)

    # ARP Layer (sorted)
    if packet.haslayer("ARP"):
        arp = packet["ARP"]
        print("ARP Layer:")
        print(f"\tOperation: {arp.op} ({'Request' if arp.op == 1 else 'Reply'})")
        print(
            f"\tHardware Type: {arp.hwtype} ({'Ethernet' if arp.hwtype == 1 else 'Other'})"
        )
        print(
            f"\tProtocol Type: {hex(arp.ptype)} ({'IPv4' if arp.ptype == 0x0800 else 'Other'})"
        )
        print(f"\tHardware Size: {arp.hwlen} bytes")
        print(f"\tProtocol Size: {arp.plen} bytes")
        print(f"\tSender MAC Address: {arp.hwsrc}")
        print(f"\tSender IP Address: {arp.psrc}")
        print(f"\tTarget MAC Address: {arp.hwdst}")
        print(f"\tTarget IP Address: {arp.pdst}")
        print("=" * 60)

    # Fallback summary if no known layer is present
    else:
        print(packet.summary())


# Capture a single packet on the default interface
sniff(count=1, prn=packet_callback)

packet = sniff(count=1)

print(f"Prnt packet : {packet}")
