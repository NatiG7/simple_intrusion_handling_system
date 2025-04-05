from scapy.all import sniff


# Function to process the captured packet and print detailed info
def packet_callback(packet):
    print("\nPacket Captured:")
    
    # Print details of IP layer (if present)
    if packet.haslayer('IP'):
        print(f"IP Version: {packet['IP'].version}")
        print(f"Source IP: {packet['IP'].src}")
        print(f"Destination IP: {packet['IP'].dst}")
        print(f"Packet Length: {packet['IP'].len} bytes")
        print(f"Identification Field: {packet['IP'].id}")
        print(f"Header Checksum: {packet['IP'].chksum}")

    # Print details of TCP layer (if present)
    if packet.haslayer('TCP'):
        print(f"Source Port: {packet['TCP'].sport}")
        print(f"Destination Port: {packet['TCP'].dport}")
        print(f"Sequence Number: {packet['TCP'].seq}")
        print(f"TCP Header Size: {packet['TCP'].dataofs * 4} bytes")
        print(f"Reserved Bits: {packet['TCP'].reserved}")
        print(f"TCP Flags: {packet['TCP'].flags}")
        print(f"TCP Checksum: {packet['TCP'].chksum}")
        print(f"TCP Window Size: {packet['TCP'].window}")

# Capture a single packet on the default interface
sniff(count=1, prn=packet_callback)
