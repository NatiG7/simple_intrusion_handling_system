from scapy.all import sniff


# Function to process the captured packet and print detailed info
def packet_callback(packet):
    print("\nPacket Captured:")
    print("=" * 60)
    
    # Print details of IP layer (if present)
    if packet.haslayer('IP'):
        print("Packet has IP Layer:")
        print(f"\tIP Version: {packet['IP'].version}")
        print(f"\tSource IP: {packet['IP'].src}")
        print(f"\tDestination IP: {packet['IP'].dst}")
        print(f"\tPacket Length: {packet['IP'].len} bytes")
        print(f"\tIdentification Field: {packet['IP'].id}")
        print(f"\tHeader Checksum: {packet['IP'].chksum}")
        print("=" * 60)

    # Print details of TCP layer (if present)
    if packet.haslayer('TCP'):
        print("Packet has TCP Layer:")
        print(f"\tSource Port: {packet['TCP'].sport}")
        print(f"\tDestination Port: {packet['TCP'].dport}")
        print(f"\tSequence Number: {packet['TCP'].seq}")
        print(f"\tTCP Header Size: {packet['TCP'].dataofs * 4} bytes")
        print(f"\tReserved Bits: {packet['TCP'].reserved}")
        print(f"\tTCP Flags: {packet['TCP'].flags}")
        print(f"\tTCP Checksum: {packet['TCP'].chksum}")
        print(f"\tTCP Window Size: {packet['TCP'].window}")
        print("=" * 60)
    
    # Print details of ICMP layer (if present)
    if packet.haslayer('ICMP'):
        print("=" * 60)
        print("ICMP Layer Found:")
        print("=" * 60)
        
    else:
        print(packet.summary())

# Capture a single packet on the default interface
sniff(count=1, prn=packet_callback)
