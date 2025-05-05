from colorama import Fore, Style, init
from scapy.all import sniff
from scapy.layers.inet import ICMP, TCP, UDP, Ether

init(autoreset=True)


# Add this wherever you parse packets
def handle_packet(pkt):
    if TCP in pkt:
        # existing logic here
        print(Fore.GREEN + "TCP Packet processed.\n")
    elif UDP in pkt:
        print(Fore.BLUE + "UDP Packet detected but not processed.\n")
    elif ICMP in pkt:
        print(Fore.MAGENTA + "ICMP Packet detected but not processed.\n")
    elif Ether in pkt:
        print(Fore.CYAN + "Ethernet Packet detected but not processed.\n")
    else:
        print(
            Fore.RED + Style.BRIGHT + f"Unknown or unhandled packet type: {type(pkt)}"
        )
        print(Fore.YELLOW + f"Summary: {pkt.summary()}")
        print(Fore.WHITE + f"Raw Dump:\n{bytes(pkt)}\n")


# Example usage in a sniffing loop
sniff(prn=handle_packet, count=100)
