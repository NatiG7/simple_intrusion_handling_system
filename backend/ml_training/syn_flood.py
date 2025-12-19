import os
import socket
from scapy.all import wrpcap, IP, TCP
from scapy.volatile import RandIP, RandShort

FILECOUNT = 1
OUTPUT_DIR = "backend/attacks"
OUTPUT_FILE = f"attack_test_{FILECOUNT}.pcap"
PACKET_COUNT = 5000
SF = "S"

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

def generate_syn_flood():
    global FILECOUNT
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"Created dir: {OUTPUT_DIR}")

    target_ip = get_local_ip()
    print(f"Target localhost: {target_ip}")
    print(f"Generating {PACKET_COUNT} SYN flood packets")
    
    syn_packets = []
    
    for _ in range(PACKET_COUNT):
        # create ip,tcp layers adn stack
        ip_layer = IP(src=RandIP(), dst=target_ip)
        tcp_layer = TCP(sport=RandShort(), dport = 80, flags=SF)
        # scapy / operator stacks.
        packet = ip_layer / tcp_layer
        syn_packets.append(packet)
        
    full_path = os.path.join(OUTPUT_DIR,OUTPUT_FILE)
    print(f"Saving to {full_path}")
    wrpcap(full_path, syn_packets)
    FILECOUNT+=1
    print("Done.")
    
if __name__ == "__main__":
    generate_syn_flood()