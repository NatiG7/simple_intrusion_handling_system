import os
import random
import socket
import time
from scapy.all import wrpcap, IP, TCP
from scapy.volatile import RandIP, RandShort

FILECOUNT = 1
OUTPUT_DIR = "backend/attacks"
OUTPUT_FILE = f"attack_test_{FILECOUNT}.pcap"
PACKET_COUNT = 5000
SF = "S"

def get_local_ip():
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
    print(f"Generating {PACKET_COUNT} SYN flood packets with timestamps...")
    
    syn_packets = []
    src_ips = [RandIP() for _ in range(50)]
    
    # start time
    base_time = time.time()
    
    for i in range(PACKET_COUNT):
        ip_layer = IP(src=random.choice(src_ips), dst=target_ip)
        tcp_layer = TCP(sport=RandShort(), dport=80, flags=SF)
        packet = ip_layer / tcp_layer
        
        # set timestamp
        packet.time = base_time + (i * 0.001)
        
        syn_packets.append(packet)
        
    full_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    print(f"Saving to {full_path}")
    wrpcap(full_path, syn_packets)
    FILECOUNT += 1
    print(f"Done. Flow Duration should be approx {PACKET_COUNT * 0.001} seconds.")
    
if __name__ == "__main__":
    generate_syn_flood()