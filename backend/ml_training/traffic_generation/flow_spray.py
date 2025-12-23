"""
Flow Sprayer / Entropy Generator
Goal: Maximize 'Unique Flows' per minute, not bandwidth.
Strategy: Rapid-fire connection initiation with immediate termination to force Source Port rotation.
"""

import socket
import random
import time
from concurrent.futures import ThreadPoolExecutor

# Safe, high-capacity targets (DNS and CDNs) that won't ban you for rapid connects
TARGETS = [
    ('8.8.8.8', 53),        # Google DNS (UDP)
    ('1.1.1.1', 53),        # Cloudflare DNS (UDP)
    ('8.8.4.4', 53),        # Google DNS Backup
    ('208.67.222.222', 53), # OpenDNS
    ('142.250.190.46', 80), # Google (TCP)
    ('104.16.132.229', 80), # Cloudflare (TCP)
]

def spray_tcp(target):
    """Connects and immediately disconnects (TCP Handshake + FIN)."""
    ip, port = target
    try:
        # SOCK_STREAM = TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.close() # Immediate close forces a new flow entry
    except:
        pass

def spray_udp(target):
    """Fires a single packet into the void (UDP)."""
    ip, port = target
    try:
        # SOCK_DGRAM = UDP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Send garbage byte
        s.sendto(b'\x00', (ip, port))
        s.close()
    except:
        pass

def noise_maker():
    print("=== Starting Flow Sprayer (High Entropy) ===")
    
    # We use a thread pool to maximize the number of sockets we can open/close per second
    with ThreadPoolExecutor(max_workers=20) as executor:
        while True:
            try:
                # Pick a random target
                target = random.choice(TARGETS)
                
                # 50/50 chance of TCP or UDP
                # UDP is faster (fire and forget), TCP creates fuller flow records
                if random.random() < 0.5:
                    executor.submit(spray_tcp, target)
                else:
                    executor.submit(spray_udp, target)
                
                # Sleep tiny amount to prevent CPU lockup, but keep it FAST
                # 0.01s sleep * 20 threads = ~2000 flows/sec potential
                time.sleep(0.05)
                
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    noise_maker()