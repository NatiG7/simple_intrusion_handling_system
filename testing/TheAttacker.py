"""
Module: Packet Generator
Purpose: Crafts and sends specific packet patterns (Normal & Attack simulations).
"""
import time
import random
from scapy.all import send
from scapy.layers.inet import IP, TCP, ICMP

def send_syn_flood(target_ip="127.0.0.1", count=20):
    print(f"[>] Sending {count} SYN packets to [{target_ip}]...")
    for _ in range(count):
        # Random source port for realism
        sport = random.randint(1024, 65535)
        packet = IP(dst=target_ip) / TCP(sport=sport, dport=80, flags="S")
        send(packet, verbose=0)
        time.sleep(0.05) # Fast but visible

def send_http_traffic(target_ip="127.0.0.1"):
    print(f"[>] Simulating HTTP flow to {target_ip}...")
    sport = 12345
    # Handshake
    send(IP(dst=target_ip)/TCP(sport=sport, dport=80, flags="S"), verbose=0)
    time.sleep(0.1)
    send(IP(dst=target_ip)/TCP(sport=sport, dport=80, flags="A"), verbose=0)
    time.sleep(0.1)
    # Data PSH+ACK
    payload = b"GET /index.html HTTP/1.1\r\nHost: test.com\r\n\r\n"
    send(IP(dst=target_ip)/TCP(sport=sport, dport=80, flags="PA")/payload, verbose=0)
    print("[+] HTTP flow sent.")

def send_ping(target_ip="127.0.0.1"):
    print(f"[>] Sending ICMP Ping to {target_ip}...")
    send(IP(dst=target_ip)/ICMP(), verbose=0)