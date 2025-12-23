"""
Complementary Traffic Generator.
Simulates "Heavy Lifting" (Downloads) and "Background Noise" (UDP).
Crucial for teaching ML models about Long-Duration Flows and non-HTTP protocols.
"""

import time
import random
import socket
import struct
import urllib.request
from datetime import datetime

# --- Configuration ---
DURATION = 3600       # Runtime in seconds
NTP_SERVERS = [
    "pool.ntp.org",
    "time.google.com",
    "time.windows.com",
    "time.nist.gov",
    "ntp.ubuntu.com",
    "time.cloudflare.com",
    "0.pool.ntp.org",
    "1.pool.ntp.org"
]
# Safe, public, large files for bandwidth testing
LARGE_FILES = [
    "http://speedtest.tele2.net/1MB.zip",
    "http://ipv4.download.thinkbroadband.com/5MB.zip",
    "http://speedtest.tele2.net/5MB.zip"
]

def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

# --- 1. UDP Simulation (NTP) ---
def simulate_ntp_sync():
    """
    Sends a raw UDP packet to an NTP server.
    Teaches the IDS that 'UDP' and 'Small Packets' are normal.
    """
    target_server = random.choice(NTP_SERVERS)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(2)
    
    # NTP v3, Client mode packet structure (48 bytes)
    msg = b'\x1b' + 47 * b'\0'
    
    try:
        start = time.time()
        client.sendto(msg, (target_server, 123))
        data, address = client.recvfrom(1024)
        elapsed = time.time() - start
        
        #  - Implicitly modeled by the byte array
        log(f"UDP/NTP Sync: Received {len(data)} bytes from {address[0]} in {elapsed:.3f}s")
        
    except socket.timeout:
        log("UDP/NTP Sync: Request Timed Out (Normal Network Noise)")
    except Exception as e:
        log(f"UDP/NTP Error: {e}")
    finally:
        client.close()

# --- 2. Long TCP Flow (File Download) ---
def simulate_large_download():
    """
    Streams a large file without saving it.
    Teaches the IDS that 'High Byte Count' and 'Long Duration' flows are normal.
    """
    target = random.choice(LARGE_FILES)
    log(f"Starting Heavy Download: {target}")
    
    total_bytes = 0
    start_time = time.time()
    
    try:
        # Stream the file in chunks to simulate sustained throughput
        with urllib.request.urlopen(target, timeout=10) as response:
            while True:
                chunk = response.read(8192) # 8KB chunks
                if not chunk:
                    break
                total_bytes += len(chunk)
                
                # Optional: slight sleep to mimic non-max-speed download
                # time.sleep(0.001) 
                
        duration = time.time() - start_time
        speed_mb = (total_bytes / 1024 / 1024)
        
        log(f" -> Download Finished: {speed_mb:.2f} MB in {duration:.2f}s")
        log(f" -> Flow Metric: {total_bytes} bytes / {duration:.2f} sec")
        
    except Exception as e:
        log(f"Download Error: {e}")

# --- Main Loop ---
def generate_noise():
    print(f"=== Starting Heavy/UDP Gen ({DURATION}s) ===")
    start_global = time.time()
    
    try:
        while time.time() - start_global < DURATION:
            # 1. Background Noise (Frequent)
            # Do a few UDP pings
            for _ in range(random.randint(1, 3)):
                simulate_ntp_sync()
                time.sleep(random.uniform(0.5, 2.0))
            
            # 2. Heavy Lift (Occasional)
            # Once every ~30-60 seconds, do a big download
            if random.random() < 0.3: # 30% chance per loop
                simulate_large_download()
                
            # Wait before next cycle
            wait = random.uniform(5, 15)
            log(f"Idling for {wait:.1f}s...")
            time.sleep(wait)
            
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    generate_noise()