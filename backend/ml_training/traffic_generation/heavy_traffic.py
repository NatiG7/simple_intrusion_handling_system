"""
TRAINING GENERATOR V2
Includes: Azure, Heavy Downloads, UDP Noise, AND General CDN/Web Browsing.
Goal: Teach the model that "The Internet" is safe, not just Azure.
"""

import time
import random
import socket
import urllib.request
import urllib.error
from datetime import datetime

# --- Configuration ---
DURATION = 3600       # Runtime in seconds

# --- TRAFFIC SOURCES ---

# 1. Cloudflare / CDNs (The "Normal Web" Noise)
# Hitting these generates traffic to 104.x.x.x, 172.x.x.x, etc.
CDN_ASSETS = [
    "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
    "https://fonts.googleapis.com/css?family=Roboto",
    "https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css",
    "https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.5.1.min.js",
    "https://code.jquery.com/jquery-3.6.0.min.js"
]

# 2. Azure Infrastructure (Your Baseline)
AZURE_ENDPOINTS = [
    "https://management.azure.com",
    "https://login.microsoftonline.com",
    "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"
]

# 3. Heavy Files (Bandwidth Training)
LARGE_FILES = [
    "http://speedtest.tele2.net/1MB.zip",
    "http://ipv4.download.thinkbroadband.com/5MB.zip"
]

def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

# --- TRAFFIC MODULES ---

def simulate_cdn_browsing():
    """
    Simulates loading a modern webpage (fetching JS/CSS from CDNs).
    Teaches the model: 'Connections to Cloudflare/Google CDNs are SAFE'.
    """
    target = random.choice(CDN_ASSETS)
    try:
        # User-Agent mimics a browser to ensure we get real traffic behavior
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        req = urllib.request.Request(target, headers=headers)
        
        start = time.time()
        with urllib.request.urlopen(req, timeout=3) as response:
            data = response.read(10000) # Read small chunk
        
        elapsed = time.time() - start
        log(f"WEB/CDN: Fetched {len(data)}b from {target.split('/')[2]} ({elapsed:.2f}s)")
        
    except Exception as e:
        log(f"WEB/CDN Error: {e}")

def simulate_azure():
    target = random.choice(AZURE_ENDPOINTS)
    try:
        with urllib.request.urlopen(target, timeout=3) as response:
            response.read(1024)
        log(f"AZURE: Heartbeat sent to {target.split('/')[2]}")
    except:
        pass

def simulate_heavy_download():
    target = random.choice(LARGE_FILES)
    try:
        log(f"DOWNLOAD: Starting flow to {target}")
        with urllib.request.urlopen(target, timeout=5) as response:
            response.read(1024*1024) # Read 1MB
        log("DOWNLOAD: Complete")
    except:
        pass

# --- MAIN LOOP ---
def generate_noise():
    print(f"=== Starting 'General Internet' Training ({DURATION}s) ===")
    start_global = time.time()
    
    try:
        while time.time() - start_global < DURATION:
            
            dice = random.random()
            
            if dice < 0.5:
                # 50% Chance: General Web/CDN Traffic (Fixes your Cloudflare alerts)
                simulate_cdn_browsing()
                
            elif dice < 0.8:
                # 30% Chance: Azure Traffic
                simulate_azure()
                
            else:
                # 20% Chance: Heavy Download
                simulate_heavy_download()
            
            # Random sleep to mimic human reading time
            time.sleep(random.uniform(0.5, 3.0))
            
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    generate_noise()