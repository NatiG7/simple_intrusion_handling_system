"""
Automated traffic generator for overnight training.
Simulates realistic web browsing and network activity.
Run this alongside train_baseline_overnight.py
"""

import time
import random
import subprocess
import webbrowser
from datetime import datetime
import urllib.request
import urllib.error

# Configuration
DURATION = 28800  # 8 hours (match overnight training)
MIN_WAIT = 30     # Minimum seconds between activities
MAX_WAIT = 180    # Maximum seconds between activities
USE_HEADLESS = True  # Use headless requests instead of browser (recommended)

# Diverse website categories
WEBSITES = {
    'news': [
        'https://www.bbc.com/news',
        'https://www.reuters.com',
        'https://www.theguardian.com',
        'https://www.npr.org',
        'https://apnews.com',
    ],
    'tech': [
        'https://news.ycombinator.com',
        'https://techcrunch.com',
        'https://arstechnica.com',
        'https://www.theverge.com',
        'https://stackoverflow.com',
    ],
    'social': [
        'https://www.reddit.com',
        'https://www.reddit.com/r/programming',
        'https://www.reddit.com/r/technology',
        'https://twitter.com',
    ],
    'reference': [
        'https://en.wikipedia.org',
        'https://www.wikipedia.org',
        'https://docs.python.org',
        'https://developer.mozilla.org',
    ],
    'video': [
        'https://www.youtube.com',
        'https://vimeo.com',
    ],
    'shopping': [
        'https://www.amazon.com',
        'https://www.ebay.com',
    ],
}

# APIs for background requests
API_ENDPOINTS = [
    'https://api.github.com',
    'https://httpbin.org/get',
    'https://jsonplaceholder.typicode.com/posts',
    'https://api.ipify.org?format=json',
]

# DNS queries via ping
PING_TARGETS = [
    'google.com',
    'github.com',
    'stackoverflow.com',
    'wikipedia.org',
    'cloudflare.com',
    '8.8.8.8',
    '1.1.1.1',
]
HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}


def log(message):
    """Log with timestamp"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {message}")

def visit_website(url):
    """Open website - either in browser or headless"""
    try:
        if USE_HEADLESS:
            # Headless mode - just fetch the page
            log(f"Fetching (headless): {url}")
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=15) as response:
                data = response.read()
                log(f"  Loaded: {len(data)} bytes")
            return True
        else:
            # Browser mode - opens tabs
            log(f"Opening in browser: {url}")
            webbrowser.open(url, new=2, autoraise=False)  # new=2 opens new tab
            return True
    except Exception as e:
        log(f"ERROR visiting {url}: {e}")
        return False

def make_api_request(url):
    """Make HTTP request to API"""
    try:
        log(f"API request: {url}")
        with urllib.request.urlopen(url, timeout=10) as response:
            data = response.read()
            log(f"  Response: {len(data)} bytes")
        return True
    except urllib.error.URLError as e:
        log(f"  ERROR: {e}")
        return False
    except Exception as e:
        log(f"  ERROR: {e}")
        return False

def ping_host(host):
    """Ping a host"""
    try:
        log(f"Pinging: {host}")
        result = subprocess.run(
            ['ping', '-n', '4', host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
        return result.returncode == 0
    except Exception as e:
        log(f"  ERROR: {e}")
        return False

def dns_lookup(domain):
    """Perform DNS lookup"""
    try:
        log(f"DNS lookup: {domain}")
        import socket
        result = socket.gethostbyname(domain)
        log(f"  Resolved to: {result}")
        return True
    except Exception as e:
        log(f"  ERROR: {e}")
        return False
    
def send_udp_packet():
    """Generate lightweight UDP traffic."""
    import socket
    log("Sending UDP packet")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b'hello', ("8.8.8.8", 53))  # DNS-style packet
    except Exception as e:
        log(f"UDP ERROR: {e}")
    finally:
        sock.close()

def download_small_file():
    """Download a small file"""
    urls = [
        'https://www.google.com/robots.txt',
        'https://www.github.com/robots.txt',
        'https://www.wikipedia.org/robots.txt',
    ]
    
    url = random.choice(urls)
    try:
        log(f"Downloading: {url}")
        with urllib.request.urlopen(url, timeout=10) as response:
            data = response.read()
            log(f"  Downloaded: {len(data)} bytes")
        return True
    except Exception as e:
        log(f"  ERROR: {e}")
        return False
    
def download_large_file():
    """Download a medium-sized file to generate real TCP bursts."""
    url = "https://speed.hetzner.de/10MB.bin"  # safe test file
    try:
        log("Large download start (10MB)")
        with urllib.request.urlopen(url, timeout=30) as r:
            while r.read(1024 * 64):
                pass  # stream in chunks
        log("Large download complete")
    except Exception as e:
        log(f"Large download error: {e}")

def random_tcp_handshake():
    """Open a short-lived TCP connection on random common ports."""
    import socket
    host = "example.com"
    port = random.choice([80, 443, 22, 25, 8080])
    log(f"TCP handshake to {host}:{port}")
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
    except Exception as e:
        log(f"TCP ERROR: {e}")
    finally:
        s.close()

def simulate_streaming():
    """Hold a connection open for a bit to mimic streaming/video."""
    url = "https://www.youtube.com"
    log("Simulating streaming session")
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            for _ in range(50):  # ~50 small chunks
                r.read(1024 * 32)
                time.sleep(0.1)
    except Exception as e:
        log(f"STREAM ERROR: {e}")

def background_activity():
    """Simulate background network activity"""
    activities = [
        ('ping', ping_host, PING_TARGETS),
        ('dns', dns_lookup, ['google.com', 'github.com', 'wikipedia.org']),
        ('api', make_api_request, API_ENDPOINTS),
        ('download', download_small_file, [None]),
        ('udp', send_udp_packet, [None]),
        ('large_download', download_large_file, [None]),
        ('tcp', random_tcp_handshake, [None]),
        ('stream', simulate_streaming, [None]),
    ]
    
    activity_type, func, targets = random.choice(activities)
    target = random.choice(targets)
    
    if target:
        func(target)
    else:
        func()

def browsing_session():
    """Simulate a browsing session"""
    # Pick random category
    category = random.choice(list(WEBSITES.keys()))
    sites = WEBSITES[category]
    
    # Visit 2-4 sites from this category
    num_sites = random.randint(2, 4)
    selected = random.sample(sites, min(num_sites, len(sites)))
    
    log(f"Browsing session: {category} ({num_sites} sites)")
    
    for site in selected:
        visit_website(site)
        # Wait between tabs
        time.sleep(random.uniform(3, 8))

def generate_traffic():
    """Main traffic generation loop"""
    print("="*70)
    print("OVERNIGHT TRAFFIC GENERATOR")
    print("="*70)
    print(f"Duration: {DURATION//3600} hours")
    print(f"Activity interval: {MIN_WAIT}-{MAX_WAIT} seconds")
    print(f"Mode: {'HEADLESS (no browser tabs)' if USE_HEADLESS else 'BROWSER (opens tabs)'}")
    print()
    print("This will simulate realistic web browsing and network activity.")
    print("Run this alongside train_baseline_overnight.py")
    print()
    print("Activities:")
    print("  - Browse news, tech, social media sites")
    print("  - Make API requests")
    print("  - Perform DNS lookups")
    print("  - Ping various hosts")
    print("  - Download small files")
    print()
    if not USE_HEADLESS:
        print("WARNING: Browser mode will open many tabs!")
        print("Consider setting USE_HEADLESS = True in the script")
    else:
        print("HEADLESS MODE: No browser tabs will open (network traffic only)")
    print("="*70 + "\n")
    
    response = input("Press ENTER to start generating traffic (Ctrl+C to stop): ")
    print()
    
    start_time = time.time()
    end_time = start_time + DURATION
    
    activity_count = 0
    browsing_sessions = 0
    background_activities = 0
    
    log("Traffic generation started")
    
    try:
        while time.time() < end_time:
            # Choose activity type
            if random.random() < 0.7:  # 70% browsing, 30% background
                browsing_session()
                browsing_sessions += 1
            else:
                background_activity()
                background_activities += 1
            
            activity_count += 1
            
            # Wait random time
            wait_time = random.uniform(MIN_WAIT, MAX_WAIT)
            
            # Progress update
            elapsed = time.time() - start_time
            remaining = end_time - time.time()
            progress = (elapsed / DURATION) * 100
            
            log(f"Activity {activity_count} complete. "
                f"Progress: {progress:.1f}% | "
                f"Elapsed: {elapsed//3600:.0f}h {(elapsed%3600)//60:.0f}m | "
                f"Remaining: {remaining//3600:.0f}h {(remaining%3600)//60:.0f}m")
            log(f"Waiting {wait_time:.0f}s until next activity...\n")
            
            time.sleep(wait_time)
        
        log("Traffic generation complete!")
        
    except KeyboardInterrupt:
        print("\n\nTraffic generation stopped by user")
        elapsed = time.time() - start_time
        log(f"Ran for {elapsed//3600:.0f}h {(elapsed%3600)//60:.0f}m")
    
    finally:
        print("\n" + "="*70)
        print("TRAFFIC GENERATION SUMMARY")
        print("="*70)
        print(f"Total activities: {activity_count}")
        print(f"Browsing sessions: {browsing_sessions}")
        print(f"Background activities: {background_activities}")
        print("="*70)

if __name__ == "__main__":
    generate_traffic()