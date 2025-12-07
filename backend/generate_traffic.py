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
            with urllib.request.urlopen(url, timeout=15) as response:
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

def background_activity():
    """Simulate background network activity"""
    activities = [
        ('ping', ping_host, PING_TARGETS),
        ('dns', dns_lookup, ['google.com', 'github.com', 'wikipedia.org']),
        ('api', make_api_request, API_ENDPOINTS),
        ('download', download_small_file, [None]),
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