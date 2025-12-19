"""
Automated traffic generator for baseline training.
Simulates REALISTIC web browsing with parallel asset loading (TCP Bursts).
"""

import time
import random
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# --- Configuration ---
DURATION = 3600   # Total runtime in seconds (1 hour)
MIN_WAIT = 2      # Minimum wait between simulated user actions
MAX_WAIT = 15     # Maximum wait between simulated user actions
THREADS = 4       # Max parallel threads for asset simulation

# Categories of websites to visit
WEBSITES = {
    'news': ['https://www.bbc.com', 'https://www.reuters.com', 'https://www.npr.org'],
    'tech': ['https://news.ycombinator.com', 'https://github.com', 'https://stackoverflow.com'],
    'social': ['https://www.reddit.com', 'https://twitter.com', 'https://www.linkedin.com'],
    'video': ['https://www.youtube.com', 'https://vimeo.com']
}

# Static assets to request in parallel (simulating images, scripts, CSS)
ASSETS = [
    'https://www.google.com/favicon.ico',
    'https://github.com/favicon.ico',
    'https://api.github.com/zen',
    'https://www.cloudflare.com/favicon.ico',
    'https://fonts.googleapis.com/css?family=Roboto',
    'https://code.jquery.com/jquery-3.6.0.min.js',
]

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

def log(msg: str) -> None:
    """Prints a message with a timestamp."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def make_request(url: str, label: str = "Asset") -> int:
    """
    Performs a single HTTP GET request.
    
    Args:
        url: The target URL.
        label: Description for logging purposes.
        
    Returns:
        int: Length of response in bytes, or 0 on failure.
    """
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=5) as response:
            return len(response.read())
    except (urllib.error.URLError, urllib.error.HTTPError):
        # Ignore expected network noise (404s, timeouts)
        return 0
    except Exception as e:
        print(f"Error in {label}: {e}")
        return 0

def simulate_page_load(url: str) -> None:
    """
    Simulates a full page load: main HTML request followed by parallel asset requests.
    This creates the 'TCP Burst' patterns crucial for IAT training.
    """
    log(f"Visiting: {url}")
    
    # Request Main Page
    make_request(url, "Main HTML")
    
    # Parallel Asset Loading
    # Randomly select 3-8 assets to fetch simultaneously
    num = random.randint(3, 8)
    assets = [random.choice(ASSETS) for _ in range(num)]
    
    # Use thread pool to fire requests in parallel
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(make_request, assets)
    
    log(f"  -> Loaded page + {num} assets")

def generate_traffic() -> None:
    """Main execution loop for traffic generation."""
    print(f"=== Starting Generator ({DURATION}s) ===")
    start = time.time()
    
    try:
        while time.time() - start < DURATION:
            # Pick random category and site
            cat = random.choice(list(WEBSITES.keys()))
            site = random.choice(WEBSITES[cat])
            
            simulate_page_load(site)
            
            # Mimic human reading time
            time.sleep(random.uniform(MIN_WAIT, MAX_WAIT))
            
            # Occasional background noise (DNS/Ping check)
            if random.random() < 0.3:
                make_request("https://1.1.1.1", "Ping")

    except KeyboardInterrupt:
        print("\nStopped by user.")

if __name__ == "__main__":
    generate_traffic()