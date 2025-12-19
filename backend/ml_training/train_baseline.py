"""
Baseline training script with Data Health Checks.
Captures traffic, validates feature quality, and trains the FlowML model.
"""

import sys
import time
from typing import List, Dict, Any

from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis

# --- Configuration ---
TARGET_PACKETS = 15000     # Packets needed for a solid baseline
TIMEOUT = 1200            # Max capture time in seconds (20 mins)
CONTAMINATION = 0.01      # Estimated anomaly rate in baseline (1%)

def check_data_health(features: List[Dict[str, Any]]) -> bool:
    """
    Validates extracted features to prevent training on bad data.
    
    Checks for:
    1. Zero Inter-Arrival Time (IAT) -> Indicates broken packet timestamping.
    2. Zero TCP Flags -> Indicates broken BPF filters or extraction logic.
    """
    print("\n--- Data Health Check ---")
    if not features:
        print("FAIL: No features extracted.")
        return False
        
    # Check 1: Global Average IAT
    # If this is exactly 0.0, the sniffer isn't recording time deltas correctly.
    avg_iats = [f['avg_iat'] for f in features]
    if sum(avg_iats) / len(avg_iats) == 0:
        print("CRITICAL: IAT is 0.0. Timing logic broken.")
        return False

    # Check 2: TCP Flags
    # We expect at least *some* SYN or ACK flags in normal traffic.
    syn = sum(f['syn_count'] for f in features)
    ack = sum(f['ack_count'] for f in features)
    if syn == 0 and ack == 0:
        print("CRITICAL: No TCP Flags detected.")
        return False
    
    print("Pass: Data looks healthy.\n")
    return True

def main() -> None:
    """Main training pipeline."""
    print("=== Baseline Training ===")
    
    # Initialize components
    capture = PacketCapture()
    analyzer = TrafficAnalysis()
    
    # --- Phase 1: Capture ---
    print(f"Capturing ~{TARGET_PACKETS} packets... (Ensure generator is running)")
    capture.start_capture()
    
    try:
        # Loop until target count reached or timeout
        while capture.packet_queue.qsize() < TARGET_PACKETS:
            time.sleep(1)
            print(f"Packets: {capture.packet_queue.qsize()}/{TARGET_PACKETS}", end='\r')
            if time.time() > time.time() + TIMEOUT:
                break
    except KeyboardInterrupt:
        print("\nStopping capture early...")
    
    # Graceful stop
    capture.stop_capture_event()
    packets = list(capture.packet_queue.queue)
    
    # --- Phase 2: Analysis ---
    print("\nExtracting features...")
    # List comprehension to analyze packets, filtering out None returns
    features = [analyzer.analyze_packet(p) for p in packets if analyzer.analyze_packet(p)]
            
    # Abort if data is garbage
    if not check_data_health(features):
        sys.exit("Training Aborted.")
        
    # --- Phase 3: Training ---
    print(f"Training FlowML on {len(features)} flows...")
    model = FlowMLModel(contamination=CONTAMINATION)
    model.train(features)
    
    # --- Phase 4: Persistence ---
    model.save("models/baseline_model.pkl")
    print("Model saved to models/baseline_model.pkl")

if __name__ == "__main__":
    main()