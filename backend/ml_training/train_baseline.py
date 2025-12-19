import sys
import time
import queue
from typing import List, Dict, Any

from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis

# --- Configuration ---
# We want 1000 unique, quality conversations (flows), not just packets.
TARGET_UNIQUE_FLOWS = 1000  
TIMEOUT = 1200  
CONTAMINATION = 0.01

def check_data_health(features: List[Dict[str, Any]]) -> bool:
    print("\n--- Data Health Check ---")
    if not features:
        print("FAIL: No features extracted.")
        return False
    
    # Check 1: Do we have packets?
    # Using 'packet_count' which we added to features earlier
    total_packets = sum(f.get('packet_count', 0) for f in features)
    print(f"Total Packets across {len(features)} flows: {total_packets}")
    
    if total_packets == 0:
        print("CRITICAL: Packets not being counted.")
        return False

    # Check 2: TCP Flags (Sanity)
    syn = sum(f.get('syn_count', 0) for f in features)
    ack = sum(f.get('ack_count', 0) for f in features)
    if syn == 0 and ack == 0:
        print("CRITICAL: No TCP Flags detected.")
        return False
    
    print("Pass: Data looks healthy.\n")
    return True

def main() -> None:
    print("=== Baseline Training (Accumulate Mode) ===")
    
    capture = PacketCapture()
    analyzer = TrafficAnalysis()
    
    print(f"Starting capture... Waiting for {TARGET_UNIQUE_FLOWS} unique flows.")
    capture.start_capture()
    start_time = time.time()
    
    processed_packets = 0
    
    try:
        # --- PHASE 1: ACCUMULATE STATE ---
        # We just feed the analyzer. We don't extract features yet.
        while True:
            try:
                packet = capture.packet_queue.get(timeout=0.1)
                processed_packets += 1
                
                # Update the analyzer's internal memory
                analyzer.analyze_packet(packet)
                
            except queue.Empty:
                pass

            # Check Status
            unique_flows = len(analyzer.flow_stats)
            
            # Update UI
            if processed_packets % 50 == 0:
                print(f"Packets: {processed_packets} | Unique Flows In Memory: {unique_flows}/{TARGET_UNIQUE_FLOWS}", end='\r')

            # Stop Condition
            if unique_flows >= TARGET_UNIQUE_FLOWS:
                print("\nTarget flow count reached.")
                break
                
            if time.time() - start_time > TIMEOUT:
                print("\nTimeout reached.")
                break
            
            # Optional: Call cleanup occasionally to remove stale flows if needed
            # analyzer.cleanup_old_flows() 

    except KeyboardInterrupt:
        print("\nStopping capture early...")
    
    capture.stop_capture_event()
    
    # --- PHASE 2: HARVEST & FILTER ---
    print(f"\n\nProcessing {len(analyzer.flow_stats)} raw flows...")
    
    training_data = []
    ignored_count = 0
    
    # Iterate through the analyzer's memory
    for flow_key, flow_stats in analyzer.flow_stats.items():
        # 1. Extract the features using the method in TrafficAnalysis
        # Note: We need to recreate the feature dict from stats manually or call extract_features
        # Since analyze_packet returns it, we can also just use the internal extract_features method
        # if you exposed it. Assuming TrafficAnalysis.extract_features takes (packet, stats):
        
        # Simpler approach: Use the data directly since we know the structure
        # OR: Call extract_features with a dummy packet? No, that's messy.
        
        # BEST WAY: We use the logic we wrote in TrafficAnalysis.extract_features
        # but apply it here to the 'flow_stats'.
        # Since we can't easily call internal methods, let's rely on the fact 
        # that 'extract_features' logic is consistent. 
        
        # Let's generate the features directly from the stats we have
        # This mirrors TrafficAnalysis.extract_features but works offline
        
        # -- Filter Logic --
        if flow_stats['packet_count'] < 3 or flow_stats['flow_duration'] == 0:
            ignored_count += 1
            continue

        # -- Extraction Logic (Mirroring your TrafficAnalysis.py) --
        duration = max(flow_stats['flow_duration'], 1e-6)
        features = analyzer.extract_features(None, flow_stats) # Pass None as packet if method allows
        
        # Fix: Your TrafficAnalysis.extract_features uses 'packet' for 'len(packet)' and window.
        # Since we don't have the last packet here easily, we might miss 'packet_size' and 'latest_window'.
        # That's acceptable for aggregate training. We can mock them or use averages.
        
        # Actually, let's look at your TrafficAnalysis code provided.
        # It calculates packet_size from 'len(packet)'. 
        # We can approximate 'packet_size' using 'byte_count / packet_count'.
        if features:
             # Manual Patch for missing 'packet' based fields if they are 0/None
             if features.get('packet_size', 0) == 0:
                 features['packet_size'] = flow_stats['byte_count'] / flow_stats['packet_count']
             
             training_data.append(features)

    print(f"Filtering Complete.")
    print(f"   > Raw Flows:      {len(analyzer.flow_stats)}")
    print(f"   > Ignored (Noise):{ignored_count}")
    print(f"   > Training Flows: {len(training_data)}")

    if not training_data:
        sys.exit("Error: No quality flows found after filtering.")

    # --- PHASE 3: TRAINING ---
    if not check_data_health(training_data):
        sys.exit("Training Aborted.")

    print(f"Training FlowML on {len(training_data)} clean flows...")
    model = FlowMLModel(contamination=CONTAMINATION)
    model.train(training_data)
    
    model.save("models/baseline_model.pkl")
    print("Model saved to models/baseline_model.pkl")

if __name__ == "__main__":
    main()