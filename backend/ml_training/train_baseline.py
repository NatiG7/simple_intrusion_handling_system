import sys
import time
import queue
from typing import List, Dict, Any
from scapy.layers.l2 import Ether  # Needed for packet reconstruction

from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis

# --- Configuration ---
TARGET_UNIQUE_FLOWS = 1000  
TIMEOUT = 1200  
CONTAMINATION = 0.01

def check_data_health(features: List[Dict[str, Any]]) -> bool:
    print("\n--- Data Health Check ---")
    if not features:
        print("FAIL: No features extracted.")
        return False
    
    total_packets = sum(f.get('packet_count', 0) for f in features)
    print(f"Total Packets across {len(features)} flows: {total_packets}")
    
    if total_packets == 0:
        print("CRITICAL: Packets not being counted.")
        return False

    syn = sum(f.get('syn_count', 0) for f in features)
    ack = sum(f.get('ack_count', 0) for f in features)
    if syn == 0 and ack == 0:
        print("WARNING: No TCP Flags detected. (Might be okay for pure background traffic)")
    
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
        while True:
            try:
                # unpack the tuple (bytes, timestamp)
                raw_data, timestamp = capture.packet_queue.get(timeout=0.1)
                processed_packets += 1
                
                # reconstruct Packet
                packet = Ether(raw_data)
                packet.time = timestamp
            
                analyzer.analyze_packet(packet)
                
            except queue.Empty:
                pass
            except Exception:
                # Ignore malformed packets
                pass

            # Check Status
            unique_flows = len(analyzer.flow_stats)
            
            # Update UI
            if processed_packets % 50 == 0:
                print(f"Packets: {processed_packets} | Unique Flows In Memory: {unique_flows}/{TARGET_UNIQUE_FLOWS}", end='\r')

            # Stop Condition: Target Reached
            if unique_flows >= TARGET_UNIQUE_FLOWS:
                print("\nTarget flow count reached.")
                break
            
            # Stop Condition: Timeout
            if time.time() - start_time > TIMEOUT:
                print("\nTimeout reached.")
                break
            
            # NOTE: Cleanup removed here to ensure we accumulate data without deleting it.

    except KeyboardInterrupt:
        print("\nStopping capture early...")
    
    capture.stop_capture_event()
    
    print(f"\n\nProcessing {len(analyzer.flow_stats)} raw flows...")
    
    training_data = []
    ignored_count = 0
    
    # Iterate through the analyzer's memory
    for flow_key, flow_stats in analyzer.flow_stats.items():
        # Filter noise
        if flow_stats['packet_count'] < 3 or flow_stats['flow_duration'] == 0:
            ignored_count += 1
            continue

        # Extract features
        # We pass None as packet because we are extracting from stored stats
        features = analyzer.extract_features(None, flow_stats) 

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

    if not check_data_health(training_data):
        sys.exit("Training Aborted.")

    print(f"Training FlowML on {len(training_data)} clean flows...")
    model = FlowMLModel(contamination=CONTAMINATION)
    model.train(training_data)
    
    model.save("models/baseline_model.pkl")
    print("Model saved to models/baseline_model.pkl")

if __name__ == "__main__":
    main()