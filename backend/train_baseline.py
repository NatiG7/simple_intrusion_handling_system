"""
Baseline training script for the IDS.
Captures normal network traffic and trains the anomaly detection model.
Run this once to establish a baseline, then use main.py for real-time detection.
"""

import os
import sys
import time
import subprocess

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis
from scapy.all import get_if_list, IFACES

# Configuration
TARGET_PACKETS = 5000
CAPTURE_TIMEOUT = 120  # 2 minutes max
CONTAMINATION = 0.05   # Expected anomaly rate (5%)

def select_interface():
    """Select the best active network interface"""
    available_interfaces = get_if_list()
    
    print("Available interfaces:")
    for name in available_interfaces:
        if name in IFACES:
            print(f"  {name}")
            print(f"    Description: {IFACES[name].description}")
            print(f"    IP: {IFACES[name].ip}\n")
    
    # Find interface with valid IP (not loopback or WAN Miniport)
    for name in available_interfaces:
        if name in IFACES:
            iface = IFACES[name]
            desc = iface.description.lower()
            
            if 'loopback' in desc or 'wan miniport' in desc:
                continue
            
            if iface.ip and iface.ip != '0.0.0.0' and iface.ip != '':
                print(f"Selected interface: {iface.description}")
                print(f"IP: {iface.ip}\n")
                return name
    
    print("ERROR: No active network interface found!")
    return None

def generate_traffic():
    """Start background ping processes to generate network traffic"""
    processes = []
    targets = ['8.8.8.8', '1.1.1.1', 'google.com']
    
    for target in targets:
        p = subprocess.Popen(
            ['ping', '-n', '100', '-w', '1000', target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        processes.append(p)
    
    return processes

def capture_baseline(interface, target_packets, timeout):
    """Capture baseline network traffic"""
    sniffer = PacketCapture()
    
    print(f"Capturing up to {target_packets} packets (timeout: {timeout}s)...")
    print("NOTE: This requires Administrator privileges on Windows!")
    print("TIP: Browse the web or stream videos to generate diverse traffic\n")
    
    try:
        start_time = time.time()
        sniffer.start_capture(interface, timeout=timeout)
        
        # Monitor progress
        last_count = 0
        while time.time() - start_time < timeout:
            time.sleep(2)
            current_count = sniffer.packet_queue.qsize()
            
            if current_count > last_count:
                print(f"Captured: {current_count}/{target_packets} packets...")
                last_count = current_count
            
            if current_count >= target_packets:
                print(f"\nTarget reached: {current_count} packets!")
                break
        
        sniffer.stop_capture_event()
        elapsed = time.time() - start_time
        print(f"Capture completed in {elapsed:.1f}s\n")
        
        return list(sniffer.packet_queue.queue)
        
    except PermissionError:
        print("ERROR: Administrator privileges required")
        raise
    except Exception as e:
        print(f"ERROR: {e}")
        raise

def extract_features(packets, analyser):
    """Extract features from captured packets"""
    print("Analyzing packets and extracting features...")
    
    flow_features = []
    progress_interval = max(1, len(packets) // 20)
    
    for i, pkt in enumerate(packets):
        features = analyser.analyze_packet(pkt)
        
        if features:
            flow_features.append(features)
        
        if (i + 1) % progress_interval == 0 or (i + 1) == len(packets):
            percentage = ((i + 1) / len(packets)) * 100
            print(f"  Progress: {i + 1}/{len(packets)} ({percentage:.1f}%)")
    
    return flow_features

def train_model(flow_features, contamination):
    """Train the Isolation Forest model"""
    print(f"\nTraining Isolation Forest on {len(flow_features)} samples...")
    
    ml_model = FlowMLModel(contamination=contamination)
    
    train_start = time.time()
    ml_model.train(flow_features)
    train_time = time.time() - train_start
    
    print(f"Model training complete ({train_time:.2f}s)\n")
    
    return ml_model

def validate_model(ml_model, flow_features):
    """Validate the trained model on baseline data"""
    print("Validating model on baseline data...")
    
    predictions = ml_model.predict(flow_features)
    scores = ml_model.anomaly_score(flow_features)
    
    anomaly_count = sum(1 for p in predictions if p == -1)
    normal_count = len(predictions) - anomaly_count
    anomaly_percentage = (anomaly_count / len(predictions)) * 100
    
    min_score = min(scores)
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)
    
    print("\n" + "="*60)
    print("BASELINE MODEL STATISTICS")
    print("="*60)
    print(f"Total samples: {len(flow_features)}")
    print(f"Normal traffic: {normal_count} ({100-anomaly_percentage:.1f}%)")
    print(f"Flagged anomalies: {anomaly_count} ({anomaly_percentage:.1f}%)")
    print(f"\nAnomaly Score Range:")
    print(f"  Minimum: {min_score:.3f}")
    print(f"  Average: {avg_score:.3f}")
    print(f"  Maximum: {max_score:.3f}")
    print("="*60)
    
    if anomaly_count > 0:
        print(f"\nTop 5 anomalies detected in baseline:")
        anomaly_indices = [(i, s) for i, (p, s) in enumerate(zip(predictions, scores)) if p == -1]
        anomaly_indices.sort(key=lambda x: x[1])
        
        for idx, score in anomaly_indices[:5]:
            print(f"  Packet {idx+1}: Score {score:.3f}")
    
    return ml_model

def main():
    print("="*60)
    print("BASELINE TRAINING MODE")
    print("="*60)
    print(f"Target: {TARGET_PACKETS} packets")
    print(f"Contamination rate: {CONTAMINATION*100}%")
    print("="*60 + "\n")
    
    # Select interface
    interface = select_interface()
    if not interface:
        sys.exit(1)
    
    # Initialize components
    analyser = TrafficAnalysis()
    ping_processes = []
    
    try:
        # Generate background traffic
        print("Starting background traffic generation...")
        ping_processes = generate_traffic()
        
        # Capture packets
        packets = capture_baseline(interface, TARGET_PACKETS, CAPTURE_TIMEOUT)
        print(f"Total captured: {len(packets)} packets\n")
        
        if len(packets) < 100:
            print("WARNING: Less than 100 packets captured!")
            print("Try browsing websites or streaming videos for more traffic")
            sys.exit(1)
        
        # Extract features
        flow_features = extract_features(packets, analyser)
        
        if not flow_features:
            print("\nERROR: No features extracted")
            sys.exit(1)
        
        print(f"\nExtracted features from {len(flow_features)} packets")
        print(f"Feature extraction rate: {len(flow_features)/len(packets)*100:.1f}%\n")
        
        # Train model
        ml_model = train_model(flow_features, CONTAMINATION)
        
        # Validate model
        validate_model(ml_model, flow_features)
        
        # Save the trained model
        model_path = "models/baseline_model.pkl"
        print(f"\nSaving trained model to {model_path}...")
        ml_model.save(model_path)
        
        print("\nBASELINE TRAINING COMPLETE!")
        print("Run main.py for real-time anomaly detection")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Clean up
        for p in ping_processes:
            p.terminate()

if __name__ == "__main__":
    main()