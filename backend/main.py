# backend/main.py
"""
Real-time intrusion detection system.
Loads a pre-trained baseline model and detects anomalies in live traffic.
Run train_baseline.py first to create the baseline model.
"""

import os
import sys
import time
import subprocess
import ipaddress

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis
from scapy.all import get_if_list, IFACES

# Configuration
CAPTURE_DURATION = 100  # seconds
MODEL_PATH = "models/baseline_model.pkl"

def is_apipa(ip):
    # check if IP is a local temp IP
    try:
        return ipaddress.ip_address(ip).is_link_local
    except:
        return True

def select_interface():
    """Select the best active network interface"""
    available_interfaces = get_if_list()
    
    print("Available interfaces:")
    for name in available_interfaces:
        if name in IFACES:
            print(f"  {name}")
            print(f"    Description: {IFACES[name].description}")
            print(f"    IP: {IFACES[name].ip}\n")

    # 1. Prefer Wi-Fi or Ethernet
    for name in available_interfaces:
        if name in IFACES:
            iface = IFACES[name]
            desc = iface.description.lower()
            ip = iface.ip

            if ('wi-fi' in desc or 'wireless' in desc or 'realtek' in desc or 'ethernet' in desc) \
               and ip and ip != '0.0.0.0' and not is_apipa(ip):
                print(f"Selected interface: {iface.description}")
                print(f"IP: {iface.ip}\n")
                return name

    # 2. Fallback: any non-WAN, non-loopback, non-APIPA interface
    for name in available_interfaces:
        if name in IFACES:
            iface = IFACES[name]
            desc = iface.description.lower()
            ip = iface.ip
            
            if 'loopback' in desc or 'wan miniport' in desc:
                continue
            if ip and ip != '0.0.0.0' and not is_apipa(ip):
                print(f"Selected interface: {iface.description}")
                print(f"IP: {iface.ip}\n")
                return name
    
    print("ERROR: No active network interface found!")
    return None

def main():
    print("="*60)
    print("REAL-TIME INTRUSION DETECTION SYSTEM")
    print("="*60 + "\n")
    
    # Check if baseline model exists
    if not FlowMLModel.model_exists(MODEL_PATH):
        print(f"ERROR: Baseline model not found at {MODEL_PATH}")
        print("Please run train_baseline.py first to create a baseline model")
        sys.exit(1)
    
    # Load the trained model
    print("Loading baseline model...")
    ml_model = FlowMLModel()
    ml_model.load(MODEL_PATH)
    print()
    
    # Select interface
    interface = select_interface()
    if not interface:
        print("ERROR: No active network interface found")
        sys.exit(1)
    
    # Initialize components
    sniffer = PacketCapture()
    analyser = TrafficAnalysis()
    
    # Generate some traffic
    print("Generating background traffic...")
    ping_process = subprocess.Popen(
        ['ping', '-n', '10', '8.8.8.8'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    print(f"Capturing packets for {CAPTURE_DURATION} seconds...")
    print("NOTE: This requires Administrator privileges on Windows!\n")
    
    try:
        # Capture packets
        sniffer.start_capture(interface, timeout=CAPTURE_DURATION)
        time.sleep(CAPTURE_DURATION + 1)
        sniffer.stop_capture_event()
        
        packets = list(sniffer.packet_queue.queue)
        print(f"Captured {len(packets)} packets\n")
        
        if len(packets) == 0:
            print("WARNING: No packets captured")
            sys.exit(1)
        
        # Extract features
        print("Analyzing packets...")
        flow_features = []
        
        for pkt in packets:
            features = analyser.analyze_packet(pkt)
            if features:
                flow_features.append(features)
        
        if not flow_features:
            print("ERROR: No features extracted")
            sys.exit(1)
        
        print(f"Extracted features from {len(flow_features)} packets\n")
        
        # Predict anomalies
        print("Running anomaly detection...")
        predictions = ml_model.predict(flow_features)
        scores = ml_model.anomaly_score(flow_features)
        
        # Display results
        print("\n" + "="*60)
        print("DETECTION RESULTS")
        print("="*60)
        
        anomaly_count = 0
        anomalies = []
        
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:
                anomaly_count += 1
                anomalies.append((i, score))
                status = "ANOMALY"
            else:
                status = "NORMAL"
            
            # Only show anomalies and first few normal packets
            if pred == -1 or i < 3:
                print(f"Packet {i+1}: {status}, Anomaly Score: {score:.3f}")
        
        if len(flow_features) > 3 and anomaly_count < len(flow_features):
            print(f"... ({len(flow_features) - anomaly_count - 3} more normal packets)")
        
        print("\n" + "="*60)
        print(f"Summary: {anomaly_count}/{len(flow_features)} anomalies detected")
        print(f"Normal: {len(flow_features) - anomaly_count}/{len(flow_features)} packets")
        print("="*60)
        
        # Show top anomalies
        if anomalies:
            anomaly_percentage = len(anomalies) / len(predictions) * 100
            print("\nTop anomalies (lowest scores):")
            anomalies.sort(key=lambda x: x[1])
            for idx, score in anomalies[:5]:
                print(f"  Packet {idx+1}: Score {score:.3f}")
            print(f"Anomaly percentage : {anomaly_percentage:.2f}%")
        
    except PermissionError:
        print("ERROR: Administrator privileges required")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        ping_process.terminate()

if __name__ == "__main__":
    main()