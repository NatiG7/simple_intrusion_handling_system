"""
Script to evaluate the trained FlowML model against a PCAP file.
Calculates the Detection Rate (Percentage of anomalies detected).
"""

import os
import sys
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP
from backend.detection.FlowML import FlowMLModel
from backend.capture.TrafficAnalysis import TrafficAnalysis

# config
PCAP_FILE = "backend/attacks/attack_test_1.pcap" 
MODEL_PATH = "models/baseline_model.pkl"

def main():
    print("=== Model Evaluation ===")

    # Load Model
    print(f"Loading model from {MODEL_PATH}...")
    model = FlowMLModel()
    try:
        model.load(MODEL_PATH)
    except FileNotFoundError:
        sys.exit("Error: Model file not found. Train the baseline first.")

    # Setup Analyzer
    analyzer = TrafficAnalysis()
    
    # Process PCAP
    if not os.path.exists(PCAP_FILE):
        sys.exit(f"Error: PCAP file not found: {PCAP_FILE}")

    print(f"Reading {PCAP_FILE}...")
    
    features_list = []
    packet_count = 0
    
    # Use PcapReader for memory efficiency with large files
    with PcapReader(PCAP_FILE) as pcap_reader:
        for packet in pcap_reader:
            packet_count += 1
            if packet_count % 1000 == 0:
                print(f"Processed {packet_count} packets...", end='\r')
            
            # Extract features exactly as we did during training
            if packet.haslayer(IP) and packet.haslayer(TCP):
                features = analyzer.analyze_packet(packet)
                if features:
                    features_list.append(features)

    print(f"\nExtraction complete. Analyzed {len(features_list)} flows from {packet_count} packets.")

    if not features_list:
        sys.exit("No TCP/IP features extracted. Is the PCAP empty or non-TCP?")

    # Predict
    print("Running inference...")
    predictions = model.predict(features_list)
    
    # Calculate Metrics
    # IsolationForest: 1 = Normal, -1 = Anomaly
    total = len(predictions)
    anomalies = predictions.count(-1)
    normals = predictions.count(1)
    
    detection_rate = (anomalies / total) * 100
    
    print("-" * 30)
    print(f"Total Flows Checked: {total}")
    print(f"Normal Flags (1):    {normals}")
    print(f"Anomalies Found (-1):{anomalies}")
    print("-" * 30)
    print(f"DETECTION RATE:      {detection_rate:.2f}%")
    print("-" * 30)

    if detection_rate > 90:
        print("RESULT: EXCELLENT detection capability.")
    elif detection_rate > 50:
        print("RESULT: MODERATE detection. Consider tuning contamination.")
    else:
        print("RESULT: POOR detection. Model may be overfitted to baseline.")

if __name__ == "__main__":
    main()