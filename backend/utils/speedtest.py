"""
Total System Benchmark
Measures the maximum theoretical throughput (PPS) of the IDS logic.
Tests components in isolation: Extraction vs. ML vs. End-to-End.
"""

import time
import logging
import random
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from backend.capture.TrafficAnalysis import TrafficAnalysis
from backend.detection.UnifiedThreatDetection import UnifiedThreatDetection
from backend.detection.FlowML import FlowMLModel

# Silence logs
logging.getLogger().setLevel(logging.ERROR)

# --- Config ---
TEST_PACKETS = 5000  # Number of iterations per test
MODEL_PATH = "models/baseline_model.pkl"

def generate_dummy_packet():
    """Pre-generates a standard TCP packet to avoid Scapy creation overhead during test."""
    pkt = Ether()/IP(src="192.168.1.100", dst="192.168.1.5")/TCP(dport=80, flags="S")
    return Ether(bytes(pkt))

def benchmark_analysis(packet):
    print(f"1. Benchmarking Feature Extraction (TrafficAnalysis)...")
    analyzer = TrafficAnalysis()
    
    start = time.perf_counter()
    for _ in range(TEST_PACKETS):
        # We use the same packet to stress-test the update logic
        # In a real scenario, dictionary lookups would be slightly slower (more flows)
        analyzer.analyze_packet(packet)
    end = time.perf_counter()
    
    duration = end - start
    pps = TEST_PACKETS / duration
    print(f"   -> Result: {pps:.0f} packets/sec")
    return pps, analyzer # Return analyzer to use its extracted features for next test

def benchmark_ml(features):
    print(f"2. Benchmarking ML Inference (FlowML)...")
    model = FlowMLModel()
    try:
        model.load(MODEL_PATH)
    except:
        print("   [!] Model not found. Skipping ML benchmark.")
        return 0

    # Prepare a single feature vector (Micro view)
    micro_feat = features.get('micro')
    if not micro_feat:
        print("   [!] No micro features found to test.")
        return 0

    start = time.perf_counter()
    for _ in range(TEST_PACKETS):
        # Simulate predicting on a single packet's features
        model.predict([micro_feat])
    end = time.perf_counter()
    
    duration = end - start
    ips = TEST_PACKETS / duration # Inferences Per Second
    print(f"   -> Result: {ips:.0f} inferences/sec")
    return ips

def benchmark_pipeline(packet):
    print(f"3. Benchmarking Full Pipeline (End-to-End)...")
    analyzer = TrafficAnalysis()
    detector = UnifiedThreatDetection()
    
    start = time.perf_counter()
    for _ in range(TEST_PACKETS):
        features = analyzer.analyze_packet(packet)
        if features:
            detector.detect(features)
    end = time.perf_counter()
    
    duration = end - start
    pps = TEST_PACKETS / duration
    print(f"   -> Result: {pps:.0f} packets/sec")
    return pps

def main():
    print(f"=== IDS SPEED LIMIT TEST ({TEST_PACKETS} Iterations) ===")
    print("Generating in-memory packet...")
    dummy_pkt = generate_dummy_packet()
    
    # 1. Test Analysis Logic
    pps_analysis, analyzer = benchmark_analysis(dummy_pkt)
    
    # Get a valid feature set for the ML test
    # We grab the features from the last packet processed
    last_conn_key = list(analyzer.flow_stats.keys())[0]
    valid_features = analyzer.extract_features(dummy_pkt, analyzer.flow_stats[last_conn_key])
    # Wrap it like the detector expects
    boxed_features = {"micro": valid_features, "macro": {}} 
    
    # 2. Test AI Brain
    pps_ml = benchmark_ml(boxed_features)
    
    # 3. Test Everything Together
    pps_total = benchmark_pipeline(dummy_pkt)
    
    print(f"\n{'='*30}")
    print(f"FINAL SCORECARD")
    print(f"{'='*30}")
    print(f"Feature Extraction:  {pps_analysis:>6.0f} PPS  (The Parser)")
    print(f"AI Prediction:       {pps_ml:>6.0f} IPS  (The Brain)")
    print(f"FULL SYSTEM:         {pps_total:>6.0f} PPS  (Real Speed)")
    print(f"{'='*30}")
    
    if pps_total > 1000:
        print("VERDICT: HIGH PERFORMANCE (Suitable for >100Mbps traffic)")
    elif pps_total > 100:
        print("VERDICT: MEDIUM PERFORMANCE (Suitable for home networks)")
    else:
        print("VERDICT: LOW PERFORMANCE (Optimization required)")

if __name__ == "__main__":
    main()