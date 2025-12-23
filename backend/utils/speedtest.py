"""
Total System Benchmark (Fast Mode)
Measures the maximum throughput (PPS) using the new Byte-Level Parser.
"""

import time
import logging
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from backend.capture.TrafficAnalysis import TrafficAnalysis
from backend.detection.UnifiedThreatDetection import UnifiedThreatDetection
from backend.detection.FlowML import FlowMLModel

# Silence logs
logging.getLogger().setLevel(logging.INFO)

# --- Config ---
TEST_PACKETS = 50000  # Increased iterations since it should be much faster now
MODEL_PATH = "models/baseline_model.pkl"

def generate_dummy_bytes():
    """
    Generates a valid raw byte sequence for a TCP packet.
    Forces Scapy to calculate lengths/checksums before converting to bytes.
    """
    # 1. Create Scapy Object
    pkt = Ether()/IP(src="192.168.1.100", dst="192.168.1.5")/TCP(dport=80, flags="S")
    
    # 2. Build it (forces calculation of IHL, Len, Checksum)
    built_pkt = Ether(bytes(pkt))
    
    # 3. Return as immutable bytes (Fast Mode input)
    return bytes(built_pkt)

def benchmark_analysis(raw_bytes):
    print(f"1. Benchmarking Fast Feature Extraction...")
    analyzer = TrafficAnalysis()
    
    start = time.perf_counter()
    for _ in range(TEST_PACKETS):
        # Passing BYTES triggers the new parse_packet_fast logic
        analyzer.analyze_packet(raw_bytes)
    end = time.perf_counter()
    
    duration = end - start
    pps = TEST_PACKETS / duration
    print(f"   -> Result: {pps:.0f} packets/sec")
    
    # Return analyzer to get features for next step
    return pps, analyzer

def benchmark_ml(features):
    print(f"2. Benchmarking ML Inference (FlowML)...")
    model = FlowMLModel()
    try:
        model.load(MODEL_PATH)
    except:
        print("   [!] Model not found. Skipping ML benchmark.")
        return 0

    micro_feat = features.get('micro')
    if not micro_feat:
        print("   [!] No micro features found.")
        return 0

    start = time.perf_counter()
    for _ in range(TEST_PACKETS // 10): # ML is slower, run fewer to save time
        model.predict([micro_feat])
    end = time.perf_counter()
    
    duration = end - start
    # Scale back up to 1 second
    ips = (TEST_PACKETS // 10) / duration
    print(f"   -> Result: {ips:.0f} inferences/sec")
    return ips

def benchmark_pipeline(raw_bytes):
    print(f"3. Benchmarking Full Pipeline (End-to-End)...")
    analyzer = TrafficAnalysis()
    detector = UnifiedThreatDetection()
    
    start = time.perf_counter()
    for _ in range(TEST_PACKETS // 5):
        features = analyzer.analyze_packet(raw_bytes)
        if features:
            detector.detect(features)
    end = time.perf_counter()
    
    duration = end - start
    pps = (TEST_PACKETS // 5) / duration
    print(f"   -> Result: {pps:.0f} packets/sec")
    return pps

def main():
    print(f"=== IDS SPEED LIMIT TEST (Fast Mode) ===")
    print("Generating raw packet bytes...")
    raw_bytes = generate_dummy_bytes()
    print(f"Packet Size: {len(raw_bytes)} bytes")
    
    # 1. Test Analysis Logic (Fast Parser)
    pps_analysis, analyzer = benchmark_analysis(raw_bytes)
    
    # Get features for ML test
    # (We need to extract features once to get a valid input for the ML model)
    # We access the internal flow stats to simulate a "ready" feature set
    last_conn_key = list(analyzer.flow_stats.keys())[0]
    valid_features = analyzer.extract_features(None, analyzer.flow_stats[last_conn_key])
    boxed_features = {"micro": valid_features, "macro": {}}
    
    # 2. Test AI Brain
    pps_ml = benchmark_ml(boxed_features)
    
    # 3. Test Full Pipeline
    pps_total = benchmark_pipeline(raw_bytes)
    
    print(f"\n{'='*30}")
    print(f"FINAL SCORECARD (Fast Mode)")
    print(f"{'='*30}")
    print(f"Feature Extraction:  {pps_analysis:>6.0f} PPS  (New Parser)")
    print(f"AI Prediction:       {pps_ml:>6.0f} IPS  (The Brain)")
    print(f"FULL SYSTEM:         {pps_total:>6.0f} PPS  (Real Speed)")
    print(f"{'='*30}")

if __name__ == "__main__":
    main()