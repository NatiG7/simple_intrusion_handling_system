import sys
import logging
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, Ether
from backend.capture.TrafficAnalysis import TrafficAnalysis
from backend.detection.UnifiedThreatDetection import UnifiedThreatDetection

# Configure logging to see model status
logging.basicConfig(level=logging.INFO, format='%(message)s')

PCAP_FILE = "backend/attacks/attack_test_1.pcap" 

def main():
    print(f"=== DIAGNOSTIC MODE: Analyzing {PCAP_FILE} ===")
    
    # 1. Setup
    detector = UnifiedThreatDetection()
    analyzer = TrafficAnalysis()
    
    packet_count = 0
    detections = 0
    
    print("\n[!] Starting Packet Inspection...")
    
    with PcapReader(PCAP_FILE) as pcap_reader:
        for packet in pcap_reader:
            packet_count += 1
            
            if packet.haslayer(IP) and packet.haslayer(TCP):
                # 2. Get the Feature Box
                combined_features = analyzer.analyze_packet(packet)
                
                # DIAGNOSTIC: Check what is actually inside
                if combined_features:
                    macro = combined_features.get("macro", {})
                    
                    # 3. Check Vital Signs every 500 packets
                    if packet_count % 500 == 0:
                        syn = macro.get("syn_count", 0)
                        rate = macro.get("packet_rate", 0.0)
                        duration = macro.get("flow_duration", 0.0)
                        
                        print(f"--- Packet #{packet_count} ---")
                        print(f"   > Macro SYN Count: {syn}  (Threshold: >100)")
                        print(f"   > Macro Rate:      {rate:.2f} (Threshold: >50)")
                        print(f"   > Flow Duration:   {duration:.4f}s")
                        
                        if syn < 2:
                            print("   [CRITICAL FAIL] Aggregation is not working. Count is 1.")
                        elif rate == 0:
                            print("   [CRITICAL FAIL] Rate is 0. Duration issue?")
                    
                    # 4. Run Detection
                    result = detector.detect(combined_features)
                    if result["is_threat"]:
                        detections += 1
                        if detections == 1:
                            print(f"\n[SUCCESS] FIRST DETECTION at Packet #{packet_count}!")
                            print(f"   > Type: {result['threat_type']}")
                            
    print(f"\n=== RESULT: {detections} Detections out of {packet_count} Packets ===")

if __name__ == "__main__":
    main()