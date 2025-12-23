import sys
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, Ether
from backend.detection.UnifiedThreatDetection import UnifiedThreatDetection
from backend.capture.TrafficAnalysis import TrafficAnalysis

# temp enable logging info
import logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

PCAP_FILE = "backend/attacks/attack_test_1.pcap" 

def main():
    print("=== System Evaluation (Signatures + ML) ===")

    # 1. Initialize the Full Engine
    detector = UnifiedThreatDetection()
    analyzer = TrafficAnalysis()
    
    print(f"Reading {PCAP_FILE}...")
    
    stats = {"Total": 0, "Normal": 0, "Signatures": 0, "ML_Anomalies": 0}
    
    with PcapReader(PCAP_FILE) as pcap_reader:
        for packet in pcap_reader:
            stats["Total"] += 1
            
            if packet.haslayer(IP) and packet.haslayer(TCP):
                # 2. micro + macro
                combined_features = analyzer.analyze_packet(packet)
                
                if combined_features:
                    # detect
                    result = detector.detect(combined_features)
                    
                    if result["is_threat"]:
                        if result["engine"] == "Signature":
                            stats["Signatures"] += 1
                        else:
                            stats["ML_Anomalies"] += 1
                        
                        # print first few alerts
                        if (stats["Signatures"] + stats["ML_Anomalies"]) <= 5:
                            print(f"[!] {result['threat_type']} detected! (Packet #{stats['Total']})")
                    else:
                        stats["Normal"] += 1
            
            if stats["Total"] % 1000 == 0:
                print(f"Processed {stats['Total']} packets...", end='\r')

    # 4. Final Report
    print(f"\n\n{'='*30}")
    print(f"FINAL REPORT")
    print(f"{'='*30}")
    print(f"Total Packets:      {stats['Total']}")
    print(f"Flood Detections:   {stats['Signatures']} (Signature Engine)")
    print(f"Content Anomalies:  {stats['ML_Anomalies']} (ML Engine)")
    
    threat_count = stats['Signatures'] + stats['ML_Anomalies']
    rate = (threat_count / stats['Total']) * 100 if stats['Total'] else 0
    print(f"Overall Detection:  {rate:.2f}%")
    print(f"{'='*30}")

if __name__ == "__main__":
    main()