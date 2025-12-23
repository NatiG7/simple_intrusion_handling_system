import time
import queue
import logging
import signal
import sys
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

# Import your modules
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis
from backend.detection.UnifiedThreatDetection import UnifiedThreatDetection

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S'
)

def main():
    print("[*] Initializing Simple IDS...")

    capture = PacketCapture()
    analyzer = TrafficAnalysis()
    detector = UnifiedThreatDetection()
    
    print("[*] Starting Packet Capture...")
    try:
        capture.start_capture()
    except Exception as e:
        print(f"[!] Failed to start capture: {e}")
        return

    print(f"[*] IDS Running. Press Ctrl+C to stop.")
    
    try:
        packet_count = 0
        
        while True:
            try:
                raw_data, timestamp = capture.packet_queue.get(timeout=1)
                packet = Ether(raw_data)
                packet.time = timestamp
                # reads packet in bytes and extracts fields / headers
                flow_features = analyzer.analyze_packet(packet)
                if flow_features:
                    result = detector.detect(flow_features)
                    
                    if result["is_threat"]:
                        print(f"\n[!!!] ALERT: {result['threat_type']}")
                        print(f"      Source: {packet[IP].src} -> Dest: {packet[IP].dst}")
                        print(f"      Risk Score: {result['risk_score']:.4f}")
                        if "ml_score" in result:
                            print(f"      ML Anomaly Score: {result['ml_score']:.4f}")

                # E. Periodic Cleanup (Every 1000 packets)
                packet_count += 1
                if packet_count % 1000 == 0:
                    removed = analyzer.cleanup_old_flows(timeout=60)
                    if removed > 0:
                        logging.debug(f"Garbage Collection: Removed {removed} old flows.")

            except queue.Empty:
                continue
                
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS...")
        capture.stop_capture_event()
        print("[*] Capture Stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()