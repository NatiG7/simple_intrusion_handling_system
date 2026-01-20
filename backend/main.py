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
from backend.database.DatabaseManager import DatabaseManager

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
        db = DatabaseManager(uri="mongodb://localhost:27017/", db_name="ids_db")
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
                        # alert_payload = {
                        #     "src_ip": packet[IP].src,
                        #     "dst_ip": packet[IP].dst,
                        #     "threat_type": result['threat_type'],
                        #     "risk_score": float(result['risk_score']), # Ensure native types
                        #     "ml_score": float(result.get('ml_score', 0)),
                        #     "timestamp": packet.time
                        # }
                        alert_payload = flow_features
                        db.log_alert(alert_payload)
                        print(f"[!!!] Logged Alert: {result['threat_type']}")
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