import time
import queue
import logging
import threading
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

def db_writer(alert_queue: queue.Queue, db: DatabaseManager):
    while True:
        batch = []
        try:
            batch.append(alert_queue.get(timeout=1))
            for _ in range(49):
                try:
                    batch.append(alert_queue.get_nowait())
                except queue.Empty:
                    break
            if batch:
                db.log_alerts_batch(batch)
        except queue.Empty:
            continue

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
        last_gc_time = time.time()
        alert_queue = queue.Queue()
        threading.Thread(target=db_writer,args=(alert_queue, db), daemon=True).start()
        while True:
            try:
                raw_data, timestamp = capture.packet_queue.get(timeout=1)
                packet = Ether(raw_data)
                packet.time = timestamp
                # reads packet in bytes and extracts fields / headers
                flow_features = analyzer.analyze_packet(raw_data, timestamp=timestamp)
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
                        alert_payload = {
                            **flow_features.get("micro", {}),
                            "threat_type": result['threat_type'],
                            "risk_score": result['risk_score'],
                            "src_ip": packet[IP].src,
                            "dst_ip": packet[IP].dst,
                            "timestamp":timestamp
                        }
                        alert_queue.put(alert_payload)
                        print(f"[!!!] Logged Alert: {result['threat_type']}")
                        print(f"\n[!!!] ALERT: {result['threat_type']}")
                        print(f"      Source: {packet[IP].src} -> Dest: {packet[IP].dst}")
                        print(f"      Risk Score: {result['risk_score']:.4f}")
                        if "ml_score" in result:
                            print(f"      ML Anomaly Score: {result['ml_score']:.4f}")

                # E. Periodic Cleanup (Every 1000 packets)
                current_time = time.time()
                if current_time - last_gc_time > 60:
                    removed_src = analyzer.cleanup_old_flows(timeout=60)
                    removed_dst = analyzer.cleanup_old_dst_flows(max_age=3)
                    last_gc_time = current_time
                    if removed_src > 0 or removed_dst > 0:
                        logging.debug(f"[GC] Removed {removed_src} source flows, {removed_dst} destination flows")

            except queue.Empty:
                continue
                
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS...")
        capture.stop_capture_event()
        print("[*] Capture Stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()