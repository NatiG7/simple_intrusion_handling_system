import os
import sys
import time

from backend.detection.FlowML import FlowMLModel
ml_model = FlowMLModel(contamination=0.05)

flow_features = []

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.capture.PacketCapture import *
from backend.capture.TrafficAnalysis import *

sniffer = PacketCapture()
analyser = TrafficAnalysis()

print("Capturing packets for 5 seconds. . .")
sniffer.start_capture("wlan0")
time.sleep(5)

sniffer.stop_capture_event()

packets = list(sniffer.packet_queue.queue)
print(f"\n✅ Captured {len(packets)} packets.")

for i, pkt in enumerate(packets):
    print(f"\n📦 Packet {i+1}:")
    print(pkt.summary())
    
    print("Analyzing packets...")

    features = analyser.analyze_packet(pkt)
    
    if features:
        print("Packet Features :", features)
        flow_features.append(features)
    else:
        print("⚠️ No analyzable features found.")

if flow_features:
    predictions = ml_model.predict(flow_features)
    scores = ml_model.anomaly_score(flow_features)
    print("\n--- ML Predictions ---")
    for i, (pred, score) in enumerate(zip(predictions, scores)):
        status = "ANOMALY" if pred == -1 else "NORMAL"
        print(f"Packet {i+1}: {status}, Anomaly Score: {score:.3f}")
