import os
import sys
import time

# Add parent directory to path to enable absolute imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import *
from backend.capture.TrafficAnalysis import *
from scapy.all import get_if_list

ml_model = FlowMLModel(contamination=0.05)

flow_features = []

# Get available network interfaces
available_interfaces = get_if_list()
print(f"Available interfaces: {available_interfaces}")

# Try WiFi first, then fall back to available interfaces
interface = None
for iface in ["WiFi", "wlan0", "WLAN"]:
    if iface in available_interfaces:
        interface = iface
        break

# If no WiFi found, use the first available interface (excluding loopback)
if not interface:
    interface = next((iface for iface in available_interfaces if iface.lower() not in ["lo", "loopback"]), available_interfaces[0] if available_interfaces else None)

if not interface:
    print("❌ No network interfaces found! Make sure you're running as Administrator.")
    sys.exit(1)

print(f"Using interface: {interface}")

sniffer = PacketCapture()
analyser = TrafficAnalysis()

print("Capturing packets for 5 seconds. . .")
print("⚠️  Note: This requires Administrator/sudo privileges on Windows!")
try:
    sniffer.start_capture(interface)
    time.sleep(5)
    sniffer.stop_capture_event()
except PermissionError:
    print("❌ Error: This script requires Administrator privileges on Windows.")
    print("   Please run as Administrator (right-click cmd/PowerShell > Run as Administrator)")
    sys.exit(1)
except ValueError as e:
    print(f"❌ Error: {e}")
    sys.exit(1)

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
