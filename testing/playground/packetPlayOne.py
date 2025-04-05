import os
import sys
import time

from backend.capture.PacketCapture import PacketCapture

WAIT_SECONDS = 2
packet_data = {}
capture_instance = PacketCapture()

capture_instance.start_capture("Ethernet")

time.sleep(WAIT_SECONDS)

print(f"Captured {capture_instance.packet_queue.qsize()} packets in {WAIT_SECONDS} seconds!")

from backend.capture.TrafficAnalysis import TrafficAnalysis

analysis = TrafficAnalysis()
print("=" * 90)
print("Starting packet analysis")
packet_num = 0
while not capture_instance.packet_queue.empty():
    packet_num += 1
    packet = capture_instance.packet_queue.get()
    print(f"Packet : {packet.summary()}")
    analysis.analyze_packet(packet)

capture_instance.stop_capture_event()
print("Capture stopped.")

print("Accessing flow_stats : ")
print(analysis.flow_stats)


