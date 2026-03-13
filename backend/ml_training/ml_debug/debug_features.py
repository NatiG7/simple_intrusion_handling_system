from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP
from backend.capture.TrafficAnalysis import TrafficAnalysis

# Point to your generated attack file
PCAP_FILE = "backend/attacks/attack_test_1.pcap"

def main():
    print(f"--- Inspecting Features from {PCAP_FILE} ---")
    analyzer = TrafficAnalysis()

    count = 0
    with PcapReader(PCAP_FILE) as pcap:
        for packet in pcap:
            if packet.haslayer(TCP):
                # Analyze the packet
                features = analyzer.analyze_packet(packet)
                
                # Print the critical features for the first 5 packets
                print(f"\nPacket {count+1}:")
                print(f"  Flow Duration: {features['micro'].get('flow_duration')}")
                print(f"  Packet Count:  {features['micro'].get('packet_count')}")
                print(f"  SYN Count:     {features['micro'].get('syn_count')} (Should be 1)")
                print(f"  ACK Count:     {features['micro'].get('ack_count')}")
                print(f"  IAT (Timing):  {features['micro'].get('avg_iat')}")
                
                count += 1
                if count >= 5:
                    break

if __name__ == "__main__":
    main()