"""
Main Entry Point: Playground Runner
Run this file to choose which showcase to execute.
"""
import threading
import time
import sys

# Import our modules
import TheAttacker as gen
import TheEyes as sniffer
import TheBrain as analyzer
import ThePolice as detector
import TheScreen as dash

# Global instances
flow_engine = analyzer.FlowAnalyzer()
detect_engine = detector.SimpleDetector()

def callback_microscope(packet):
    """Showcase 1: Just see the packets."""
    data = sniffer.dissect_packet(packet)
    dash.log_packet(data)

def callback_full_stack(packet):
    """Showcase 2: Analyze & Detect."""
    data = sniffer.dissect_packet(packet)
    
    # 1. Analyze Flow
    result = flow_engine.process_packet(data)
    if result:
        key, stats = result
        dash.log_flow_update(key, stats)
        
        # 2. Check Rules
        alerts = detect_engine.check_flow(key, stats)
        for alert in alerts:
            dash.log_alert(alert)

def run_sniffer_thread(callback):
    t = threading.Thread(target=sniffer.start_sniffing, kwargs={'count':0, 'prn_callback':callback})
    t.daemon = True
    t.start()
    return t

def main():
    print("=== IDS PLAYGROUND SHOWCASE ===")
    print("1. Packet Microscope (See Raw Packets)")
    print("2. Flow Analyzer (Watch Stats Build)")
    print("3. Attack Simulation (SYN Flood + Detection)")
    print("4. Traffic Simulation (HTTP Traffic)")
    
    choice = input("\nSelect Showcase (1-4): ")

    if choice == "1":
        print("\n[Mode] Packet Microscope. Waiting for traffic...")
        sniffer.start_sniffing(prn_callback=callback_microscope)

    elif choice == "2":
        print("\n[Mode] Flow Analyzer. Waiting for traffic...")
        sniffer.start_sniffing(prn_callback=callback_full_stack)

    elif choice == "3":
        print("\n[Mode] Attack Sim. Starting Sniffer in background...")
        run_sniffer_thread(callback_full_stack)
        time.sleep(2)
        print("\n[+] Launching SYN Flood Attack...")
        gen.send_syn_flood(count=20)
        input("\nPress Enter to stop...")

    elif choice == "4":
        print("\n[Mode] Traffic Sim. Starting Sniffer in background...")
        run_sniffer_thread(callback_full_stack)
        time.sleep(2)
        print("\n[+] Launching HTTP Traffic...")
        gen.send_http_traffic()
        input("\nPress Enter to stop...")

if __name__ == "__main__":
    main()