import numpy as np
import pickle
from scapy.utils import PcapReader
from backend.capture.TrafficAnalysis import TrafficAnalysis
from backend.detection.FlowML import FlowMLModel

# Files
MODEL_FILE = "models/baseline_model.pkl"
PCAP_FILE = "backend/attacks/attack_test_1.pcap"

def main():
    print(f"--- DEEP DEBUG DIAGNOSTIC ---")
    
    # 1. Load the Model manually to inspect internals
    print(f"1. Loading {MODEL_FILE}...")
    with open(MODEL_FILE, "rb") as f:
        data = pickle.load(f)
        
    model = data["model"]
    feature_names = data["feature_names"]
    
    print(f"   > Model Feature List: {feature_names[:3]} ...")
    
    if "packet_count" not in feature_names:
        print("\n[FATAL ERROR]: 'packet_count' is MISSING from the model's brain.")
        print("The model was saved with the old code. You need to re-save the class definition.")
        return

    # 2. Extract Features from the Attack File
    print(f"2. Reading first packet from {PCAP_FILE}...")
    analyzer = TrafficAnalysis()
    target_features = None
    
    with PcapReader(PCAP_FILE) as pcap:
        for packet in pcap:
            # We only need the first one to prove the point
            target_features = analyzer.analyze_packet(packet)
            if target_features:
                break
    
    if not target_features:
        print("Error: Could not extract features from PCAP.")
        return

    print(f"   > Extracted 'packet_count': {target_features.get('packet_count')}")
    print(f"   > Extracted 'flow_duration': {target_features.get('flow_duration')}")

    # 3. Vectorize (Simulate what FlowML does internally)
    # We manually build the row to see if it matches expectations
    row = [float(target_features.get(name, 0)) for name in feature_names]
    
    print(f"\n3. The Vector (What the model sees):")
    print(f"   {row[:5]} ...")
    
    # 4. Check the Index of packet_count
    pc_index = feature_names.index("packet_count")
    print(f"   > Value at index {pc_index} (packet_count): {row[pc_index]}")

    if row[pc_index] == 0:
        print("\n[DIAGNOSIS]: The model sees '0' packets. The feature extraction is failing.")
    elif row[pc_index] == 1:
        print(f"\n[DIAGNOSIS]: The model sees '1' packet.")
        
        # 5. Run Prediction directly
        # We need to scale it first using the saved scaler
        scaler = data["scaler"]
        vector_np = np.array([row])
        vector_scaled = scaler.transform(vector_np)
        
        pred = model.predict(vector_scaled)[0]
        score = model.decision_function(vector_scaled)[0]
        
        print(f"   > Scaled Input: {vector_scaled[0][:5]}...")
        print(f"   > Prediction: {pred} (1=Normal, -1=Attack)")
        print(f"   > Anomaly Score: {score:.4f} (Negative = Abnormal)")
        
        if pred == 1:
            print("\n[CONCLUSION]: The model STILL thinks this is normal.")
            print("This implies the 'Normal' training data wasn't as clean as we thought,")
            print("OR the Contamination parameter (0.01) is too conservative.")
    
if __name__ == "__main__":
    main()