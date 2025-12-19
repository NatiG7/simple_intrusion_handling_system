"""
Directly probes the trained model to see its decision boundary.
"""
import sys
from backend.detection.FlowML import FlowMLModel

def main():
    print("Loading model...")
    model = FlowMLModel()
    try:
        model.load("models/baseline_model.pkl")
    except Exception as e:
        sys.exit(f"Failed to load model: {e}")

    print(f"Model expects features: {model.feature_names[:5]}...")

    # --- TEST CASE 1: The "Ideal" Normal User ---
    # 500 packets, 300KB, 10 seconds duration (YouTube-ish)
    normal_flow = {
        "packet_count": 500,        # <--- HIGH count
        "packet_size": 600,
        "flow_duration": 10.0,
        "packet_rate": 50.0,
        "byte_rate": 30000.0,
        "syn_count": 1,
        "ack_count": 499,
        "fin_count": 1,
        "avg_iat": 0.02
    }

    # --- TEST CASE 2: The "Syn Flood" Attacker ---
    # 1 packet, 0 duration (The attack we generated)
    attack_flow = {
        "packet_count": 1,          # <--- LOW count
        "packet_size": 60,
        "flow_duration": 0.0,
        "packet_rate": 0.0,
        "byte_rate": 0.0,
        "syn_count": 1,
        "ack_count": 0,
        "fin_count": 0,
        "avg_iat": 0.0
    }

    print("\n--- SANITY CHECK ---")
    
    # Predict
    # Note: predict() expects a list of flows
    pred_normal = model.predict([normal_flow])[0]
    pred_attack = model.predict([attack_flow])[0]
    
    # Score (Lower is more anomalous)
    score_normal = model.anomaly_score([normal_flow])[0]
    score_attack = model.anomaly_score([attack_flow])[0]

    print(f"Normal Flow (500 pkts): Predicted {pred_normal} (Score: {score_normal:.4f})")
    print(f"Attack Flow (1 pkt):    Predicted {pred_attack} (Score: {score_attack:.4f})")

    if pred_attack == 1:
        print("\n[DIAGNOSIS]: The model thinks 1-packet flows are NORMAL.")
        print("Reason: Your training data was full of 1-packet flows.")
    else:
        print("\n[DIAGNOSIS]: The model is working correctly!")

if __name__ == "__main__":
    main()