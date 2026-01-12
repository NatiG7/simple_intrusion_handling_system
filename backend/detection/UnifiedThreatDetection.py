from backend.detection.FlowML import FlowMLModel
import logging
from collections import deque
import numpy as np
MODEL_PATH = "models/baseline_model.pkl"

class UnifiedThreatDetection:
    
    def __init__(self) -> None:
        
        self.signature_rules = self._load_signature_rules()
        self.ml_model = FlowMLModel()
        try:
            self.ml_model.load(MODEL_PATH)
            logging.info("ML model loaded successfully.")
            self.score_history = deque(maxlen=1000)
            self.drift_alert = False
        except FileNotFoundError:
            logging.warning("No pre-trained ML model found at startup.")
    
    def _load_signature_rules(self) -> dict:
        return {
            "SYN_flood" : lambda f: f.get("syn_count") > 100 and f.get("packet_rate") > 50,
            "SYN_flood_DST": lambda f:(f.get("syn_count") > 1000
                            and f.get("unique_src_ips") > 100 and f.get("ack_count",0) == 0),
            "Slowloris" : lambda f: f.get("flow_duration") > 10 and f.get("packet_rate") < 5
        }
        
    def detect(self, combined_features: dict) -> dict:
        """
        Routes traffic to the correct engine:
        - Macro Features -> Signature Engine (Floods)
        - Micro Features -> ML Engine (Anomalies)
        """
        macro = combined_features.get("macro", {})
        micro = combined_features.get("micro", {})
        
        safe_result = {"is_threat": False, "risk_score": 0.0, "threat_type": "none"}

        # sig check using macro
        for signature, rule in self.signature_rules.items():
            if rule(macro):
                return {
                    "is_threat": True,
                    "risk_score": 1.0,
                    "threat_type": signature,
                    "engine": "Signature"
                }

        # ml check using micro
        try:
            if self.ml_model.is_trained and micro:
                # Predict
                prediction = self.ml_model.predict([micro])[0]
                score = self.ml_model.anomaly_score([micro])[0]
                
                if prediction <= 0:
                    return {
                        "is_threat": True,
                        "risk_score": float(abs(score)),
                        "threat_type": "ML_Anomaly",
                        "engine": "FlowML"
                    }
                    
        except Exception as e:
            logging.error(f"ML Inference failure: {e}")
            
        return safe_result
    
    def _check_concept_drift(self):
        if len(self.score_history) == self.score_history.maxlen:
            avg_score = np.mean(self.score_history)
            if avg_score < -0.20 and not self.drift_alerted:
                logging.warning(f"Drift Detected (Avg: {avg_score:.2f}). Retrain.")
                self.drift_alerted = True