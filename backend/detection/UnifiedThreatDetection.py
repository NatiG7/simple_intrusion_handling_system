from FlowML import FlowMLModel
import logging
MODEL_PATH = "./models/flowml"

class UnifiedThreatDetection:
    
    def __init__(self) -> None:
        
        self.signature_rules = self._load_signature_rules()
        self.ml_model = FlowMLModel()
        try:
            self.ml_model.load(MODEL_PATH)
            logging.info("ML model loaded successfully.")
        except FileNotFoundError:
            logging.warning("No pre-trained ML model found at startup.")
    
    def _load_signature_rules(self) -> dict:
        return {
            "SYN_flood" : lambda f: f.get("syn_count") > 100 and f.get("packet_rate") > 50,
            "Slowloris" : lambda f: f.get("flow_duration") > 10 and f.get("packet_rate") < 5
        }
        
    def detect(self, flow_features: dict) -> dict:
        safe_result = {"is_threat": False, "risk_score": 0.0, "threat_type": "none"}
        for signature, rule in self.signature_rules.items():
            if rule(flow_features):
                threat_result = {}
                threat_result["is_threat"] = True
                threat_result["risk_score"] = 1.0
                threat_result["threat_type"] = signature
                logging.info(f"Signature-based threat detected: {signature}")
                return threat_result

        if self.ml_model.is_trained:
            ml_prediction = self.ml_model.predict([flow_features])[0]
            ml_score = self.ml_model.anomaly_score([flow_features])[0]
            if ml_prediction == -1:
                safe_result["is_threat"] = True
                safe_result["risk_score"] = abs(ml_score)
                safe_result["threat_type"] = "ML_Anomaly"
                logging.info(f"ML-based threat detected with score: {ml_score}")
            
        return safe_result