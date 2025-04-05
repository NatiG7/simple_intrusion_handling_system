from typing import Any, Callable, Dict, List

import numpy as np
from sklearn.ensemble import IsolationForest


class ThreatDetection:
    """
    A threat detection engine with signature-based and anomaly-based detection methods.
    """

    def __init__(self) -> None:
        """
        Initialize the ThreatDetection class with
            signature rules and IsolationForest detector.
        """
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.signature_rules: Dict[str, Dict[str, Callable[[Dict[str, Any]], bool]]] = (
            self.load_signature_rules()
        )
        self.training_data: List[List[float]] = []

    def load_signature_rules(
        self,
    ) -> Dict[str, Dict[str, Callable[[Dict[str, Any]], bool]]]:
        """
        Load predefined signature-based detection rules.

        :returns: a dict of rule names and corresponding conditions.
        """
        return {
            "syn_flood": {
                "condition": lambda features: (
                    # SYN
                    features["tcp_flags"] == 2 and features["packet_rate"] > 100
                )
            },
            "port_scan": {
                "condition": lambda features: (
                    # fast sniff
                    features["packet_size"] < 100 and features["packet_rate"] > 50
                )
            },
        }

    def train_anomaly_detector(self, normal_traffic_data: List[List[float]]) -> None:
        """
        Train the IsolationForest anomaly detector with normal traffic data.

        Args:
            normal_traffic_data(list): A list of feature vectors representing normal traffic.
        """
        self.anomaly_detector.fit(normal_traffic_data)

    def detect_threats(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect threats based on signature rules and anomaly scores.

        Args:
            features(dict): A dictionary of traffic features.

        Returns:
            threats(list): A list of detected threats with metadata.
        """
        threats: List[Dict[str, Any]] = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule["condition"](features):
                threats.append(
                    {"type": "signature", "rule": rule_name, "confidence": 1.0}
                )

        # Anomaly-based detection
        feature_vector = np.array(
            [[features["packet_size"], features["packet_rate"], features["byte_rate"]]]
        )

        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]

        if anomaly_score < -0.5:
            threats.append(
                {
                    "type": "anomaly",
                    "score": anomaly_score,
                    "confidence": min(1.0, abs(anomaly_score)),
                }
            )

        return threats
