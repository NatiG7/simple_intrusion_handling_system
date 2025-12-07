# backend/detection/FlowML.py
from typing import List, Dict
import numpy as np
from sklearn.ensemble import IsolationForest


class FlowMLModel:
    """
    ML model for detecting anomalous TCP/IP flows using IsolationForest.
    """

    def __init__(self, contamination: float = 0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.feature_names = [
            "packet_size",
            "flow_duration",
            "packet_rate",
            "byte_rate",
            "latest_window_size",
            "syn_count",
            "ack_count",
            "fin_count",
            "rst_count",
            "avg_sequence_number",
            "avg_window_size",
            "avg_ip_header_length",
            "avg_tcp_header_size",
            "unique_src_ips",
            "unique_dst_ips",
            "unique_src_ports",
            "unique_dst_ports",
            "ip_checksum_errors",
            "tcp_checksum_errors",
            "reserved_bit_set_count",
        ]

    def prepare_training_data(self, flow_features: List[Dict]) -> np.ndarray:
        """
        Convert a list of flow feature dictionaries to a numpy array
        suitable for training the IsolationForest.
        """
        X = []
        for f in flow_features:
            row = [f.get(name, 0) for name in self.feature_names]
            X.append(row)
        return np.array(X)

    def train(self, flow_features: List[Dict]):
        """
        Train the IsolationForest model on normal traffic feature vectors.
        """
        X_train = self.prepare_training_data(flow_features)
        self.model.fit(X_train)

    def predict(self, flow_features: List[Dict]) -> List[int]:
        """
        Predict anomalies for a list of flow feature dicts.
        Returns:
            -1 for anomaly, 1 for normal
        """
        X_test = self.prepare_training_data(flow_features)
        return self.model.predict(X_test)

    def anomaly_score(self, flow_features: List[Dict]) -> np.ndarray:
        """
        Returns the anomaly score (higher = normal, lower = anomaly)
        """
        X_test = self.prepare_training_data(flow_features)
        return self.model.score_samples(X_test)
