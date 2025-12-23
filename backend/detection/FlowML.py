"""
FlowML: IsolationForest-based anomaly detection for TCP/IP flow features.
"""

from typing import List, Dict, Any
import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler


class FlowMLModel:
    """
    Machine learning model for detecting anomalous TCP/IP flows using IsolationForest.

    Attributes:
        model (IsolationForest): IsolationForest instance used for anomaly detection.
        scaler (StandardScaler): Normalization scaler for input features.
        is_trained (bool): Indicates whether the model has been trained.
        feature_names (List[str]): Ordered list of expected flow feature names.
    """

    def __init__(self, contamination: float = 0.1) -> None:
        """
        Initialize the FlowMLModel.

        Args:
            contamination (float): Expected fraction of anomalies in the training data.
        """
        self.model = IsolationForest(contamination=contamination,
                                     random_state=42,
                                     bootstrap=True,
                                     max_samples=256)
        self.scaler = RobustScaler()
        self.is_trained = False

        self.feature_names: List[str] = [
            "packet_count",
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
            "min_iat",
            "max_iat",
            "avg_iat",
            "std_iat",
        ]

    # ----------------------------------------------------------------------

    def prepare_training_data(self, flow_features: List[Dict[str, Any]]) -> np.ndarray:
        """
        Convert flow feature dictionaries into a numeric 2D NumPy array.

        Args:
            flow_features (List[Dict[str, Any]]): A list of flow feature mappings.

        Returns:
            np.ndarray: 2D array of shape (n_samples, n_features).
        """
        rows = [
            [features.get(name, 0) for name in self.feature_names]
            for features in flow_features
        ]
        return np.array(rows)

    # ----------------------------------------------------------------------

    def train(self, flow_features: List[Dict[str, Any]]) -> None:
        """
        Train the IsolationForest model using normalized flow features.

        Args:
            flow_features (List[Dict[str, Any]]): A list of flow feature mappings.

        Raises:
            ValueError: If no flow features are provided.
        """
        if not flow_features:
            raise ValueError("Training data cannot be empty.")

        X_train = self.prepare_training_data(flow_features)

        # Fit normalization
        self.scaler.fit(X_train)
        X_scaled = self.scaler.transform(X_train)

        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True

    # ----------------------------------------------------------------------

    def predict(self, flow_features: List[Dict[str, Any]]) -> List[int]:
        """
        Predict anomalies in the given flows.

        Args:
            flow_features (List[Dict[str, Any]]): List of flow feature dictionaries.

        Returns:
            List[int]: 1 for normal, -1 for anomaly.

        Raises:
            ValueError: If the model has not been trained.
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() or load() first.")

        X_test = self.prepare_training_data(flow_features)
        X_scaled = self.scaler.transform(X_test)
        return self.model.predict(X_scaled).tolist()

    # ----------------------------------------------------------------------

    def anomaly_score(self, flow_features: List[Dict[str, Any]]) -> np.ndarray:
        """
        Compute anomaly scores for flows.

        Args:
            flow_features (List[Dict[str, Any]]): A list of flow feature mappings.

        Returns:
            np.ndarray: Score per flow (higher = more normal).

        Raises:
            ValueError: If the model has not been trained.
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() or load() first.")

        X_test = self.prepare_training_data(flow_features)
        X_scaled = self.scaler.transform(X_test)
        return self.model.score_samples(X_scaled)

    # ----------------------------------------------------------------------

    def save(self, filepath: str = "models/baseline_model.pkl") -> None:
        """
        Save the trained model, scaler, and metadata to disk.

        Args:
            filepath (str): Location where the model should be stored.

        Raises:
            ValueError: If the model has not been trained.
        """
        if not self.is_trained:
            raise ValueError("Cannot save an untrained model.")

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "is_trained": self.is_trained,
        }

        with open(filepath, "wb") as f:
            pickle.dump(data, f)

    # ----------------------------------------------------------------------

    def load(self, filepath: str = "models/baseline_model.pkl") -> None:
        """
        Load a trained model from disk.

        Args:
            filepath (str): Path to the serialized model file.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")

        with open(filepath, "rb") as f:
            data = pickle.load(f)

        self.model = data["model"]
        self.scaler = data["scaler"]
        self.feature_names = data["feature_names"]
        self.is_trained = data["is_trained"]

    # ----------------------------------------------------------------------

    @staticmethod
    def model_exists(filepath: str = "models/baseline_model.pkl") -> bool:
        """
        Check if a model file exists.

        Args:
            filepath (str): File path to check.

        Returns:
            bool: True if the model exists, False otherwise.
        """
        return os.path.exists(filepath)
