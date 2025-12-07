# backend/detection/FlowML.py
from typing import List, Dict
import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class FlowMLModel:
    """
    ML model for detecting anomalous TCP/IP flows using IsolationForest.
    """
    def __init__(self, contamination: float = 0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()  # Add scaler for better normalization
        self.is_trained = False
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
        
        # Fit scaler and transform data
        self.scaler.fit(X_train)
        X_scaled = self.scaler.transform(X_train)
        
        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True
    
    def predict(self, flow_features: List[Dict]) -> List[int]:
        """
        Predict anomalies for a list of flow feature dicts.
        Returns:
            -1 for anomaly, 1 for normal
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() or load() first.")
        
        X_test = self.prepare_training_data(flow_features)
        X_scaled = self.scaler.transform(X_test)
        return self.model.predict(X_scaled)
    
    def anomaly_score(self, flow_features: List[Dict]) -> np.ndarray:
        """
        Returns the anomaly score (higher = normal, lower = anomaly)
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() or load() first.")
        
        X_test = self.prepare_training_data(flow_features)
        X_scaled = self.scaler.transform(X_test)
        return self.model.score_samples(X_scaled)
    
    def save(self, filepath: str = "models/baseline_model.pkl"):
        """
        Save the trained model and scaler to disk.
        
        Args:
            filepath: Path where the model will be saved
        """
        if not self.is_trained:
            raise ValueError("Cannot save untrained model. Call train() first.")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Save model, scaler, and metadata
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"Model saved to {filepath}")
    
    def load(self, filepath: str = "models/baseline_model.pkl"):
        """
        Load a trained model and scaler from disk.
        
        Args:
            filepath: Path to the saved model
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        
        print(f"Model loaded from {filepath}")
    
    @staticmethod
    def model_exists(filepath: str = "models/baseline_model.pkl") -> bool:
        """
        Check if a saved model exists.
        
        Args:
            filepath: Path to check for model
            
        Returns:
            True if model file exists, False otherwise
        """
        return os.path.exists(filepath)