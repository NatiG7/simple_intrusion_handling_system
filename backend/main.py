"""
Real-time intrusion detection system.
Loads a pre-trained baseline model and detects anomalies in live traffic.
Run train_baseline.py first to create the baseline model.
"""

import os
import sys
import time
import subprocess


# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis
from utils.interface_detect import *

# Configuration
CAPTURE_DURATION = 100  # seconds
MODEL_PATH = "models/baseline_model.pkl"


def main():
    pass

if __name__ == "__main__":
    main()