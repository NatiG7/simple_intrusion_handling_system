"""
Baseline training script for the IDS.

Captures normal network traffic and trains the anomaly detection model.
Run this once to establish a baseline. After that, use main.py for
real-time intrusion detection.
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import sys
import time
from typing import List, Optional, Dict, Any

from scapy.all import get_if_list, IFACES

# Local imports: add parent directory to path
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from backend.detection.FlowML import FlowMLModel
from backend.capture.PacketCapture import PacketCapture
from backend.capture.TrafficAnalysis import TrafficAnalysis


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

TARGET_PACKETS = 50_000
CAPTURE_TIMEOUT = 3600  # 30 minutes
CONTAMINATION = 0.01    # Expected anomaly percentage in baseline data


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def is_apipa(ip: str) -> bool:
    """
    Detect whether an IPv4 address is link-local (APIPA 169.254.x.x).

    Args:
        ip (str): IP string.

    Returns:
        bool: True if APIPA or invalid.
    """
    try:
        return ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return True


def select_interface() -> Optional[str]:
    """
    Select an active interface that actually has internet traffic.

    Returns:
        Optional[str]: Interface name or None if none found.
    """
    available = get_if_list()
    print("Available interfaces:")

    for name in available:
        if name in IFACES:
            iface = IFACES[name]
            print(f"  {name}")
            print(f"    Description: {iface.description}")
            print(f"    IP: {iface.ip}\n")

    # Prefer physical Wi-Fi or Ethernet
    for name in available:
        if name not in IFACES:
            continue

        iface = IFACES[name]
        desc = iface.description.lower()
        ip = iface.ip

        if (
            any(k in desc for k in ("wi-fi", "wireless", "ethernet", "realtek"))
            and ip
            and ip != "0.0.0.0"
            and not is_apipa(ip)
        ):
            print(f"Selected interface: {iface.description}\n")
            return name

    # Fallback: any non-loopback, non-WAN
    for name in available:
        if name not in IFACES:
            continue

        iface = IFACES[name]
        desc = iface.description.lower()
        ip = iface.ip

        if "loopback" in desc or "wan miniport" in desc:
            continue

        if ip and ip != "0.0.0.0" and not is_apipa(ip):
            print(f"Selected interface: {iface.description}\n")
            return name

    print("ERROR: No suitable active interface found.")
    return None


def generate_background_traffic() -> List[subprocess.Popen]:
    """
    Launch minimal background traffic to ensure packets exist.

    Returns:
        List[subprocess.Popen]: Processes to terminate after capture.
    """
    print("Generating minimal baseline traffic (ping)...")

    processes = []
    targets = ["1.1.1.1", "8.8.8.8", "google.com"]

    for target in targets:
        p = subprocess.Popen(
            ["ping", "-n", "100", "-w", "1000", target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(p)

    return processes


def capture_baseline(
    interface: str,
    target_packets: int,
    timeout: int
) -> List[Any]:
    """
    Capture raw packets until limit or timeout.

    Args:
        interface (str): Network interface name.
        target_packets (int): Stop after capturing this many packets.
        timeout (int): Timeout in seconds.

    Returns:
        List[Any]: Raw Scapy packets.
    """
    sniffer = PacketCapture()

    print(
        f"Capturing up to {target_packets} packets "
        f"(timeout: {timeout}s)..."
    )
    print("This requires Administrator permissions!\n")
    print("TIP: Please browse websites, watch YouTube, use Discord/Steam, etc.\n")

    sniffer.start_capture(interface, timeout=timeout)
    start_time = time.time()
    last_count = 0

    while time.time() - start_time < timeout:
        time.sleep(2)

        count = sniffer.packet_queue.qsize()
        if count > last_count:
            print(f"Captured: {count}/{target_packets} packets...")
            last_count = count

        if count >= target_packets:
            print("\nTarget reached.\n")
            break

    sniffer.stop_capture_event()
    elapsed = time.time() - start_time
    print(f"Capture completed in {elapsed:.1f}s\n")

    return list(sniffer.packet_queue.queue)


def extract_features(
    packets: List[Any],
    analyser: TrafficAnalysis
) -> List[Dict[str, Any]]:
    """
    Extract flow-level ML features from captured packets.

    Args:
        packets (List[Any]): Raw packets.
        analyser (TrafficAnalysis): Analyzer instance.

    Returns:
        List[Dict[str, Any]]: List of flow feature dicts.
    """
    print("Extracting flow features...")

    results: List[Dict[str, Any]] = []
    interval = max(1, len(packets) // 20)

    for i, pkt in enumerate(packets):
        features = analyser.analyze_packet(pkt)

        # Reject empty or zero-variance flows
        if features and sum(features.values()) != 0:
            results.append(features)

        if (i + 1) % interval == 0:
            pct = (i + 1) / len(packets) * 100
            print(f"  Progress: {i + 1}/{len(packets)} ({pct:.1f}%)")

    return results


def train_model(
    flow_features: List[Dict[str, Any]],
    contamination: float
) -> FlowMLModel:
    """
    Train the IsolationForest model.

    Args:
        flow_features (List[Dict[str, Any]]): Training feature list.
        contamination (float): Expected anomaly proportion.

    Returns:
        FlowMLModel: Trained model.
    """
    print(f"Training IsolationForest on {len(flow_features)} flows...")

    model = FlowMLModel(contamination=contamination)
    start = time.time()
    model.train(flow_features)
    elapsed = time.time() - start

    print(f"Training done ({elapsed:.2f}s)\n")
    return model


def validate_model(
    model: FlowMLModel,
    flow_features: List[Dict[str, Any]]
) -> None:
    """
    Validate the trained model by checking anomaly ratios on baseline data
    and reporting anomaly scores.
    """
    print("Validating baseline...")

    predictions = model.predict(flow_features)
    scores = model.anomaly_score(flow_features)

    anomalies = [(i, s) for i, (p, s) in enumerate(zip(predictions, scores)) if p == -1]
    normals = len(predictions) - len(anomalies)
    pct = len(anomalies) / len(predictions) * 100

    print("\n" + "=" * 60)
    print("BASELINE VALIDATION")
    print("=" * 60)
    print(f"Total flows: {len(flow_features)}")
    print(f"Normal: {normals}")
    print(f"Anomalies flagged: {len(anomalies)} ({pct:.2f}%)")
    if anomalies:
        print("\nTop 5 anomalies by score:")
        for idx, score in sorted(anomalies, key=lambda x: x[1])[:5]:
            print(f"  Flow {idx + 1}: Score {score:.3f}")
    print("=" * 60 + "\n")

def main() -> None:
    """Execute baseline capture, training, validation, and saving."""
    print("=" * 60)
    print(" IDS BASELINE TRAINING ")
    print("=" * 60)
    print(f"Target packets: {TARGET_PACKETS}")
    print(f"Contamination: {CONTAMINATION}\n")

    interface = select_interface()
    if not interface:
        sys.exit(1)

    analyser = TrafficAnalysis()
    processes: List[subprocess.Popen] = []

    try:
        # Generate minimal background traffic
        processes = generate_background_traffic()

        # Capture
        packets = capture_baseline(interface, TARGET_PACKETS, CAPTURE_TIMEOUT)
        print(f"Captured packets: {len(packets)}\n")

        if len(packets) < 100:
            print("ERROR: Not enough packets captured.")
            print("Move around online during capture (YouTube/Discord/etc).")
            sys.exit(1)

        # Extract features
        features = extract_features(packets, analyser)
        print(f"Extracted flow features: {len(features)}\n")

        if not features:
            print("ERROR: No feature vectors extracted.")
            sys.exit(1)

        # Train & validate
        model = train_model(features, CONTAMINATION)
        validate_model(model, features)

        # Save
        path = "models/baseline_model.pkl"
        print(f"Saving model to {path} ...")
        model.save(path)

        print("\nBaseline training completed successfully.")
        print("Next: run main.py for real-time detection.\n")

    except KeyboardInterrupt:
        print("\nTraining interrupted by user. Cleaning up...")

    except Exception as exc:
        print(f"ERROR: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        for p in processes:
            p.terminate()


if __name__ == "__main__":
    main()
