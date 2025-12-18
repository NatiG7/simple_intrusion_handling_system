# 🛡️ Simple Intrusion Handling System (SIHS)

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![MongoDB](https://img.shields.io/badge/MongoDB-Enabled-green?style=for-the-badge&logo=mongodb)
![Status](https://img.shields.io/badge/Status-Prototype-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Author:** Nati Goral
**Repository:** `simple_intrusion_handling_system`

## 📖 Overview

This project is a lightweight **Intrusion Detection System (IDS)** designed to monitor network traffic in real-time, log suspicious activities, and alert administrators.

**Note:** This is strictly a *detection* system (IDS), not a prevention system (IPS). It "sniffs and barks" but does not actively block packets or modify firewall rules.

### 🚀 Key Objectives
* **Real-Time Monitoring:** Capture and parse TCP/IP packets using **Scapy**.
* **Hybrid Detection Engine:**
    * **Signature-Based:** Flags known patterns (e.g., SYN Floods, Port Scans) using configurable rules.
    * **Statistical Anomaly Detection:** Uses **Isolation Forest** to identify statistical outliers in traffic flow (e.g., unusual packet sizes or volume spikes).
* **Data Persistence:** Scalable logging of alerts and flow statistics to a local **MongoDB** database (NoSQL).
* **Visualization:** (Planned) A containerized web dashboard for viewing logs and statistics.

---

## 🏗️ System Architecture

The system operates on a modular architecture to separate packet capture, analysis, and storage.

1.  **Packet Sniffer:** Captures raw traffic (Promiscuous mode) via the Network Interface.
2.  **Traffic Analyzer:** Extracts features (Packet Count, SYN/ACK ratios, Duration).
3.  **Threat Detector:**
    * Checks static rules (Signatures).
    * Runs feature vectors through an Isolation Forest model to find outliers.
4.  **Database Manager:** Handles thread-safe writing of JSON logs to **MongoDB**.

---

## 📂 Project Structure (Tentative)

*Note: The project structure is currently in flux and subject to change.*

```text
simple_intrusion_handling_system/
├── backend/
│   ├── detection/
│   │   ├── ThreatDetector.py    # Detection logic (Rules + ML)
│   │   └── signatures.json      # Rule definitions
│   ├── database/
│   │   └── DatabaseManager.py   # MongoDB Handler (NoSQL)
│   ├── capture/
│   │   └── PacketCapture.py     # Scapy wrapper
│   ├── models/
│   │   └── isolation_forest.pkl # Trained model
│   └── main.py                  # Entry point
├── frontend/                    # (Planned) Web Dashboard
├── docker/                      # Docker configuration
├── docs/                        # Documentation & Diagrams
├── requirements.txt
└── README.md
```

---

## 🛠️ Tech Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Language** | Python 3.9+ | Core logic |
| **Capture** | Scapy | Packet sniffing |
| **ML Engine** | Scikit-Learn | Isolation Forest (Outlier Detection) |
| **Storage** | MongoDB | NoSQL Log Storage |
| **Deployment** | Docker | Containerization (Planned) |

---

## ⚡ Getting Started

### Prerequisites
* Python 3.9+
* **MongoDB Server** (Local or Remote)
* Npcap (Windows) or libpcap (Linux)
* Root/Admin privileges (Required for sniffing)

### Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/yourusername/simple_intrusion_handling_system.git](https://github.com/yourusername/simple_intrusion_handling_system.git)
    cd simple_intrusion_handling_system
    ```

2.  **Set up Virtual Environment**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the System**
    ```bash
    # Ensure MongoDB is running first
    sudo python backend/main.py
    ```

---

## 🤝 Contributing

This is an educational project. Contributions to improve the detection logic or dashboard are welcome.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.