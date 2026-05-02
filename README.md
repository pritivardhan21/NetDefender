# NetDefender: AI-Driven SDN-Based Zero-Day Threat Detection System

This repository contains the architecture, implementation, and experimental data for **NetDefender**, an autonomous Software-Defined Networking (SDN) security system. This project was developed as part of a TEEP/FTIP Internship at National Formosa University (NFU), Yunlin, Taiwan.

## 🛡️ Project Overview

NetDefender is engineered to detect, throttle, and trap zero-day network attacks without relying on traditional signature-based firewalls or computationally heavy Machine Learning (ML) libraries. By leveraging the centralized, programmable nature of SDN, NetDefender provides millisecond-level response capabilities to secure network perimeters.

### Key Contributions
*   **Custom Trust Engine:** Utilizes purely mathematical behavioral profiling (Z-Score volumetric anomaly detection and a Connection Diversity Ratio heuristic) to identify both massive flood attacks and stealthy, low-volume intrusions.
*   **Victim Guard Mechanism:** Prevents targeted servers from being penalized by reflection traffic during active attacks, ensuring a 0% false-positive rate on victim hosts.
*   **Active Defense Pipeline:** Simultaneously applies a bandwidth throttle of over 99% via OpenFlow Meter Tables and transparently redirects attacker traffic into an isolated Cowrie SSH honeypot for live threat intelligence capture.

## ⚙️ System Architecture

The framework operates across the layered SDN paradigm:
1.  **Data Plane (The Battlefield):** Emulated via Mininet and Open vSwitch (OVS). Enforces hardware-level OpenFlow rules, modifying flows mid-flight.
2.  **Control Plane (The Brain):** Managed by a centralized Ryu controller application. The custom Trust Engine executes within the controller's event loop, polling traffic statistics every 3 seconds.
3.  **Intelligence Plane (The Trap):** An isolated Docker container hosting a Cowrie SSH honeypot. Attacker traffic is seamlessly routed here to log keystrokes, credentials, and payload data.

## 📊 Experimental Results

Tested on a physical ASUS RS300-E8-PS4 rack server, NetDefender demonstrated:
*   **Deterministic Detection Latency:** Consistently detected attacks within a single 3.0-second polling cycle.
*   **High Accuracy:** Successfully mitigated Layer 3 ICMP Floods, Layer 4 TCP SYN Floods, and Layer 7 Slowloris attacks.
*   **Zero Victim False Positives:** The Victim Guard successfully protected the targeted server in all flood trials.

## 📁 Repository Structure

*   `netdefender_live_ai.py`: The core Ryu controller application and Trust Engine logic.
*   `netdefender_tarpit.py`: Script for executing the dynamic bandwidth throttling response.
*   `train_ai.py` & `pcap_to_csv.py`: Data processing and training pipeline.
*   `netdefender_ai_model.pkl`: The trained AI model (if applicable based on final implementation).
*   `attack_traffic.pcap` & `normal_traffic.pcap`: Experimental data captures demonstrating system performance under attack conditions.
*   `NetDefender_Detailed_Project_Report.docx`: The full, comprehensive research paper detailing the architecture, mathematics, and experimental results.

## 🚀 Future Work

*   Integration of Deep Packet Inspection (DPI) to classify application-layer protocols and whitelist legitimate high-throughput sessions.
*   Adaptive threshold calibration based on time-of-day traffic profiling.

---
**Author:** Pritivardhan Chothe

**Supervisor:** Prof. Ming-Shen Jian

**Institutions:** National Formosa University & Rajarambapu Institute of Technology
