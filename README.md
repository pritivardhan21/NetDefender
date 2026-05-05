# NetDefender
### ML-Free SDN Anomaly Detection via Statistical Heuristics
[Badges: Python | Mininet | Ryu Controller | Z-Score | Shannon Entropy | Cowrie | License: MIT]

## Abstract
NetDefender is a Software-Defined Networking (SDN) based zero-day threat detection system that employs purely mathematical heuristics — specifically Z-Score normalization and Shannon Entropy analysis — to identify anomalous traffic patterns in real time. Unlike contemporary approaches that rely on computationally heavy Machine Learning (ML) classifiers, NetDefender is signature-agnostic and model-free, operating without any labeled training dataset. This design choice ensures consistent, millisecond-level performance against novel, unseen attack vectors.

## Design Philosophy — Why NOT Machine Learning
Most IDS/IPS systems face a fundamental limitation: they are only as good as their training data. NetDefender makes a deliberate architectural decision to avoid ML for three academically defensible reasons:
1. **Zero-day Resilience:** Zero-day attacks have no training representation; ML classifiers fail silently, whereas statistical bounds trigger reliably.
2. **Mathematical Explainability:** Every alert has a quantifiable basis, eliminating the "black box" problem of neural networks.
3. **Hardware Efficiency:** Deterministic models are reproducible and run blazingly fast on edge hardware without GPU infrastructure.

## 🛡️ Key Active Defense Mechanisms
* **Custom Trust Engine:** Executes within the controller's event loop, polling traffic statistics every 3 seconds to calculate dynamic Z-Scores and Connection Diversity Ratios.
* **Victim Guard:** Prevents targeted servers from being penalized by reflection traffic during active attacks, ensuring a 0% false-positive rate on victim hosts.
* **Tarpit & Honeypot Redirection:** Simultaneously applies a bandwidth throttle (>99%) via OpenFlow Meter Tables and transparently redirects attacker traffic into an isolated Cowrie SSH honeypot for live threat intelligence capture.

## Architecture
```text
  ┌─────────────────────────────────────────────┐
  │  Mininet Virtual Topology / Physical OVS    │
  │          ↓  OpenFlow 1.3                    │
  │  Ryu SDN Controller (Flow Table Manager)    │
  │          ↓  Packet-in Events                │
  │  NetDefender Detection Engine               │
  │    ├─ Z-Score Engine (Flow Rate Anomaly)    │
  │    └─ Shannon Entropy (Port Distribution)   │
  │          ↓  Alert Triggered                 │
  │    ├─ OpenFlow Meter Table (Throttle)       │
  │    └─ Redirection to Cowrie SSH Honeypot    │
  └─────────────────────────────────────────────┘
## Mathematical Core
### Z-Score Anomaly Detection
Z = (x - μ) / σ 
*(where x = current packet rate, μ = rolling mean, σ = rolling std dev)*
Threshold: |Z| > 3.0 → anomaly flag

### Shannon Entropy Analysis
H(X) = -Σ p(x) log₂ p(x)
Low entropy in destination port distribution → DDoS/scan pattern (many flows, few ports).

## 📊 Experimental Results
Tested on a physical ASUS RS300-E8-PS4 rack server, NetDefender demonstrated deterministic detection latency, consistently catching attacks within a single 3.0-second polling cycle.

| Attack Type       | Detection Latency | False Positive Rate (Victim) | Mitigation |
|-------------------|-------------------|------------------------------|------------|
| Layer 3 ICMP Flood| < 3.0 seconds     | 0%                           | Blocked / Tarpit |
| Layer 4 SYN Flood | < 3.0 seconds     | 0%                           | Blocked / Tarpit |
| Layer 7 Slowloris | < 3.0 seconds     | 0%                           | Blocked / Tarpit |

## 📁 Repository Structure
* `detection_engine.py`: The core Ryu controller application and Mathematical Trust Engine logic.
* `netdefender_tarpit.py`: Script for executing the dynamic bandwidth throttling response.
* `pcap_to_csv.py`: Data processing pipeline for feature extraction.
* `attack_traffic.pcap` & `normal_traffic.pcap`: Experimental data captures.
* `NetDefender_Detailed_Project_Report.docx`: Comprehensive research paper detailing the architecture.

## Research Context & Credits
This project originated from research conducted at National Formosa University, Taiwan (FTIP Program, Feb–Jul 2026) and was extended as a standalone implementation. 

* **Author:** Pritivardhan Chothe
* **Supervisor:** Prof. Ming-Shen Jian
* **Institutions:** National Formosa University & Rajarambapu Institute of Technology
