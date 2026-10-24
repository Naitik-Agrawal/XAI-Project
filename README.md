# XAI-ZT-P2P: Explainable AI-Driven Zero-Trust P2P File Sharing

This repository contains the complete experimental prototype, machine learning pipeline, peer simulation suite, and research paper manuscript for:

> **XAI-ZT-P2P: An Explainable AI-Driven Zero-Trust Framework for Secure and Adaptive Cross-Platform Peer-to-Peer File Sharing**

Extending the baseline hybrid UDP/TCP file-sharing architecture by *Urmila & Shubham Mishra (2025)*, this project eliminates **implicit perimeter trust** by integrating continuous 14-feature behavioral telemetry, an Explainable AI (Random Forest + TreeSHAP) risk engine, and an adaptive 4-tier Zero-Trust protocol response.

---

## 📁 Project Directory Structure

The project has been modularized and cleanly organized to ensure smooth execution without path errors:

```text
paperanddataset/
├── A_Secure_and_Efficient_Cross-Platform_P2P_File_Sha.pdf  # Reference base paper
├── EXPERIMENT_PROTOCOL.md                                  # Research & evaluation protocol
├── README.md                                               # Project overview and instructions
├── package.json                                            # Root npm scripts & runner
├── peer_simulator.js                                       # Root forwarder for Node simulator
├── requirements.txt                                        # Python ML dependencies
│
├── paper/                                                  # Research Paper Manuscripts
│   ├── XAI_ZT_P2P_IEEE.tex                                 # Formal IEEE Transactions / Conference LaTeX source
│   ├── references.bib                                      # BibTeX bibliography database
│   ├── XAI_ZT_P2P_RESEARCH_PAPER.md                        # Complete publication-ready manuscript
│   └── COMPARISON_AND_DISCOVERY_SUMMARY.md                 # Base paper vs XAI-ZT-P2P discoveries
│
├── python/                                                 # Python Machine Learning & Risk Engine
│   ├── generate_dataset.py                                 # Synthetic behavioral telemetry generator
│   ├── train_model.py                                      # Random Forest training & GridSearchCV
│   ├── explain_model.py                                    # TreeSHAP feature attribution generator
│   ├── benchmark_models.py                                 # Multi-Model Benchmark (RF, XGB, LGBM, MLP, SVM, LR)
│   ├── risk_engine.py                                      # Real-time inference & policy engine
│   └── benchmark.py                                        # Inference latency profiler
│
├── node/                                                   # Node.js Peer Simulation & Telemetry
│   ├── package.json                                        # Node module package definition
│   ├── peer_simulator.js                                   # Peer telemetry, attack & ZT simulator
│   └── p2p_live_node.js                                    # Real UDP 5353 discovery & TCP chunk streaming engine
│
├── data/                                                   # Datasets & Session Telemetry
│   ├── p2p_behavior.csv                                    # 12,000-session training telemetry
│   ├── p2p_simulated_sessions.csv                          # Real-time recorded simulation logs
│   └── received/                                           # Received socket files directory
│
├── models/                                                 # Serialized Model Artifacts
│   ├── random_forest.joblib                                # Trained Random Forest ensemble
│   └── feature_columns.json                                # 14-feature metadata schema
│
└── results/                                                # Evaluation Metrics, Plots & Reports
    ├── metrics.json                                        # Model accuracy, precision, F1, AUC
    ├── model_comparison.csv                                # Multi-model comparative benchmark data
    ├── model_comparison_roc.png                            # Overlaid comparative ROC curves (6 models)
    ├── model_comparison_metrics.png                        # Comparative metrics bar chart
    ├── classification_report.txt                           # Detailed per-class precision/recall
    ├── confusion_matrix.csv                                # Raw confusion matrix counts
    ├── confusion_matrix.png                                # Confusion matrix visualization
    ├── roc_curve.png                                       # ROC curve with AUC metric
    ├── feature_importance.png                              # Global feature importance plot
    ├── shap_summary.png                                    # Global TreeSHAP feature distribution
    ├── shap_peer_explanation.png                           # Single-peer local attribution bar chart
    ├── single_peer_shap_values.csv                         # Local SHAP values table
    ├── simulation_summary.json                             # 8-peer simulation evaluation summary
    └── inference_benchmark.json                            # Sub-20ms scoring latency benchmark
```

---

## 🚀 Quick Start Guide

### 1. Launch the Interactive Web Dashboard
Experience the real-time visual UI with interactive SVG gauges, TreeSHAP feature waterfalls, and live scenario execution:

```bash
# Start local dashboard server:
npm run dashboard
# Then open: http://localhost:3000

# Or open offline directly in your browser:
# Double-click index.html in the project root!
```

### 2. Run the Live P2P Socket Engine (UDP 5353 + TCP Streaming)
Experience real UDP 5353 multicast discovery, binary TCP socket framing, SHA-256 chunk verification, and threat-adaptive buffer modulation in real time:

```bash
# Clean high-speed benign transfer (sustained 64 KB chunks):
npm run p2p:live

# Chunk tampering attack (detects SHA-256 mismatch, throttles to 32 KB RESTRICT):
npm run p2p:attack

# Denial of Service request flood (detects >50 req/s, throttles to 16 KB QUARANTINE):
npm run p2p:dos

# Or start receiver daemon:
node node/p2p_live_node.js --mode receiver --port 62001

# Send real file to peer:
node node/p2p_live_node.js --mode sender --file ./data/live_transfer_test.bin --port 62001
```

### 3. Run the Peer Simulation Suite (16 Scenarios)
The CLI simulator evaluates 16 distinct peer scenarios spanning all 4 Zero-Trust tiers (ALLOW, RESTRICT, VERIFY_QUARANTINE, BLOCK), communicates with the Python risk engine, and exports session logs:

```bash
npm start
# (or: node peer_simulator.js)
```

### 4. Multi-Model Benchmark (RF vs XGBoost vs LightGBM vs MLP vs SVM vs LR)
Run the full comparative benchmark suite across 6 ML architectures:

```bash
npm run benchmark:models
# (or: python python/benchmark_models.py)
```

### 5. Machine Learning & Zero-Trust Pipeline

```bash
# Train Random Forest ensemble:
npm run train

# Generate TreeSHAP explainability plots:
npm run explain

# Profile inference scoring latency:
npm run benchmark
```

---

## 🛡️ Zero-Trust Security Policy Matrix

Continuous risk probability ($R \in [0, 1]$) is mapped to four granular defensive postures:

| Risk Score ($R$) | Policy Tier | Dynamic Chunk Size | Bandwidth Cap | Cryptographic Action |
| :---: | :---: | :---: | :---: | :--- |
| **$< 0.30$** | **`ALLOW`** | **64 KB** | 50 MB/s | Unrestricted high-speed streaming |
| **$0.30 - <0.60$** | **`RESTRICT`** | **32 KB** | 5 MB/s | Bandwidth throttled, rate-limited |
| **$0.60 - <0.80$** | **`VERIFY_QUARANTINE`** | **16 KB** | 0.5 MB/s | Transfers paused; RSA-2048 nonce challenge |
| **$\ge 0.80$** | **`BLOCK`** | **0 KB** | 0 MB/s | Socket severed; peer blacklisted across subnet |

---

## 📊 Quantitative Experimental Results

- **Classification Accuracy:** **94.33%**
- **Precision:** **93.96%**
- **Recall (Sensitivity):** **88.14%**
- **F1-Score:** **0.9096**
- **ROC-AUC Score:** **0.9199**
- **False Positive Rate:** **2.71%**
- **Mean Inference Latency:** **18.79 ms** (sub-50 ms discovery preserved)

---

## 📄 Research Paper Manuscripts

Read the complete academic papers in the `paper/` directory:
- [paper/XAI_ZT_P2P_RESEARCH_PAPER.md](file:///c:/Users/naitik%20agrawal/Downloads/paperanddataset/paper/XAI_ZT_P2P_RESEARCH_PAPER.md): Full research paper formatted for IEEE/ACM submission.
- [paper/COMPARISON_AND_DISCOVERY_SUMMARY.md](file:///c:/Users/naitik%20agrawal/Downloads/paperanddataset/paper/COMPARISON_AND_DISCOVERY_SUMMARY.md): In-depth comparative breakdown between the base paper and our novel contributions.
