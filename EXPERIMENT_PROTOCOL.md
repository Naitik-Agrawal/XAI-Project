# Experimental protocol for the manuscript

## Phase A — Software validation
1. Generate 12,000 synthetic records using seed 42.
2. Run GridSearchCV with 5-fold stratification.
3. Save best parameters.
4. Evaluate the held-out 20% test set.
5. Generate confusion matrix, ROC, feature importance and SHAP.

## Phase B — Real P2P data collection
Instrument the actual Node.js P2P implementation to log one row per peer/session window.
Do not collect file contents. Collect only security/network telemetry.

Recommended logging fields:
timestamp, peer_id, auth_failures, request_rate, transfer_rate,
failed_transfers, packet_anomaly_score, connection_duration_s,
discovery_rate, unauthorized_requests, transfer_size_deviation,
retry_rate, integrity_failures, historical_reputation,
session_age_s, device_consistency, label.

## Phase C — Controlled attacks
Generate controlled scenarios:
normal peer, repeated authentication failure, unauthorized requests,
high request rate, integrity failures, abnormal discovery, malformed requests,
and combinations of the above.

## Phase D — Network benchmarking
For each network:
2.4 GHz Wi-Fi, 5 GHz Wi-Fi, Ethernet.
For each file size:
10 MB, 100 MB, 500 MB, 1 GB.
Repeat each experiment at least 10 times.

Measure:
discovery latency, authentication latency, transfer throughput,
CPU, memory, failed transfers and security overhead.

## Phase E — Statistical analysis
Run at least 5 independent seeds for the ML pipeline and report
mean ± standard deviation. Use paired tests for repeated network benchmarks.
