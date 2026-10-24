import argparse
import json
import subprocess
import time
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

from risk_engine import score, get_model_and_features

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=100)
    ap.add_argument("--mode", choices=["in-process", "subprocess"], default="in-process")
    args = ap.parse_args()

    payload = {
        "auth_failures": 1, "request_rate": 3,
        "transfer_rate": 4, "failed_transfers": 0,
        "packet_anomaly_score": 0.12, "connection_duration_s": 120,
        "discovery_rate": 2, "unauthorized_requests": 0,
        "transfer_size_deviation": 0.4, "retry_rate": 0.05,
        "integrity_failures": 0, "historical_reputation": 0.90,
        "session_age_s": 300, "device_consistency": 0.96
    }

    times = []
    if args.mode == "in-process":
        get_model_and_features()  # warm up
        for _ in range(args.requests):
            t0 = time.perf_counter()
            score(payload)
            times.append((time.perf_counter() - t0) * 1000)
    else:
        cmd = [
            "python", str(ROOT / "python" / "risk_engine.py"),
            "--json", json.dumps(payload)
        ]
        for _ in range(args.requests):
            t0 = time.perf_counter()
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            times.append((time.perf_counter() - t0) * 1000)

    result = {
        "mode": args.mode,
        "requests": args.requests,
        "mean_latency_ms": round(sum(times) / len(times), 3),
        "min_latency_ms": round(min(times), 3),
        "max_latency_ms": round(max(times), 3),
        "throughput_evals_per_sec": round(1000.0 / (sum(times) / len(times)), 1)
    }

    out = ROOT / "results" / "inference_benchmark.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
