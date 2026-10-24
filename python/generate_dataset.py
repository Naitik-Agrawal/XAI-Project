"""
XAI-ZT-P2P: Contextual Behavioral Telemetry Generator
Generates realistic P2P network telemetry reflecting real-world distributed dynamics:
- Non-linear contextual behavior (benign power users with high request rates, Wi-Fi jitter)
- Multi-vector threats (DoS flooding, chunk poisoning, low-and-slow probes, auth attacks)
- Natural observational noise reflecting real wireless channel variations
"""

import argparse
from pathlib import Path
import numpy as np
import pandas as pd

FEATURES = [
    "auth_failures",
    "request_rate",
    "transfer_rate",
    "failed_transfers",
    "packet_anomaly_score",
    "connection_duration_s",
    "discovery_rate",
    "unauthorized_requests",
    "transfer_size_deviation",
    "retry_rate",
    "integrity_failures",
    "historical_reputation",
    "session_age_s",
    "device_consistency",
]

def generate_contextual_dataset(rows=12000, seed=42):
    rng = np.random.default_rng(seed)

    auth_fail = rng.poisson(0.40, rows)
    req_rate = rng.gamma(3.0, 2.4, rows)
    trans_rate = rng.gamma(4.0, 2.0, rows)
    failed_trans = rng.poisson(0.45, rows)
    packet_anom = np.clip(rng.beta(2.0, 6.5, rows), 0.0, 1.0)
    conn_dur = np.clip(rng.normal(140, 60, rows), 10, 900)
    disc_rate = rng.gamma(2.5, 1.5, rows)
    unauth_req = rng.poisson(0.30, rows)
    size_dev = np.abs(rng.normal(0.55, 0.35, rows))
    retry_rate = np.clip(rng.beta(2.0, 7.5, rows), 0.0, 1.0)
    integ_fail = rng.poisson(0.30, rows)
    reputation = np.clip(rng.beta(5.5, 2.8, rows), 0.0, 1.0)
    session_age = np.clip(rng.normal(260, 120, rows), 20, 1800)
    dev_consist = np.clip(rng.beta(6.5, 2.2, rows), 0.0, 1.0)

    # Non-linear latent risk formulation
    latent = (
        0.36 * (auth_fail >= 2)
        + 0.55 * (integ_fail >= 1)
        + 0.40 * packet_anom
        + 0.32 * (unauth_req >= 1)
        - 0.42 * reputation
        - 0.30 * dev_consist
        # Power user exception: high request rate but high reputation
        + 0.52 * ((req_rate > 14.0) & (reputation < 0.55))
        - 0.45 * ((req_rate > 14.0) & (reputation >= 0.70))
        # Wi-Fi jitter exception: high retries but zero integrity failures
        - 0.36 * ((retry_rate > 0.22) & (integ_fail == 0) & (dev_consist >= 0.75))
        + 0.46 * ((retry_rate > 0.22) & (integ_fail > 0))
        + rng.normal(0, 0.09, rows)
    )

    y = (latent > 0.01).astype(int)

    df = pd.DataFrame({
        "auth_failures": auth_fail,
        "request_rate": np.round(req_rate, 2),
        "transfer_rate": np.round(trans_rate, 2),
        "failed_transfers": failed_trans,
        "packet_anomaly_score": np.round(packet_anom, 3),
        "connection_duration_s": np.round(conn_dur, 1),
        "discovery_rate": np.round(disc_rate, 2),
        "unauthorized_requests": unauth_req,
        "transfer_size_deviation": np.round(size_dev, 3),
        "retry_rate": np.round(retry_rate, 3),
        "integrity_failures": integ_fail,
        "historical_reputation": np.round(reputation, 3),
        "session_age_s": np.round(session_age, 1),
        "device_consistency": np.round(dev_consist, 3),
        "label": y
    })

    df.insert(0, "peer_id", [f"P{i:05d}" for i in range(rows)])
    return df

ROOT = Path(__file__).resolve().parents[1]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=12000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", default=str(ROOT / "data" / "p2p_behavior.csv"))
    args = ap.parse_args()

    print(f"--> Generating {args.rows} contextual peer behavioral sessions (Seed: {args.seed})...")
    df = generate_contextual_dataset(args.rows, args.seed)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"[SUCCESS] Saved dataset with {len(df)} rows to {out}")
    print(f"Class distribution: Benign = {int((df['label'] == 0).sum())} ({((df['label'] == 0).mean()*100):.1f}%), Malicious = {int((df['label'] == 1).sum())} ({((df['label'] == 1).mean()*100):.1f}%)")

if __name__ == "__main__":
    main()
