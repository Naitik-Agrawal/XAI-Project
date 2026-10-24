import argparse
import json
import sys
from pathlib import Path
import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "random_forest.joblib"
FEATURES_PATH = ROOT / "models" / "feature_columns.json"

_CACHED_MODEL = None
_CACHED_FEATURES = None

def get_model_and_features():
    global _CACHED_MODEL, _CACHED_FEATURES
    if _CACHED_MODEL is None:
        _CACHED_MODEL = joblib.load(MODEL_PATH)
        _CACHED_MODEL.n_jobs = 1
        _CACHED_FEATURES = json.loads(FEATURES_PATH.read_text())
    return _CACHED_MODEL, _CACHED_FEATURES

def policy(risk):
    if risk < 0.30:
        return "ALLOW"
    if risk < 0.60:
        return "RESTRICT"
    if risk < 0.80:
        return "VERIFY_QUARANTINE"
    return "BLOCK"

MITIGATION_ACTIONS = {
    "ALLOW": {
        "status": "APPROVED",
        "chunk_size_kb": 64,
        "bandwidth_cap_mbps": 50,
        "challenge_required": False,
        "description": "Standard P2P data flow permitted at full bandwidth (64 KB chunks)."
    },
    "RESTRICT": {
        "status": "THROTTLED",
        "chunk_size_kb": 32,
        "bandwidth_cap_mbps": 5,
        "challenge_required": False,
        "description": "Elevated behavioral risk; chunk size reduced to 32 KB, rate-limiting enforced."
    },
    "VERIFY_QUARANTINE": {
        "status": "QUARANTINED",
        "chunk_size_kb": 16,
        "bandwidth_cap_mbps": 0.5,
        "challenge_required": True,
        "description": "High anomaly; file sharing suspended, 16 KB probe size, cryptographic challenge issued."
    },
    "BLOCK": {
        "status": "TERMINATED",
        "chunk_size_kb": 0,
        "bandwidth_cap_mbps": 0,
        "challenge_required": False,
        "description": "Confirmed malicious; peer blacklisted, sockets terminated, incident logged."
    }
}

def explain_features(model, features, row):
    importances = dict(zip(features, getattr(model, "feature_importances_", [1.0 / len(features)] * len(features))))
    baselines = {
        "auth_failures": (0.0, 1.0, "higher"),
        "request_rate": (3.0, 3.0, "higher"),
        "transfer_rate": (6.0, 4.0, "neutral"),
        "failed_transfers": (0.0, 1.0, "higher"),
        "packet_anomaly_score": (0.15, 0.15, "higher"),
        "connection_duration_s": (120.0, 60.0, "lower"),
        "discovery_rate": (2.0, 1.5, "higher"),
        "unauthorized_requests": (0.0, 1.0, "higher"),
        "transfer_size_deviation": (0.45, 0.3, "higher"),
        "retry_rate": (0.12, 0.1, "higher"),
        "integrity_failures": (0.0, 1.0, "higher"),
        "historical_reputation": (0.80, 0.2, "lower"),
        "session_age_s": (250.0, 120.0, "lower"),
        "device_consistency": (0.85, 0.15, "lower"),
    }
    contributions = []
    for f in features:
        val = row.get(f, 0.0)
        base_val, scale, direction = baselines.get(f, (0.0, 1.0, "higher"))
        if direction == "higher":
            dev = max(0.0, (val - base_val) / max(scale, 1e-5))
        elif direction == "lower":
            dev = max(0.0, (base_val - val) / max(scale, 1e-5))
        else:
            dev = abs(val - base_val) / max(scale, 1e-5)
        impact = dev * importances.get(f, 0.05)
        contributions.append({
            "feature": f,
            "observed_value": round(val, 4),
            "relative_risk_impact": round(impact, 4)
        })
    contributions.sort(key=lambda x: x["relative_risk_impact"], reverse=True)
    return contributions[:4]

def explainable_action(probability, row, model, features):
    risk = float(probability)
    act = policy(risk)
    return {
        "risk_score": round(risk, 4),
        "malicious_probability": round(risk, 4),
        "action": act,
        "mitigation": MITIGATION_ACTIONS[act],
        "top_contributing_features": explain_features(model, features, row),
        "peer_features": row,
        "model": "RandomForest"
    }

def score(payload):
    model, features = get_model_and_features()
    row = {f: float(payload.get(f, 0.0)) for f in features}
    X = pd.DataFrame([row], columns=features)
    probability = float(model.predict_proba(X)[0, 1])
    return explainable_action(probability, row, model, features)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--json", help="JSON object containing feature values")
    ap.add_argument("--pipe", action="store_true", help="Keep process open and read JSON lines from stdin")
    args = ap.parse_args()

    if args.pipe:
        # Pre-warm model
        get_model_and_features()
        sys.stdout.write(json.dumps({"status": "READY"}) + "\n")
        sys.stdout.flush()
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                res = score(data)
                sys.stdout.write(json.dumps(res) + "\n")
            except Exception as e:
                sys.stdout.write(json.dumps({"error": str(e)}) + "\n")
            sys.stdout.flush()
        return

    if args.demo:
        payload = {
            "auth_failures": 5, "request_rate": 20,
            "transfer_rate": 8, "failed_transfers": 4,
            "packet_anomaly_score": 0.88, "connection_duration_s": 25,
            "discovery_rate": 10, "unauthorized_requests": 4,
            "transfer_size_deviation": 2.2, "retry_rate": 0.8,
            "integrity_failures": 3, "historical_reputation": 0.18,
            "session_age_s": 30, "device_consistency": 0.35
        }
    elif args.json:
        payload = json.loads(args.json)
    else:
        raise SystemExit("Use --demo, --json '<object>', or --pipe")

    print(json.dumps(score(payload), indent=2))

if __name__ == "__main__":
    main()
