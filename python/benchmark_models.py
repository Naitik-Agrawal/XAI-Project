"""
XAI-ZT-P2P: Multi-Model Comparative Benchmark Suite
Evaluates multiple machine learning architectures on the 14-feature P2P behavioral telemetry dataset:
1. Random Forest (RF) - Ensemble Baseline
2. XGBoost (XGB) - Extreme Gradient Boosting
3. LightGBM (LGBM) - Fast Gradient Boosted Trees
4. Multi-Layer Perceptron (MLP) - Deep Neural Network
5. Support Vector Machine (SVM) - Kernel RBF / Calibrated Linear Margin
6. Logistic Regression (LR) - Linear Baseline
"""

import argparse
import json
import time
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    from lightgbm import LGBMClassifier
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "p2p_behavior.csv"
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

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

def load_data():
    df = pd.read_csv(DATA_PATH)
    X = df[FEATURES]
    y = df["label"]
    return train_test_split(X, y, test_size=0.20, stratify=y, random_state=42)

def build_models():
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=150,
            max_depth=16,
            min_samples_split=2,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
        "Multi-Layer Perceptron": Pipeline([
            ("scaler", StandardScaler()),
            ("mlp", MLPClassifier(
                hidden_layer_sizes=(48, 24),
                activation="relu",
                max_iter=300,
                early_stopping=True,
                random_state=42,
            )),
        ]),
        "Support Vector Machine": Pipeline([
            ("scaler", StandardScaler()),
            ("svm", CalibratedClassifierCV(
                LinearSVC(random_state=42, max_iter=2000, dual="auto")
            )),
        ]),
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("lr", LogisticRegression(max_iter=1000, random_state=42)),
        ]),
    }

    if HAS_XGB:
        models["XGBoost"] = XGBClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )

    if HAS_LGBM:
        models["LightGBM"] = LGBMClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        )

    return models

def benchmark():
    print("=" * 80)
    print("  XAI-ZT-P2P: Multi-Model Comparative Benchmark Suite")
    print("=" * 80)

    X_train, X_test, y_train, y_test = load_data()
    print(f"Dataset split: Train = {len(X_train)} samples, Test = {len(X_test)} samples")
    print(f"Features: {len(FEATURES)} behavioral telemetry dimensions\n")

    models = build_models()
    results = []
    roc_curves = {}

    # Convert test sample to numpy array for fast, dataframe-overhead-free latency profiling
    eval_sample_arr = X_test.head(500).to_numpy()

    for name, model in models.items():
        print(f"--> Training and evaluating: {name} ...", end=" ", flush=True)

        # Measure training duration
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        train_time_s = time.perf_counter() - t0

        # Predict probabilities
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        elif hasattr(model, "decision_function"):
            df_vals = model.decision_function(X_test)
            y_prob = 1.0 / (1.0 + np.exp(-df_vals))
        else:
            y_prob = model.predict(X_test)

        y_pred = (y_prob >= 0.50).astype(int)

        # Latency profiler: 500 single-sample inferences with numpy input
        # Convert first row to appropriate format
        test_df_single = X_test.iloc[[0]]
        t_infer_start = time.perf_counter()
        for idx in range(len(eval_sample_arr)):
            row_arr = eval_sample_arr[idx : idx + 1]
            if isinstance(model, Pipeline):
                _ = model.predict_proba(pd.DataFrame(row_arr, columns=FEATURES))
            else:
                _ = model.predict_proba(row_arr)
        total_infer_time_ms = (time.perf_counter() - t_infer_start) * 1000.0
        mean_latency_ms = total_infer_time_ms / len(eval_sample_arr)

        # Compute classification metrics
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        auc = float(roc_auc_score(y_test, y_prob))

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        fpr_arr, tpr_arr, _ = roc_curve(y_test, y_prob)
        roc_curves[name] = {
            "fpr": fpr_arr.tolist(),
            "tpr": tpr_arr.tolist(),
            "auc": auc,
        }

        row = {
            "model": name,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "fpr": round(fpr, 4),
            "latency_ms": round(mean_latency_ms, 3),
            "train_time_s": round(train_time_s, 3),
        }
        results.append(row)
        print(f"Done (Acc: {acc*100:.2f}%, F1: {f1:.4f}, AUC: {auc:.4f}, Latency: {mean_latency_ms:.2f} ms)")

    # Sort results by Accuracy descending
    results.sort(key=lambda x: x["accuracy"], reverse=True)
    df_res = pd.DataFrame(results)

    # Save to CSV and JSON
    csv_path = RESULTS_DIR / "model_comparison.csv"
    json_path = RESULTS_DIR / "model_comparison.json"
    df_res.to_csv(csv_path, index=False)
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 95)
    print("                              MULTI-MODEL BENCHMARK RESULTS")
    print("=" * 95)
    header = f"{'Model':<25} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<7} | {'F1-Score':<8} | {'ROC-AUC':<7} | {'FPR':<6} | {'Latency':<8}"
    print(header)
    print("-" * 95)
    for r in results:
        print(f"{r['model']:<25} | {r['accuracy']*100:>7.2f}% | {r['precision']*100:>8.2f}% | {r['recall']*100:>6.2f}% | {r['f1_score']:>8.4f} | {r['roc_auc']:>7.4f} | {r['fpr']*100:>5.2f}% | {r['latency_ms']:>6.2f} ms")
    print("=" * 95 + "\n")

    # Plot 1: Combined ROC Curves
    plt.figure(figsize=(8, 6))
    colors = ["#10b981", "#2563eb", "#8b5cf6", "#f59e0b", "#ec4899", "#64748b"]
    for idx, (name, curve_data) in enumerate(roc_curves.items()):
        c = colors[idx % len(colors)]
        plt.plot(curve_data["fpr"], curve_data["tpr"], color=c, lw=2, label=f"{name} (AUC = {curve_data['auc']:.4f})")
    plt.plot([0, 1], [0, 1], color="#94a3b8", lw=1.5, linestyle="--", label="Random Chance (AUC = 0.5000)")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate (FPR)", fontsize=11, fontweight="bold")
    plt.ylabel("True Positive Rate (TPR / Recall)", fontsize=11, fontweight="bold")
    plt.title("Comparative ROC Curves: Multi-Model Zero-Trust Intrusion Detection", fontsize=12, fontweight="bold")
    plt.legend(loc="lower right", framealpha=0.9)
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.tight_layout()
    roc_plot_path = RESULTS_DIR / "model_comparison_roc.png"
    plt.savefig(roc_plot_path, dpi=220)
    plt.close()
    print(f"[PLOT] Saved comparative ROC curves to: {roc_plot_path}")

    # Plot 2: Grouped Bar Chart Comparison
    plt.figure(figsize=(10, 5.5))
    x_indices = np.arange(len(results))
    bar_width = 0.18

    acc_vals = [r["accuracy"] for r in results]
    prec_vals = [r["precision"] for r in results]
    rec_vals = [r["recall"] for r in results]
    f1_vals = [r["f1_score"] for r in results]
    auc_vals = [r["roc_auc"] for r in results]

    plt.bar(x_indices - 2 * bar_width, acc_vals, width=bar_width, label="Accuracy", color="#3b82f6")
    plt.bar(x_indices - bar_width, prec_vals, width=bar_width, label="Precision", color="#10b981")
    plt.bar(x_indices, rec_vals, width=bar_width, label="Recall", color="#f59e0b")
    plt.bar(x_indices + bar_width, f1_vals, width=bar_width, label="F1-Score", color="#8b5cf6")
    plt.bar(x_indices + 2 * bar_width, auc_vals, width=bar_width, label="ROC-AUC", color="#ec4899")

    plt.xticks(x_indices, [r["model"] for r in results], rotation=15, ha="right", fontweight="bold")
    plt.ylim([0.70, 1.02])
    plt.ylabel("Score Metric", fontsize=11, fontweight="bold")
    plt.title("Comparative Performance Across Machine Learning Classifiers", fontsize=12, fontweight="bold")
    plt.legend(loc="lower right", framealpha=0.9, ncol=3)
    plt.grid(axis="y", linestyle=":", alpha=0.6)
    plt.tight_layout()
    bar_plot_path = RESULTS_DIR / "model_comparison_metrics.png"
    plt.savefig(bar_plot_path, dpi=220)
    plt.close()
    print(f"[PLOT] Saved comparative metrics bar chart to: {bar_plot_path}")

if __name__ == "__main__":
    benchmark()
