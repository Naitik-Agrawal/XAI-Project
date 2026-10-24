import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report, roc_curve
)

FEATURES = [
    "auth_failures", "request_rate", "transfer_rate", "failed_transfers",
    "packet_anomaly_score", "connection_duration_s", "discovery_rate",
    "unauthorized_requests", "transfer_size_deviation", "retry_rate",
    "integrity_failures", "historical_reputation", "session_age_s",
    "device_consistency"
]

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "p2p_behavior.csv"
MODEL_DIR = ROOT / "models"
RESULTS = ROOT / "results"
MODEL_DIR.mkdir(exist_ok=True)
RESULTS.mkdir(exist_ok=True)

df = pd.read_csv(DATA)
X = df[FEATURES]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, stratify=y, random_state=42
)

# Development grid: compact enough for a normal laptop.
# Expand this grid for the final publication experiment if compute permits.
param_grid = {
    "n_estimators": [100, 200],
    "max_depth": [12, 20],
    "min_samples_split": [2],
    "min_samples_leaf": [1],
    "criterion": ["gini"],
}

search = GridSearchCV(
    RandomForestClassifier(
        random_state=42, class_weight="balanced", n_jobs=-1
    ),
    param_grid=param_grid,
    cv=5,
    scoring="f1",
    n_jobs=-1,
    verbose=0
)
search.fit(X_train, y_train)
model = search.best_estimator_

prob = model.predict_proba(X_test)[:, 1]
pred = (prob >= 0.50).astype(int)

metrics = {
    "best_params": search.best_params_,
    "accuracy": float(accuracy_score(y_test, pred)),
    "precision": float(precision_score(y_test, pred)),
    "recall": float(recall_score(y_test, pred)),
    "f1": float(f1_score(y_test, pred)),
    "roc_auc": float(roc_auc_score(y_test, prob)),
    "false_positive_rate": float(
        confusion_matrix(y_test, pred).ravel()[1] /
        (confusion_matrix(y_test, pred).ravel()[1] +
         confusion_matrix(y_test, pred).ravel()[0])
    )
}

with open(RESULTS / "metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

with open(RESULTS / "classification_report.txt", "w") as f:
    f.write(classification_report(y_test, pred, target_names=["Normal", "Malicious"]))

cm = confusion_matrix(y_test, pred)
np.savetxt(RESULTS / "confusion_matrix.csv", cm, delimiter=",", fmt="%d")

plt.figure(figsize=(6, 5))
plt.imshow(cm)
plt.title("Random Forest Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.colorbar()
for i in range(cm.shape[0]):
    for j in range(cm.shape[1]):
        plt.text(j, i, cm[i, j], ha="center", va="center")
plt.xticks([0, 1], ["Normal", "Malicious"])
plt.yticks([0, 1], ["Normal", "Malicious"])
plt.tight_layout()
plt.savefig(RESULTS / "confusion_matrix.png", dpi=200)
plt.close()

fpr, tpr, _ = roc_curve(y_test, prob)
plt.figure(figsize=(6, 5))
plt.plot(fpr, tpr, label=f"AUC={metrics['roc_auc']:.4f}")
plt.plot([0, 1], [0, 1], "--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Random Forest ROC Curve")
plt.legend()
plt.tight_layout()
plt.savefig(RESULTS / "roc_curve.png", dpi=200)
plt.close()

imp = pd.Series(model.feature_importances_, index=FEATURES).sort_values()
plt.figure(figsize=(8, 6))
imp.plot(kind="barh")
plt.xlabel("Importance")
plt.title("Random Forest Feature Importance")
plt.tight_layout()
plt.savefig(RESULTS / "feature_importance.png", dpi=200)
plt.close()

joblib.dump(model, MODEL_DIR / "random_forest.joblib")
with open(MODEL_DIR / "feature_columns.json", "w") as f:
    json.dump(FEATURES, f, indent=2)

print(json.dumps(metrics, indent=2))
print(f"Model saved to {MODEL_DIR / 'random_forest.joblib'}")
