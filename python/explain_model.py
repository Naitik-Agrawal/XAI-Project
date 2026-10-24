from pathlib import Path
import json
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import shap

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "p2p_behavior.csv"
MODEL = ROOT / "models" / "random_forest.joblib"
RESULTS = ROOT / "results"
FEATURES = json.loads((ROOT / "models" / "feature_columns.json").read_text())

df = pd.read_csv(DATA)
X = df[FEATURES]

model = joblib.load(MODEL)

# Limit the explanation sample to keep runtime practical.
sample = X.sample(min(1000, len(X)), random_state=42)

explainer = shap.TreeExplainer(model)
sv = explainer.shap_values(sample)

# SHAP versions can return either a list or ndarray for classifiers.
if isinstance(sv, list):
    values = sv[1]
else:
    values = sv
    if values.ndim == 3:
        values = values[:, :, 1]

plt.figure()
shap.summary_plot(values, sample, show=False)
plt.tight_layout()
plt.savefig(RESULTS / "shap_summary.png", dpi=220, bbox_inches="tight")
plt.close()

# Explain one malicious-risk example selected from the sample.
row = sample.iloc[[0]]
row_sv = explainer.shap_values(row)
if isinstance(row_sv, list):
    row_values = row_sv[1][0]
else:
    row_values = row_sv[0]
    if getattr(row_values, "ndim", 1) == 2:
        row_values = row_values[:, 1][0]

explanation = pd.DataFrame({
    "feature": FEATURES,
    "value": row.iloc[0].values,
    "shap_value": row_values
}).sort_values("shap_value", key=lambda s: s.abs(), ascending=False)

explanation.to_csv(RESULTS / "single_peer_shap_values.csv", index=False)

top = explanation.head(10).sort_values("shap_value")
plt.figure(figsize=(8, 5))
plt.barh(top["feature"], top["shap_value"])
plt.axvline(0, linestyle="--")
plt.xlabel("SHAP contribution")
plt.title("Top SHAP Contributions for One Peer")
plt.tight_layout()
plt.savefig(RESULTS / "shap_peer_explanation.png", dpi=220)
plt.close()

print(explanation.head(10).to_string(index=False))
