#!/usr/bin/env python3
"""Train Hydra AI Lite.

This version trains a security-only anomaly signal. Ad-heavy/privacy-heavy
traffic is treated as benign for the security head so advertising activity is
not mislabeled as malware. Replace/extend the training set with real,
consented Hydra telemetry before treating the model as a stronger verdict.
"""
import json, math
from pathlib import Path
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score

RNG = np.random.default_rng(123)
N = 30000
PARAMS = {
    "normal":      ([20,7,10,0.4,0.2,0.8,12,1.2,0.2], [12,5,7,1.0,0.6,1.2,9,1.5,0.6]),
    "ad_heavy":    ([45,12,28,4.0,0.4,1.0,32,3.0,2.5], [25,8,18,3,1.0,1.5,18,2.5,2]),
    "suspicious":  ([65,20,36,2.6,1.6,2.6,50,6.5,1.8], [35,12,22,3,1.5,2.3,25,4.5,1.8]),
    "malware_like":([95,38,55,5.5,3.0,5.0,75,12,4.0], [45,20,28,5,2.5,3.5,30,8,3.0]),
}
FEATURE_NAMES = [
    "log_connections", "log_unique_destinations", "log_dns_queries",
    "dns_blocks", "tls_alerts", "unusual_ports", "log_recent_connections",
    "new_destinations", "sni_blocks", "dns_block_ratio", "unusual_port_ratio",
    "new_destination_ratio", "destination_ratio", "tls_alert_ratio",
]

def vector(vals):
    connections, unique, dns, dns_blocks, tls, unusual, recent, newd, sni = vals
    total = max(1, connections)
    return [
        math.log1p(max(0, connections)), math.log1p(max(0, unique)), math.log1p(max(0, dns)),
        min(max(0, dns_blocks), 20), min(max(0, tls), 10), min(max(0, unusual), 20),
        math.log1p(max(0, recent)), min(max(0, newd), 20), min(max(0, sni), 20),
        max(0, dns_blocks) / total, max(0, unusual) / total,
        max(0, newd) / max(1, unique), max(0, unique) / total, max(0, tls) / total,
    ]

X, y = [], []
for _ in range(N):
    name = RNG.choice(list(PARAMS), p=[.60, .17, .17, .06])
    means, stds = PARAMS[name]
    vals = np.maximum(0, RNG.normal(means, stds))
    ints = [int(round(v)) for v in vals]
    ints[3] = min(ints[3], ints[2])
    # Ad-heavy traffic is a privacy signal, not a malware verdict. Keep it in
    # the benign/security-normal class so the security model does not equate
    # advertising volume with maliciousness.
    label = 0 if name in ("normal", "ad_heavy") else 1
    if RNG.random() < 0.07:
        label = 1 - label
    X.append(vector(ints))
    y.append(label)

X_train, X_test, y_train, y_test = train_test_split(
    np.asarray(X), np.asarray(y), test_size=.25, random_state=7, stratify=y
)
scaler = StandardScaler()
model = LogisticRegression(max_iter=2000, C=.7, class_weight="balanced", solver="liblinear")
model.fit(scaler.fit_transform(X_train), y_train)
probs = model.predict_proba(scaler.transform(X_test))[:, 1]

output = {
    "model_version": "hydra-ai-lite-2-security",
    "model_type": "standardized_logistic_regression",
    "purpose": "behavior_anomaly_signal_only",
    "decision_authority": "none",
    "feature_names": FEATURE_NAMES,
    "means": scaler.mean_.tolist(),
    "scales": scaler.scale_.tolist(),
    "weights": model.coef_[0].tolist(),
    "bias": float(model.intercept_[0]),
    "test_metrics_synthetic": {
        "accuracy": float(accuracy_score(y_test, (probs >= .5).astype(int))),
        "auc": float(roc_auc_score(y_test, probs)),
    },
    "training_note": (
        "Security-only prototype trained on synthetic, expert-shaped behavior scenarios "
        "(normal/ad-heavy treated as benign, suspicious/malware-like as positive) with controlled noise. "
        "Not trained on real malware samples and must not be presented as a malware verdict."
    ),
}
out = Path(__file__).resolve().parents[1] / "app" / "src" / "main" / "assets" / "hydra_ai_model_v1.json"
out.write_text(json.dumps(output, indent=2), encoding="utf-8")
print(f"Wrote {out}")
print(f"synthetic test accuracy={output['test_metrics_synthetic']['accuracy']:.4f}")
print(f"synthetic test AUC={output['test_metrics_synthetic']['auc']:.4f}")
