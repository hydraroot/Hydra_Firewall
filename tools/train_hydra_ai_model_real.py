#!/usr/bin/env python3
"""Train Hydra AI Lite from real, reviewed Hydra telemetry.

Input CSV columns (same semantics consumed by the Android model):
  connections, unique_destinations, dns_queries, dns_blocks, tls_alerts,
  unusual_ports, recent_connections, new_destinations, sni_blocks, label

label: 0 = reviewed normal behavior, 1 = reviewed suspicious/malicious behavior.
This intentionally requires human-reviewed labels; it never infers labels from
raw traffic automatically.
"""
import argparse, json, math
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score

FEATURES = [
    "connections", "unique_destinations", "dns_queries", "dns_blocks",
    "tls_alerts", "unusual_ports", "recent_connections", "new_destinations",
    "sni_blocks",
]

def ratio(value, total):
    return max(0.0, float(value)) / max(1.0, float(total))

def vector(row):
    c = max(0, int(row.connections)); u = max(0, int(row.unique_destinations)); d = max(0, int(row.dns_queries))
    db = max(0, int(row.dns_blocks)); tls = max(0, int(row.tls_alerts)); up = max(0, int(row.unusual_ports))
    rc = max(0, int(row.recent_connections)); nd = max(0, int(row.new_destinations)); sb = max(0, int(row.sni_blocks))
    return [
        math.log1p(c), math.log1p(u), math.log1p(d), min(db, 20), min(tls, 10), min(up, 20),
        math.log1p(rc), min(nd, 20), min(sb, 20),
        ratio(db, c), ratio(up, c), ratio(nd, u), ratio(u, c), ratio(tls, c)
    ]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--output", type=Path, default=Path("app/src/main/assets/hydra_ai_model_v3.json"))
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    required = FEATURES + ["label"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise SystemExit("Missing columns: " + ", ".join(missing))

    df = df.dropna(subset=required).copy()
    df["label"] = df["label"].astype(int)
    if set(df["label"].unique()) != {0, 1}:
        raise SystemExit("label must contain both 0 (normal) and 1 (suspicious/malicious)")
    if len(df) < 200:
        raise SystemExit("Need at least 200 reviewed real examples")

    X = np.asarray([vector(row) for row in df.itertuples(index=False)], dtype=np.float64)
    y = df["label"].to_numpy(dtype=np.int64)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.25, random_state=11, stratify=y)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    model = LogisticRegression(max_iter=3000, C=.7, class_weight="balanced", solver="liblinear")
    model.fit(X_train_s, y_train)
    probs = model.predict_proba(X_test_s)[:, 1]

    payload = {
        "model_version": "hydra-ai-lite-3-real-telemetry",
        "model_type": "standardized_logistic_regression",
        "purpose": "behavior_anomaly_signal_only",
        "decision_authority": "none",
        "feature_names": [
            "log_connections", "log_unique_destinations", "log_dns_queries", "dns_blocks",
            "tls_alerts", "unusual_ports", "log_recent_connections", "new_destinations", "sni_blocks",
            "dns_block_ratio", "unusual_port_ratio", "new_destination_ratio", "destination_ratio", "tls_alert_ratio"
        ],
        "means": scaler.mean_.tolist(),
        "scales": scaler.scale_.tolist(),
        "weights": model.coef_[0].tolist(),
        "bias": float(model.intercept_[0]),
        "training_samples": int(len(df)),
        "test_metrics_real_reviewed": {
            "accuracy": float(accuracy_score(y_test, (probs >= .5).astype(int))),
            "auc": float(roc_auc_score(y_test, probs)),
        },
        "training_note": "Trained only from human-reviewed Hydra telemetry. Replace only after checking class balance, false-positive rate, and temporal holdout performance."
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload["test_metrics_real_reviewed"], indent=2))
    print(f"Wrote {args.output}")

if __name__ == "__main__":
    main()
