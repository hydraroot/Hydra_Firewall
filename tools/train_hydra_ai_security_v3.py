#!/usr/bin/env python3
"""
Train Hydra's tiny on-device SECURITY anomaly model.

Default mode uses a balanced synthetic calibration corpus that deliberately
separates high advertising/tracking volume from security anomalies.

For real-data training, pass --csv FILE. The CSV must contain either the 14
model feature columns named below plus a `label` column (0=benign/privacy,
1=suspicious/malicious), or the 9 raw integer counters used by the Android
BehaviorFeatures object; derived ratios/logs are computed automatically.

Output is the compact JSON consumed by HydraAiEngine.kt. The model is a
secondary signal only; the firewall never delegates a blocking decision to it.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Dict, List

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, roc_auc_score

RAW_NAMES = [
    "connections", "unique_destinations", "dns_queries", "dns_blocks",
    "tls_alerts", "unusual_ports", "recent_connections", "new_destinations",
    "sni_blocks"
]
FEATURE_NAMES = [
    "log_connections", "log_unique_destinations", "log_dns_queries", "dns_blocks",
    "tls_alerts", "unusual_ports", "log_recent_connections", "new_destinations",
    "sni_blocks", "dns_block_ratio", "unusual_port_ratio", "new_destination_ratio",
    "destination_ratio", "tls_alert_ratio"
]


def features_from_raw(r: Dict[str, float]) -> List[float]:
    c = max(0.0, r["connections"])
    u = max(0.0, r["unique_destinations"])
    d = max(0.0, r["dns_queries"])
    db = max(0.0, r["dns_blocks"])
    ta = max(0.0, r["tls_alerts"])
    up = max(0.0, r["unusual_ports"])
    rc = max(0.0, r["recent_connections"])
    nd = max(0.0, r["new_destinations"])
    sb = max(0.0, r["sni_blocks"])
    return [
        math.log1p(c), math.log1p(u), math.log1p(d), min(db, 20.0), min(ta, 10.0),
        min(up, 20.0), math.log1p(rc), min(nd, 20.0), min(sb, 20.0),
        db / max(c, 1.0), up / max(c, 1.0), nd / max(u, 1.0),
        u / max(c, 1.0), ta / max(c, 1.0)
    ]


def sample_synthetic(rng: np.random.Generator, n: int = 12000):
    X, y = [], []
    # benign / ordinary: includes browsers and streaming apps with lots of traffic
    for _ in range(n // 2):
        profile = rng.choice(["normal", "browser", "streaming", "adheavy"], p=[.35,.25,.20,.20])
        if profile == "normal":
            c = rng.integers(1, 35); u = rng.integers(1, 12); d = rng.integers(0, 35)
            db = rng.integers(0, 2); ta = rng.integers(0, 1); up = rng.integers(0, 2)
            rc = rng.integers(0, 15); nd = rng.integers(0, 5); sb = rng.integers(0, 1)
        elif profile == "browser":
            c = rng.integers(40, 450); u = rng.integers(10, 80); d = rng.integers(20, 450)
            db = rng.integers(0, 8); ta = rng.integers(0, 2); up = rng.integers(0, 4)
            rc = rng.integers(15, 250); nd = rng.integers(0, 18); sb = rng.integers(0, 8)
        elif profile == "streaming":
            c = rng.integers(20, 220); u = rng.integers(2, 15); d = rng.integers(5, 100)
            db = rng.integers(0, 2); ta = rng.integers(0, 1); up = rng.integers(0, 2)
            rc = rng.integers(10, 180); nd = rng.integers(0, 5); sb = rng.integers(0, 1)
        else:  # advertising/tracking heavy, still not malware
            c = rng.integers(80, 500); u = rng.integers(15, 120); d = rng.integers(50, 550)
            db = rng.integers(5, 20); ta = rng.integers(0, 3); up = rng.integers(0, 5)
            rc = rng.integers(30, 280); nd = rng.integers(5, 35); sb = rng.integers(5, 20)
        X.append(features_from_raw(dict(zip(RAW_NAMES, [c,u,d,db,ta,up,rc,nd,sb])))); y.append(0)

    # suspicious / malicious: emphasize anomalous ports, TLS alerts, novel destinations,
    # bursts and high ratios. SNI blocks alone do not make a sample malicious.
    for _ in range(n // 2):
        profile = rng.choice(["suspicious", "c2", "exfil"], p=[.40,.35,.25])
        if profile == "suspicious":
            c = rng.integers(70, 700); u = rng.integers(25, 260); d = rng.integers(20, 260)
            db = rng.integers(0, 8); ta = rng.integers(2, 10); up = rng.integers(2, 14)
            rc = rng.integers(50, 450); nd = rng.integers(12, 80); sb = rng.integers(0, 7)
        elif profile == "c2":
            c = rng.integers(100, 1000); u = rng.integers(40, 300); d = rng.integers(40, 400)
            db = rng.integers(0, 6); ta = rng.integers(2, 10); up = rng.integers(2, 12)
            rc = rng.integers(100, 700); nd = rng.integers(20, 100); sb = rng.integers(0, 4)
        else:
            c = rng.integers(80, 900); u = rng.integers(15, 180); d = rng.integers(10, 250)
            db = rng.integers(0, 5); ta = rng.integers(1, 8); up = rng.integers(3, 18)
            rc = rng.integers(80, 700); nd = rng.integers(20, 120); sb = rng.integers(0, 3)
        X.append(features_from_raw(dict(zip(RAW_NAMES, [c,u,d,db,ta,up,rc,nd,sb])))); y.append(1)
    return np.asarray(X, dtype=np.float64), np.asarray(y, dtype=np.int32)


def load_csv(path: Path):
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or [])
        if "label" not in fields:
            raise ValueError("CSV needs a 'label' column")
        for row in reader:
            if all(name in fields for name in RAW_NAMES):
                raw = {name: float(row.get(name) or 0) for name in RAW_NAMES}
                x = features_from_raw(raw)
            elif all(name in fields for name in FEATURE_NAMES):
                x = [float(row[name]) for name in FEATURE_NAMES]
            else:
                raise ValueError("CSV must contain raw Hydra counters or the 14 derived feature columns")
            rows.append((x, int(float(row["label"]))))
    X = np.asarray([r[0] for r in rows], dtype=np.float64)
    y = np.asarray([r[1] for r in rows], dtype=np.int32)
    if len(set(y.tolist())) < 2:
        raise ValueError("CSV must contain both labels 0 and 1")
    return X, y


def save_model(path: Path, pipe, version: str, metrics: Dict[str, float]):
    scaler = pipe.named_steps["standardscaler"]
    clf = pipe.named_steps["logisticregression"]
    root = {
        "model_version": version,
        "model_type": "standardized_logistic_regression",
        "purpose": "security_behavior_anomaly_signal_only",
        "decision_authority": "none",
        "feature_names": FEATURE_NAMES,
        "means": scaler.mean_.round(8).tolist(),
        "scales": scaler.scale_.round(8).tolist(),
        "weights": clf.coef_[0].round(8).tolist(),
        "bias": float(clf.intercept_[0]),
        "training_metrics": metrics,
    }
    path.write_text(json.dumps(root, indent=2), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", type=Path)
    ap.add_argument("--out", type=Path, default=Path("app/src/main/assets/hydra_ai_model_v3.json"))
    ap.add_argument("--seed", type=int, default=20260919)
    args = ap.parse_args()

    if args.csv:
        X, y = load_csv(args.csv)
        source = "real_dataset"
    else:
        X, y = sample_synthetic(np.random.default_rng(args.seed))
        source = "synthetic_security_calibration"

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.25, random_state=42, stratify=y)
    pipe = make_pipeline(StandardScaler(), LogisticRegression(max_iter=300, class_weight="balanced", random_state=42))
    pipe.fit(X_train, y_train)
    prob = pipe.predict_proba(X_test)[:, 1]
    pred = (prob >= .5).astype(int)
    metrics = {"source": source, "accuracy": float(accuracy_score(y_test, pred)), "auc": float(roc_auc_score(y_test, prob)), "samples": int(len(y))}
    save_model(args.out, pipe, "hydra-ai-security-v3", metrics)
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    main()
