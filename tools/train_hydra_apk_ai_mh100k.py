#!/usr/bin/env python3
"""Build a tiny APK-security model from the public MH-100K Android dataset.

Expected local files:
  mh100.parquet
  mh100-labels.csv
  feature_names.csv (recommended when parquet uses indexed columns)

The trainer selects a compact, high-signal permission subset and exports a
small JSON model that can be embedded in Hydra. This is a build-time tool; the
APK does not download the dataset. MH-100K is licensed CC BY 4.0.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, roc_auc_score

PERMS = [
    "android.permission.READ_SMS","android.permission.RECEIVE_SMS","android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS","android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG","android.permission.WRITE_CALL_LOG","android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO","android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE","android.permission.READ_PHONE_NUMBERS",
    "android.permission.SYSTEM_ALERT_WINDOW","android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.WRITE_EXTERNAL_STORAGE","android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.RECEIVE_BOOT_COMPLETED","android.permission.FOREGROUND_SERVICE",
    "android.permission.INTERNET","android.permission.WAKE_LOCK",
    "android.permission.BLUETOOTH","android.permission.BLUETOOTH_ADMIN",
]

def find_label_col(df):
    for c in ("label","malware","is_malware","class"):
        if c in df.columns: return c
    raise ValueError("No malware label column in labels CSV")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--parquet", type=Path, required=True)
    ap.add_argument("--labels", type=Path, required=True)
    ap.add_argument("--feature-names", type=Path)
    ap.add_argument("--output", type=Path, default=Path("app/src/main/assets/hydra_apk_ai_mh100k_v1.json"))
    args=ap.parse_args()
    x=pd.read_parquet(args.parquet)
    labels=pd.read_csv(args.labels)
    # Resolve indexed feature names when supplied.
    if args.feature_names:
        fn=pd.read_csv(args.feature_names)
        name_col=fn.columns[-1]
        names=fn[name_col].astype(str).tolist()
        rename={str(i): names[i] for i in range(min(len(names), len(x.columns)))}
        x=x.rename(columns={c: rename.get(str(c), c) for c in x.columns})
    label_col=find_label_col(labels)
    if len(x)!=len(labels):
        raise ValueError("Parquet and labels row counts differ")
    cols=[p for p in PERMS if p in x.columns]
    if len(cols)<8:
        raise ValueError(f"Only {len(cols)} target permissions found; expected at least 8")
    y=labels[label_col].astype(int).to_numpy()
    X=x[cols].fillna(0).astype(float).to_numpy()
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=41,stratify=y)
    pipe=make_pipeline(StandardScaler(with_mean=False),LogisticRegression(max_iter=2000,class_weight="balanced",solver="liblinear"))
    pipe.fit(Xtr,ytr)
    prob=pipe.predict_proba(Xte)[:,1]
    lr=pipe[-1]; scaler=pipe[0]
    payload={
        "model_version":"hydra-apk-ai-mh100k-v1",
        "model_type":"permission_logistic_regression",
        "purpose":"static_apk_security_signal_only",
        "dataset":"MH-100K Android Malware Dataset",
        "license":"CC-BY-4.0",
        "feature_names":cols,
        "means":scaler.mean_.tolist() if hasattr(scaler,'mean_') else [0.0]*len(cols),
        "scales":scaler.scale_.tolist() if hasattr(scaler,'scale_') else [1.0]*len(cols),
        "weights":lr.coef_[0].tolist(),
        "bias":float(lr.intercept_[0]),
        "training_samples":int(len(y)),
        "test_metrics":{"accuracy":float(accuracy_score(yte,(prob>=.5).astype(int))),"auc":float(roc_auc_score(yte,prob))}
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(payload,indent=2),encoding='utf-8')
    print(json.dumps(payload["test_metrics"],indent=2))

if __name__=='__main__': main()
