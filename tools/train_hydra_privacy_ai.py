#!/usr/bin/env python3
"""Train Hydra's tiny local privacy/tracking signal model.

This first version is a calibrated synthetic model. It intentionally labels ad/tracking
behavior as a privacy signal, not as malware. A future --csv dataset can replace the
synthetic corpus once labeled real Hydra telemetry is available.
"""
from __future__ import annotations
import argparse, csv, json, math
from pathlib import Path
from typing import Dict
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, roc_auc_score

RAW = ["connections","unique_destinations","dns_queries","dns_blocks","recent_connections","new_destinations","sni_blocks"]
FEATURES = ["log_connections","log_unique_destinations","log_dns_queries","dns_blocks","log_recent_connections","new_destinations","sni_blocks","dns_block_ratio","sni_block_ratio"]

def feat(r: Dict[str,float]):
    c=max(0,r["connections"]); u=max(0,r["unique_destinations"]); q=max(0,r["dns_queries"]); db=max(0,r["dns_blocks"]); rc=max(0,r["recent_connections"]); nd=max(0,r["new_destinations"]); sb=max(0,r["sni_blocks"])
    return [math.log1p(c),math.log1p(u),math.log1p(q),min(db,30),math.log1p(rc),min(nd,30),min(sb,30),db/max(c,1),sb/max(c,1)]

def synthetic(rng,n=12000):
    X=[];y=[]
    for _ in range(n//2):
        p=rng.choice(["normal","browser","ads"],p=[.35,.25,.40])
        if p=="normal": vals=[rng.integers(1,35),rng.integers(1,12),rng.integers(0,35),rng.integers(0,2),rng.integers(0,15),rng.integers(0,5),rng.integers(0,1)]
        elif p=="browser": vals=[rng.integers(40,450),rng.integers(10,80),rng.integers(20,450),rng.integers(0,8),rng.integers(15,250),rng.integers(0,18),rng.integers(0,8)]
        else: vals=[rng.integers(80,500),rng.integers(15,120),rng.integers(50,550),rng.integers(5,20),rng.integers(30,280),rng.integers(5,35),rng.integers(5,20)]
        X.append(feat(dict(zip(RAW,vals))));y.append(1 if p=="ads" else 0)
    for _ in range(n//2):
        p=rng.choice(["tracking","heavy","normalish"],p=[.55,.25,.20])
        if p=="tracking": vals=[rng.integers(60,520),rng.integers(20,150),rng.integers(60,650),rng.integers(5,25),rng.integers(25,320),rng.integers(5,45),rng.integers(5,25)]
        elif p=="heavy": vals=[rng.integers(120,900),rng.integers(30,180),rng.integers(100,900),rng.integers(10,30),rng.integers(60,650),rng.integers(12,70),rng.integers(8,30)]
        else: vals=[rng.integers(40,260),rng.integers(5,40),rng.integers(20,240),rng.integers(0,6),rng.integers(10,150),rng.integers(0,12),rng.integers(0,5)]
        X.append(feat(dict(zip(RAW,vals))));y.append(1 if p!="normalish" else 0)
    return np.asarray(X,float),np.asarray(y,int)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,default=Path('app/src/main/assets/hydra_ai_privacy_v1.json'));ap.add_argument('--seed',type=int,default=20260919);args=ap.parse_args()
    X,y=synthetic(np.random.default_rng(args.seed))
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
    pipe=make_pipeline(StandardScaler(),LogisticRegression(max_iter=300,class_weight='balanced',random_state=42));pipe.fit(Xtr,ytr)
    prob=pipe.predict_proba(Xte)[:,1];pred=(prob>=.5).astype(int)
    sc=pipe.named_steps['standardscaler'];clf=pipe.named_steps['logisticregression']
    root={"model_version":"hydra-ai-privacy-v1","model_type":"standardized_logistic_regression","purpose":"privacy_tracking_signal_only","decision_authority":"none","feature_names":FEATURES,"means":sc.mean_.round(8).tolist(),"scales":sc.scale_.round(8).tolist(),"weights":clf.coef_[0].round(8).tolist(),"bias":float(clf.intercept_[0]),"training_metrics":{"source":"synthetic_privacy_calibration","accuracy":float(accuracy_score(yte,pred)),"auc":float(roc_auc_score(yte,prob)),"samples":int(len(y))}}
    args.out.write_text(json.dumps(root,indent=2),encoding='utf-8');print(json.dumps(root['training_metrics'],indent=2))
if __name__=='__main__': main()
