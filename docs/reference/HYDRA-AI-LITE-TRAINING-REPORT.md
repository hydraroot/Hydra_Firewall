# Hydra AI Lite — Training Report

## What it is
Hydra AI Lite is a very small on-device logistic-regression model used only as a **behavior-anomaly signal**. It is not a malware detector and it has no authority to block traffic.

## Model size
The serialized parameter file is about 2 KB and uses only standard arithmetic. No TensorFlow Lite, ONNX Runtime, network service, account, or cloud dependency is required.

## Inputs
- connection volume
- unique destinations
- DNS query volume
- DNS block count
- TLS alert count
- unusual port count
- recent connection volume
- new destination count
- HTTPS/SNI block count
- derived ratios for the above

## Training
The first prototype was trained with Python/scikit-learn on synthetic, expert-shaped scenarios:
- normal behavior
- ad-heavy behavior
- suspicious behavior
- malware-like behavior

Controlled label noise was added to keep the classifier from treating synthetic thresholds as absolute truth.

Synthetic hold-out metrics for the current v2 prototype:
- Accuracy: about 85.6%
- ROC AUC: about 88.1%

These numbers describe the synthetic dataset only. They are **not evidence of real-world malware-detection accuracy**.

## Safety design
The model produces a score for the Security Center. Firewall rules, blocklists, DNS decisions, SNI blocking, and quarantine remain deterministic Hydra decisions.

## Next training step
The useful next dataset is real, consented Hydra telemetry labeled as normal/anomalous by review. That can be used to retrain the same tiny model without changing the Android inference code.

## Real-data training status
A build-time training workflow is being prepared around publicly documented Android malware research datasets, including CICMalDroid 2020. The dataset page describes 11,598 usable analysis results across Adware, Banking, SMS malware, Riskware and Benign, plus static/dynamic/PCAP-derived features. Because the official download is gated by a dataset request form, no raw dataset is embedded or fetched automatically by Hydra.

The bundled Android model therefore remains a synthetic security-only prototype until a legally usable real dataset is supplied to the training step.
