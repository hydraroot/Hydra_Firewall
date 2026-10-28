# Hydra MH-100K Static APK Security AI — Training Report

## Dataset

- Rows: **101,934** Android samples
- Malware: **9,800**
- Benign: **92,134**
- Static feature columns: **24,833**
  - 166 permissions
  - 250 intents
  - 24,417 API-call features

## Model selection

A stratified 70/15/15 train/validation/test split was created. Feature selection was calculated **on the training split only** to avoid leakage. The compact candidate selected the top **2,048** features by chi-square. A logistic-regression classifier with balanced class weighting was trained as a static security signal.

## Unbiased held-out test (train-only model)

The following metrics belong to `hydra_mh100_model_2048.npz`, trained only on the 70% training split. The 15% test set remained untouched during training/model selection.

| Threshold | Precision | Recall | F1 | False-positive rate | TP | FP |
|---:|---:|---:|---:|---:|---:|---:|
| 0.50 | 0.6411 | 0.9459 | 0.7642 | 0.0563 | 2781 | 1557 |
| 0.80 | 0.7602 | 0.9112 | 0.8289 | 0.0306 | 2679 | 845 |
| 0.90 | 0.8136 | 0.8806 | 0.8458 | 0.0215 | 2589 | 593 |
| 0.95 | 0.8668 | 0.8126 | 0.8388 | 0.0133 | 2389 | 367 |
| 0.99 | 0.9082 | 0.4810 | 0.6289 | 0.0052 | 1414 | 143 |

Overall held-out test ROC-AUC: **0.9785**

Overall held-out test PR-AUC: **0.8709**

These scores are model-evaluation metrics, not calibrated real-world probabilities. The dataset is a static Android malware dataset; this model is not a general-purpose guarantee that an APK is safe or malicious.

## Deployment model

After model selection, the 2,048-feature model was retrained on all 101,934 samples and saved as `hydra_mh100_production_2048.npz`. The compact runtime artifact is `hydra_apk_ai_mh100k_v2.bin`. It contains 2,048 FNV-1a-64 feature hashes, float32 weights, one mode byte per feature, and the intercept.

**Important integration note:** Hydra's current APK scanner does not yet extract the full MH-100K API-call feature vocabulary. Therefore this model should not be presented in the APK UI as if all 2,048 features are currently being evaluated until a matching static feature extractor is implemented. The artifact is ready for that extractor stage.

## Safety architecture

This model must remain a **secondary signal**. Deterministic threat signatures, known malicious indicators, explicit user rules, and network protection remain authoritative. A high model score should trigger deeper analysis or a user-facing warning, not an automatic block by itself.
