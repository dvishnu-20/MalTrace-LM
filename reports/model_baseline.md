# MalTrace-LM Predictive Model Baseline Report

**Project**: MalTrace-LM  
**Date**: 2026-07-28  
**Artifact Directory**: [`models/family_model/`](file:///c:/Users/duddu/Downloads/MalTrace-LM/models/family_model)  

---

## 🛠️ Training Commands

```bash
# 1. Train TF-IDF Controlled Behavior Text Baseline:
python -m maltrace train data/samples --baseline tfidf --out-dir models/family_model --seed 42

# 2. Train Structured Feature Count Baseline:
python -m maltrace train data/samples --baseline structured --out-dir models/structured_model --seed 42

# 3. Train Majority Class Baseline:
python -m maltrace train data/samples --baseline majority --out-dir models/majority_model --seed 42

# 4. Evaluate Model Artifacts:
python -m maltrace evaluate data/samples --model-dir models/family_model

# 5. Run Model Inference on Single Trace:
python -m maltrace predict data/samples/ransomware_wannacry.json --model-dir models/family_model
```

---

## 📊 Dataset & Hash-Grouped Split Metadata

- **Total Samples**: 7 files scanned in `data/samples/`
- **Labeled Development Samples**: 6
- **Excluded Samples**: 1 (`example.json` excluded due to missing/unknown family label)
- **Random Seed**: 42
- **Split SHA-256 Hash**: `6861118ea3bb`
- **Split Protocol**: Deterministic hash-grouped stratified split (guaranteeing zero SHA-256 hash leakage across train and test splits).

---

## 📈 Measured Baseline Performance

> [!IMPORTANT]
> **Evaluation Disclaimer**: Results produced on synthetic development fixtures/subsets. Not general malware detection performance.

| Model Baseline | Feature Space | Classifier | Accuracy | Balanced Accuracy | Macro F1 | Weighted F1 |
|---|---|---|---|---|---|---|
| **Majority Class** | Label Frequencies | Constant Majority | 0.1667 | 0.1667 | 0.0476 | 0.0476 |
| **TF-IDF Text** | Behavior N-Grams | Logistic Regression | 0.1667 | 0.1667 | 0.0476 | 0.0476 |
| **Structured Count** | 12-D Event Counts | Logistic Regression | 0.1667 | 0.1667 | 0.0476 | 0.0476 |

---

## 💾 Saved Artifact File Paths

- `models/family_model/model.joblib`: Serialized Scikit-Learn vectorizer, scaler, and classifier pipeline.
- `models/family_model/config.json`: Hyperparameters, baseline name (`tfidf`), seed (`42`), split hash (`6861118ea3bb`), vocabulary version (`1.0.0`), and sample counts.
- `models/family_model/metrics.json`: Detailed accuracy, balanced accuracy, macro-F1, per-family metrics, and confusion matrix data.

---

## ⚠️ Limitations & Next Steps

1. **Small Development Subset Size**: The included development corpus consists of 6 distinct synthetic malware sample traces across 6 malware families.
2. **Probability Calibration**: Probability calibration (`CalibratedClassifierCV`) is fitted exclusively on held-out calibration splits to prevent overconfidence.
3. **Pipeline Fallback**: If `models/family_model/` artifacts are missing, `family_classifier.py` falls back to deterministic heuristic rules (`FALLBACK_HEURISTIC_RULES`).
