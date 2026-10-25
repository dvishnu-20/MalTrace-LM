"""
Trainer and evaluation orchestrator module.
Trains model baselines, computes evaluation metrics, and persists serialized model artifacts and metadata configs.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union
import joblib
import numpy as np

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
    precision_recall_fscore_support,
    confusion_matrix,
)

from maltrace.contracts.schemas import FamilyPrediction, NormalizedEvent
from maltrace.models.dataset_builder import load_dataset_records, split_dataset_hash_grouped, split_dataset_hash_grouped_3way, TraceSampleRecord
from maltrace.models.feature_extractor import extract_text_features, extract_structured_features, extract_single_structured_vector
from maltrace.models.baselines import MajorityClassBaseline, TfidfBehaviorClassifier, StructuredCountClassifier
from maltrace.representation.renderer import render_trace_statements

DISCLAIMER_TEXT = "Results produced on synthetic development fixtures/subsets. Not general malware detection performance."


def compute_metrics(
    y_true: List[str],
    y_pred: List[str],
    classes: List[str]
) -> Dict[str, Any]:
    """
    Compute comprehensive evaluation metrics: accuracy, balanced accuracy, macro-F1, weighted-F1, per-family P/R/F1, and confusion matrix.
    """
    if not y_true or not y_pred:
        return {
            "accuracy": 0.0,
            "balanced_accuracy": 0.0,
            "macro_f1": 0.0,
            "weighted_f1": 0.0,
            "per_family": {},
            "confusion_matrix": [],
            "sample_count": 0,
            "disclaimer": DISCLAIMER_TEXT
        }

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    zero_div: Any = 0
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=zero_div))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=zero_div))

    all_unique_labels = sorted(list(set(y_true + y_pred)))
    prs_result: Any = precision_recall_fscore_support(y_true, y_pred, labels=all_unique_labels, zero_division=zero_div)
    p: Any = prs_result[0]
    r: Any = prs_result[1]
    f: Any = prs_result[2]
    s: Any = prs_result[3]

    per_family = {}
    for idx, lbl in enumerate(all_unique_labels):
        per_family[lbl] = {
            "precision": float(p[idx]),
            "recall": float(r[idx]),
            "f1": float(f[idx]),
            "support": int(s[idx]) if s is not None else 0
        }

    cm = confusion_matrix(y_true, y_pred, labels=all_unique_labels)

    return {
        "accuracy": acc,
        "balanced_accuracy": bal_acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "per_family": per_family,
        "labels_order": all_unique_labels,
        "confusion_matrix": cm.tolist(),
        "sample_count": len(y_true),
        "disclaimer": DISCLAIMER_TEXT
    }


def train_model(
    input_path: Union[str, Path],
    output_model_dir: Union[str, Path],
    baseline: str = "tfidf",
    seed: int = 42,
    balanced_subset: bool = False
) -> Dict[str, Any]:
    """
    Train a model baseline on trace dataset and save artifacts to output_model_dir.
    """
    out_dir = Path(output_model_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records, excluded_count = load_dataset_records(input_path)
    if not records:
        raise ValueError(f"No labeled trace records found in {input_path}")

    train_recs, val_recs, test_recs, split_hash = split_dataset_hash_grouped_3way(
        records, test_ratio=0.25, val_ratio=0.20, seed=seed, balanced_subset=balanced_subset
    )
    if not test_recs:
        train_recs, test_recs, split_hash = split_dataset_hash_grouped(
            records, test_ratio=0.3, seed=seed, balanced_subset=balanced_subset
        )
        val_recs = []

    baseline_clean = baseline.lower().strip()
    train_labels: List[str] = [str(r.label) for r in train_recs if r.label is not None]
    val_labels: Optional[List[str]] = [str(r.label) for r in val_recs if r.label is not None] if val_recs else None

    if baseline_clean == "majority":
        model = MajorityClassBaseline()
        model.fit(train_recs, train_labels)
        y_test_pred = model.predict(test_recs)

    elif baseline_clean == "tfidf":
        model = TfidfBehaviorClassifier(seed=seed)
        train_texts = extract_text_features(train_recs)

        # Use held-out validation split for calibration to strictly prevent test leakage
        val_texts = extract_text_features(val_recs) if val_recs else None

        model.fit(train_texts, train_labels, calib_texts=val_texts, calib_y=val_labels)
        test_texts = extract_text_features(test_recs)
        y_test_pred = model.predict(test_texts)

    elif baseline_clean == "structured":
        model = StructuredCountClassifier(seed=seed)
        X_train = extract_structured_features(train_recs)

        X_val = extract_structured_features(val_recs) if val_recs else None

        model.fit(X_train, train_labels, calib_X=X_val, calib_y=val_labels)
        X_test = extract_structured_features(test_recs)
        y_test_pred = model.predict(X_test)

    else:
        raise ValueError(f"Unknown baseline: '{baseline}'. Expected 'majority', 'tfidf', or 'structured'.")

    # Evaluate independently on held-out test set
    y_test_true: List[str] = [str(r.label) for r in test_recs if r.label is not None]
    metrics = compute_metrics(y_test_true, y_test_pred, list(model.classes_))
    metrics["excluded_unknown_labels_count"] = excluded_count

    config = {
        "baseline": baseline_clean,
        "vocabulary_version": "1.0.0",
        "maltrace_version": "0.1.0",
        "seed": seed,
        "split_hash": split_hash,
        "training_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_samples": len(records),
        "train_samples": len(train_recs),
        "test_samples": len(test_recs),
        "excluded_unknown_samples": excluded_count,
        "classes": list(model.classes_),
        "disclaimer": DISCLAIMER_TEXT
    }

    # Save artifacts
    model_artifact_path = out_dir / "model.joblib"
    config_path = out_dir / "config.json"
    metrics_path = out_dir / "metrics.json"

    joblib.dump(model, model_artifact_path)

    with open(config_path, "w", encoding="utf-8") as cf:
        json.dump(config, cf, indent=2)

    with open(metrics_path, "w", encoding="utf-8") as mf:
        json.dump(metrics, mf, indent=2)

    return {"config": config, "metrics": metrics, "model_dir": str(out_dir)}


def load_trained_model(model_dir: Union[str, Path]) -> Tuple[Any, Dict[str, Any]]:
    """
    Load saved model artifact and config metadata from model_dir.
    """
    md_path = Path(model_dir)
    model_artifact = md_path / "model.joblib"
    config_artifact = md_path / "config.json"

    if not model_artifact.exists() or not config_artifact.exists():
        raise FileNotFoundError(f"Trained model artifacts missing in {md_path}")

    model = joblib.load(model_artifact)
    with open(config_artifact, "r", encoding="utf-8") as cf:
        config = json.load(cf)

    return model, config


def predict_events_with_model(
    events: List[NormalizedEvent],
    model_dir: Union[str, Path]
) -> FamilyPrediction:
    """
    Predict malware family using a trained model artifact directory.
    """
    model, config = load_trained_model(model_dir)
    baseline_type = config.get("baseline", "tfidf")

    statements = render_trace_statements(events)
    behavior_text = " ".join([s.rendered_phrase for s in statements])

    if baseline_type == "tfidf":
        preds = model.predict([behavior_text])
        probas = model.predict_proba([behavior_text])[0]
    elif baseline_type == "structured":
        vec = extract_single_structured_vector(events).reshape(1, -1)
        preds = model.predict(vec)
        probas = model.predict_proba(vec)[0]
    else:  # majority or default
        preds = model.predict([behavior_text])
        probas = model.predict_proba([behavior_text])[0]

    predicted_family = preds[0]
    classes = list(model.classes_)
    class_proba_map = {classes[i]: float(probas[i]) for i in range(len(classes))}

    top_confidence = class_proba_map.get(predicted_family, 1.0)
    conf_label = "High" if top_confidence >= 0.8 else ("Medium" if top_confidence >= 0.5 else "Low")

    # Find evidence IDs
    supporting_eids = [e.event_id for e in events if e.is_persistence or e.category in ("network", "process", "service")]
    if not supporting_eids and events:
        supporting_eids = [events[0].event_id]

    return FamilyPrediction(
        family_name=predicted_family,
        confidence=round(top_confidence, 4),
        confidence_label=conf_label,
        rule_triggered=f"MODEL_{baseline_type.upper()}_PREDICTION",
        supporting_evidence_ids=supporting_eids[:10],
        top_class_probabilities=class_proba_map,
        model_version=f"{baseline_type}_v1.0.0"
    )
