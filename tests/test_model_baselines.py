import json
import tempfile
from pathlib import Path
import pytest

from maltrace.contracts.schemas import NormalizedEvent, FamilyPrediction
from maltrace.models.dataset_builder import load_dataset_records, split_dataset_hash_grouped, TraceSampleRecord
from maltrace.models.feature_extractor import extract_text_features, extract_structured_features, extract_single_structured_vector
from maltrace.models.baselines import MajorityClassBaseline, TfidfBehaviorClassifier, StructuredCountClassifier
from maltrace.models.trainer import train_model, load_trained_model, predict_events_with_model
from maltrace.models.family_classifier import classify_malware_family
from maltrace.reporting.generator import analyze_trace


def test_dataset_builder_unknown_label_exclusion():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_p = Path(tmp_dir)
        f1 = tmp_p / "labeled.json"
        f2 = tmp_p / "unlabeled.json"

        with open(f1, "w", encoding="utf-8") as f:
            json.dump({"sample_id": "s1", "family": "Ransomware.WannaCry", "events": [{"event_id": "e1", "process_id": 1, "api_name": "WriteFile"}]}, f)
        with open(f2, "w", encoding="utf-8") as f:
            json.dump({"sample_id": "s2", "family": "unknown", "events": [{"event_id": "e2", "process_id": 2, "api_name": "WriteFile"}]}, f)

        records, excluded = load_dataset_records(tmp_p)

        assert len(records) == 1
        assert records[0].label == "Ransomware.WannaCry"
        assert excluded == 1


def test_split_determinism_and_no_hash_leakage():
    records = [
        TraceSampleRecord(sample_id="s1", source_path="p1", sha256="hash_A", label="FamA", events=[], statements=[]),
        TraceSampleRecord(sample_id="s2", source_path="p2", sha256="hash_A", label="FamA", events=[], statements=[]),
        TraceSampleRecord(sample_id="s3", source_path="p3", sha256="hash_B", label="FamB", events=[], statements=[]),
        TraceSampleRecord(sample_id="s4", source_path="p4", sha256="hash_C", label="FamA", events=[], statements=[]),
        TraceSampleRecord(sample_id="s5", source_path="p5", sha256="hash_D", label="FamB", events=[], statements=[]),
    ]

    train1, test1, hash1 = split_dataset_hash_grouped(records, test_ratio=0.3, seed=42)
    train2, test2, hash2 = split_dataset_hash_grouped(records, test_ratio=0.3, seed=42)

    assert hash1 == hash2
    assert [r.sample_id for r in train1] == [r.sample_id for r in train2]

    # Verify ZERO hash leakage: train and test hashes are completely disjoint
    train_hashes = set(r.sha256 for r in train1)
    test_hashes = set(r.sha256 for r in test1)
    assert train_hashes.isdisjoint(test_hashes)


def test_empty_text_and_single_event_handling():
    evt = NormalizedEvent(
        sample_id="s_empty", event_id="e1", event_order=1, process_id=100, parent_process_id=0,
        api_name="NtCreateFile", category="file", safe_arguments={}, source_file="empty.json"
    )
    rec = TraceSampleRecord(sample_id="s_empty", source_path="empty.json", sha256="h", label="Benign", events=[evt], statements=[])

    texts = extract_text_features([rec])
    assert len(texts) == 1
    assert "NtCreateFile" in texts[0] or "empty_trace" in texts[0]

    vec = extract_single_structured_vector([evt])
    assert vec.shape == (12,)


def test_artifact_reload_equivalence():
    with tempfile.TemporaryDirectory() as tmp_dir:
        samples_dir = Path("data/samples")
        model_dir = Path(tmp_dir) / "test_model"

        # Train model baseline
        res = train_model(samples_dir, model_dir, baseline="tfidf", seed=42)

        assert (model_dir / "model.joblib").exists()
        assert (model_dir / "config.json").exists()
        assert (model_dir / "metrics.json").exists()

        # Reload model
        model, config = load_trained_model(model_dir)
        assert config["baseline"] == "tfidf"

        events = [
            NormalizedEvent(
                sample_id="s", event_id="e1", event_order=1, process_id=4120, parent_process_id=0,
                api_name="CreateProcessInternalW", category="process",
                safe_arguments={"image_name": "vssadmin.exe", "command_line": "vssadmin.exe Delete Shadows /All"}, source_file="f"
            )
        ]

        pred1 = predict_events_with_model(events, model_dir)
        pred2 = predict_events_with_model(events, model_dir)

        assert pred1.family_name == pred2.family_name
        assert pred1.confidence == pred2.confidence
        assert pred1.top_class_probabilities == pred2.top_class_probabilities


def test_acceptance_gate_train_two_baselines_and_pipeline_integration():
    samples_dir = Path("data/samples")
    assert samples_dir.exists()

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_dir_tfidf = Path(tmp_dir) / "tfidf_model"
        model_dir_struct = Path(tmp_dir) / "structured_model"

        # 1. Train Baseline 1: TF-IDF
        res_tfidf = train_model(samples_dir, model_dir_tfidf, baseline="tfidf", seed=42)
        assert res_tfidf["metrics"]["sample_count"] > 0

        # 2. Train Baseline 2: Structured Count
        res_struct = train_model(samples_dir, model_dir_struct, baseline="structured", seed=42)
        assert res_struct["metrics"]["sample_count"] > 0

        # 3. Test Integration into analyze_trace pipeline using classifier adapter
        # Set MODEL_DIR environment variable to model_dir_tfidf
        import os
        orig_env = os.environ.get("MODEL_DIR")
        try:
            os.environ["MODEL_DIR"] = str(model_dir_tfidf)
            analysis_res = analyze_trace(samples_dir / "ransomware_wannacry.json")
            fam_pred = analysis_res.family_prediction

            assert fam_pred.family_name is not None
            assert fam_pred.confidence >= 0.0
            assert "MODEL_TFIDF_PREDICTION" in fam_pred.rule_triggered
        finally:
            if orig_env:
                os.environ["MODEL_DIR"] = orig_env
            else:
                os.environ.pop("MODEL_DIR", None)
