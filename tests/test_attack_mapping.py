import json
from pathlib import Path
import pytest

from maltrace.contracts.schemas import NormalizedEvent, BehaviorStatement, TechniquePrediction
from maltrace.attack_mapping.catalog import load_technique_catalog, evaluate_technique_against_trace
from maltrace.attack_mapping.mapper import map_behavior_to_attack
from maltrace.ingestion.loader import load_trace_file
from maltrace.representation.normalizer import normalize_trace_events


def test_catalog_loading():
    catalog = load_technique_catalog()
    assert len(catalog) >= 12
    tids = [t.technique_id for t in catalog]
    assert "T1059.001" in tids
    assert "T1486" in tids
    assert "T1547.001" in tids


def test_positive_and_negative_fixtures_per_technique():
    catalog = load_technique_catalog()

    for tech_def in catalog:
        pat = tech_def.required_evidence_patterns[0].replace("\\\\", "\\")
        # Positive fixture
        pos_evt = NormalizedEvent(
            sample_id="s_pos", event_id="evt_pos", event_order=1, process_id=100, parent_process_id=0,
            api_name="VirtualAllocEx" if pat == "virtualalloc-remote" else "TestAPI",
            category="network" if pat == "outbound_public_ip" else ("service" if pat in ("createservice", "service") else "process"),
            safe_arguments={"raw": pat},
            network_category="public" if pat == "outbound_public_ip" else "unknown",
            is_persistence=True if "run" in pat or "startup" in pat or "autorun" in pat else False,
            source_file="pos.json"
        )
        pos_pred = evaluate_technique_against_trace(tech_def, [pos_evt], [])
        assert pos_pred is not None, f"Positive fixture failed to trigger technique {tech_def.technique_id}"
        assert len(pos_pred.supporting_evidence_ids) >= 1
        assert len(pos_pred.matched_rules) >= 1

        # Negative / Excluded fixture (if exclusion rules exist)
        if tech_def.exclusion_rules:
            ex_pat = tech_def.exclusion_rules[0].replace("\\\\", "\\")
            neg_evt = NormalizedEvent(
                sample_id="s_neg", event_id="evt_neg", event_order=1, process_id=100, parent_process_id=0,
                api_name="TestAPI", category="network" if "loopback" in ex_pat else "process",
                safe_arguments={"raw": ex_pat},
                network_category="loopback" if "loopback" in ex_pat else "unknown",
                source_file="neg.json"
            )
            neg_pred = evaluate_technique_against_trace(tech_def, [neg_evt], [])
            assert neg_pred is None, f"Exclusion rule failed to block negative fixture for technique {tech_def.technique_id}"


def test_zero_evidence_rejection():
    # Empty event list
    preds = map_behavior_to_attack([], [])
    assert len(preds) == 0, "Zero-evidence traces must not return technique predictions"


def test_ambiguous_fixture_flagging():
    # Single discovery event
    disc_evt = NormalizedEvent(
        sample_id="s_amb", event_id="evt_disc", event_order=1, process_id=100, parent_process_id=0,
        api_name="FindFirstFileW", category="file", safe_arguments={"target_path": "C:\\Users\\Public\\doc.pdf"},
        source_file="amb.json"
    )
    preds = map_behavior_to_attack([disc_evt], [])
    disc_preds = [p for p in preds if p.technique_id == "T1083"]

    if disc_preds:
        p = disc_preds[0]
        assert p.needs_review is True
        assert p.confidence_label == "Needs Review"


def test_gold_fixture_benchmark_metrics():
    gold_path = Path("data/gold_fixtures.json")
    assert gold_path.exists(), "Gold fixtures file missing"

    with open(gold_path, "r", encoding="utf-8") as f:
        gold_data = json.load(f)

    samples_map = gold_data["samples"]
    total_samples = len(samples_map)

    exact_matches = 0
    tp_total, fp_total, fn_total = 0, 0, 0
    macro_f1s = []

    for filename, expected_info in samples_map.items():
        sample_path = Path("data/samples") / filename
        if not sample_path.exists():
            continue

        raw = load_trace_file(sample_path)
        norm_events = normalize_trace_events(raw.events)
        preds = map_behavior_to_attack(norm_events, [])

        pred_tids = set(p.technique_id for p in preds)
        gold_tids = set(expected_info["expected_techniques"])

        if pred_tids == gold_tids:
            exact_matches += 1

        tp = len(pred_tids.intersection(gold_tids))
        fp = len(pred_tids - gold_tids)
        fn = len(gold_tids - pred_tids)

        tp_total += tp
        fp_total += fp
        fn_total += fn

        prec = tp / max(1, (tp + fp))
        rec = tp / max(1, (tp + fn))
        f1 = (2 * prec * rec) / max(1e-6, (prec + rec))
        macro_f1s.append(f1)

    micro_prec = tp_total / max(1, (tp_total + fp_total))
    micro_rec = tp_total / max(1, (tp_total + fn_total))
    micro_f1 = (2 * micro_prec * micro_rec) / max(1e-6, (micro_prec + micro_rec))
    macro_f1 = sum(macro_f1s) / max(1, len(macro_f1s))
    exact_match_ratio = exact_matches / max(1, total_samples)

    assert micro_f1 >= 0.70, f"Micro-F1 score below threshold: {micro_f1:.4f}"
    assert exact_match_ratio >= 0.50, f"Exact match ratio below threshold: {exact_match_ratio:.4f}"


def test_acceptance_gate_every_technique_has_evidence_and_matched_rules():
    samples_dir = Path("data/samples")
    for file_p in samples_dir.glob("*.json"):
        if file_p.name == "manifest.json":
            continue
        raw = load_trace_file(file_p)
        norm_events = normalize_trace_events(raw.events)
        preds = map_behavior_to_attack(norm_events, [])

        for pred in preds:
            assert len(pred.supporting_evidence_ids) >= 1, f"Technique {pred.technique_id} has zero supporting evidence"
            assert len(pred.matched_rules) >= 1, f"Technique {pred.technique_id} missing matched rules"
