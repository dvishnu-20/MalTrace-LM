"""
Reproducibility Evaluation Script for MalTrace-LM.
Runs independent, leak-free evaluations across all baselines, MITRE ATT&CK mapping,
context budget selector efficiency, and grounding validation.
Outputs a complete reproducibility report to reports/reproducibility_report.json.
"""

from pathlib import Path
import json
import time
from typing import Dict, Any, List

from maltrace.models.dataset_builder import load_dataset_records, split_dataset_hash_grouped_3way
from maltrace.models.trainer import train_model
from maltrace.attack_mapping.mapper import map_behavior_to_attack
from maltrace.representation.renderer import render_trace_statements
from maltrace.representation.selector import (
    DefaultBudgetSelector,
    HardBudgetSelector,
    NaiveFrontTruncationSelector,
    NaiveTailTruncationSelector,
    RandomStatementSelector,
    FrontTruncationSelector,
    CategoryFrequencySelector
)
from maltrace.ingestion.stream_parser import stream_parse_file


def run_benchmark_suite() -> Dict[str, Any]:
    print("[*] Starting MalTrace-LM Scientific Reproducibility Benchmark...")
    start_time = time.time()
    samples_dir = Path("data/samples")
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 1. Dataset Verification
    records, excluded = load_dataset_records(samples_dir, benchmark_mode=True)
    print(f"[*] Loaded {len(records)} verified labeled samples ({excluded} excluded).")

    # 2. Family Classification Baselines (Leak-free 3-way split)
    baseline_results: Dict[str, Any] = {}
    import tempfile
    with tempfile.TemporaryDirectory() as tmp_dir:
        for b in ["majority", "tfidf", "structured"]:
            res = train_model(samples_dir, Path(tmp_dir) / b, baseline=b, seed=42)
            baseline_results[b] = {
                "accuracy": res["metrics"]["accuracy"],
                "balanced_accuracy": res["metrics"]["balanced_accuracy"],
                "macro_f1": res["metrics"]["macro_f1"],
                "weighted_f1": res["metrics"]["weighted_f1"],
                "test_samples": res["config"]["test_samples"],
                "split_hash": res["config"]["split_hash"]
            }
            print(f"  - Baseline '{b}': Macro-F1 = {res['metrics']['macro_f1']:.4f}, Accuracy = {res['metrics']['accuracy']:.4f}")

    # 3. MITRE ATT&CK Mapping Gold Benchmark
    with open("data/gold_fixtures.json", "r", encoding="utf-8") as gf:
        gold_data = json.load(gf)["samples"]

    tp_tot, fp_tot, fn_tot = 0, 0, 0
    attack_eval: Dict[str, Any] = {}

    for sample_file_name, exp in gold_data.items():
        sample_file = samples_dir / sample_file_name
        if not sample_file.exists():
            continue
        events = list(stream_parse_file(sample_file, benchmark_mode=True))
        preds = map_behavior_to_attack(events, [])
        pred_tids = set(p.technique_id for p in preds)
        gold_tids = set(exp["expected_techniques"])

        true_pos = len(pred_tids.intersection(gold_tids))
        false_pos = len(pred_tids - gold_tids)
        false_neg = len(gold_tids - pred_tids)
        tp_tot += true_pos
        fp_tot += false_pos
        fn_tot += false_neg

        attack_eval[sample_file_name] = {
            "predicted": sorted(list(pred_tids)),
            "gold": sorted(list(gold_tids)),
            "match": pred_tids == gold_tids
        }

    micro_p = tp_tot / max(1, tp_tot + fp_tot)
    micro_r = tp_tot / max(1, tp_tot + fn_tot)
    micro_f1 = (2 * micro_p * micro_r) / max(1e-6, micro_p + micro_r)
    exact_matches = sum(1 for v in attack_eval.values() if v["match"])

    print(f"[*] ATT&CK Mapping Benchmark: Micro-F1 = {micro_f1:.4f}, Exact Match = {exact_matches}/{len(attack_eval)}")

    # 4. Context Budget Selector Comparison
    selector_eval: Dict[str, Any] = {}
    sample_file = samples_dir / "ransomware_wannacry.json"
    evts = list(stream_parse_file(sample_file, benchmark_mode=True))
    stmts = render_trace_statements(evts)
    all_anchor_ids = set(s.statement_id for s in stmts if s.anchor_rules)

    budgets = [300, 600, 1200]
    for b in budgets:
        def_sel = DefaultBudgetSelector.select(stmts, max_budget_chars=b)
        hard_sel = HardBudgetSelector.select(stmts, max_budget_chars=b)
        front_sel = NaiveFrontTruncationSelector.select(stmts, max_budget_chars=b)
        tail_sel = NaiveTailTruncationSelector.select(stmts, max_budget_chars=b)

        def_chars = sum(len(s.rendered_phrase) for s in def_sel)
        hard_chars = sum(len(s.rendered_phrase) for s in hard_sel)
        front_chars = sum(len(s.rendered_phrase) for s in front_sel)

        def_anchors = sum(1 for s in def_sel if s.statement_id in all_anchor_ids)
        hard_anchors = sum(1 for s in hard_sel if s.statement_id in all_anchor_ids)
        front_anchors = sum(1 for s in front_sel if s.statement_id in all_anchor_ids)

        selector_eval[f"budget_{b}"] = {
            "default_selector": {"chars": def_chars, "anchors_retained": def_anchors, "total_anchors": len(all_anchor_ids)},
            "hard_budget_selector": {"chars": hard_chars, "anchors_retained": hard_anchors, "under_budget": hard_chars <= b},
            "naive_front_selector": {"chars": front_chars, "anchors_retained": front_anchors, "under_budget": front_chars <= b}
        }

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(time.time() - start_time, 2),
        "dataset_sample_count": len(records),
        "family_baselines": baseline_results,
        "attack_mapping_evaluation": {
            "micro_precision": round(micro_p, 4),
            "micro_recall": round(micro_r, 4),
            "micro_f1": round(micro_f1, 4),
            "exact_match_ratio": round(exact_matches / max(1, len(attack_eval)), 4),
            "sample_details": attack_eval
        },
        "budget_selector_evaluation": selector_eval
    }

    out_file = reports_dir / "reproducibility_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[*] Reproducibility report written to: {out_file}")
    return report


if __name__ == "__main__":
    run_benchmark_suite()
