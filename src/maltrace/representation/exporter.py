"""
Representation exporters module.
Exports controlled behavior statements to JSONL (with direct event ID links) and human-readable text reports for debugging.
"""

import json
from pathlib import Path
from typing import List, Union

from maltrace.contracts.schemas import BehaviorStatement, TraceBehaviorSummary


def export_behavior_jsonl(
    statements: List[BehaviorStatement],
    output_file: Union[str, Path]
) -> Path:
    """
    Export behavior statements to JSONL format with direct event_id links.
    """
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        for stmt in statements:
            f.write(json.dumps(stmt.model_dump()) + "\n")

    return out_path


def export_behavior_text(
    trace_summary: TraceBehaviorSummary,
    output_file: Union[str, Path]
) -> Path:
    """
    Export a human-readable formatted text summary for analysts and debugging.
    """
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    lines.append("=" * 70)
    lines.append(f"MalTrace-LM Controlled Behavior Report - Sample: {trace_summary.sample_id}")
    lines.append("=" * 70)
    lines.append(f"Root Processes: {trace_summary.root_process_ids}")
    lines.append(f"Child Processes: {trace_summary.child_process_ids}")
    lines.append(f"Major Category Counts: {dict(trace_summary.major_categories)}")
    lines.append("-" * 70)

    lines.append("\n[SECURITY ANCHORS]")
    if trace_summary.security_anchors:
        for anchor in trace_summary.security_anchors:
            rules_str = ", ".join(anchor.anchor_rules)
            lines.append(f"  - [{anchor.event_id}] (PID {anchor.process_id}) ({rules_str}) {anchor.rendered_phrase}")
    else:
        lines.append("  (No security anchors triggered)")

    lines.append("\n[PROCESS BEHAVIOR SUMMARIES]")
    for proc in trace_summary.process_summaries:
        lines.append(f"\n--- Process: {proc.process_name} (PID {proc.process_id}) ---")
        lines.append(f"  Lineage Path: {proc.readable_path}")
        lines.append(f"  Parent Relationship: {proc.parent_relationship}")
        lines.append(f"  Event Category Counts: {proc.event_counts}")
        if proc.high_value_actions:
            lines.append(f"  High-Value Actions: {proc.high_value_actions}")
        lines.append("  Behavior Statements:")
        for s in proc.behavior_statements:
            anchor_tag = f" [{', '.join(s.anchor_rules)}]" if s.anchor_rules else ""
            lines.append(f"    * [{s.event_id} | Order {s.event_order}]{anchor_tag} {s.rendered_phrase}")

    lines.append("\n" + "=" * 70)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return out_path
