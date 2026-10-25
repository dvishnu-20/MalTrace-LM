"""
Process-aware behavior grouping and trace summarization.
Groups behavior statements per process in execution order and builds trace-level summaries.
"""

from typing import List, Dict, Set, Tuple
from collections import defaultdict

from maltrace.contracts.schemas import (
    NormalizedEvent,
    BehaviorStatement,
    ProcessBehaviorSummary,
    TraceBehaviorSummary,
)
from maltrace.features.process_tree import build_process_tree


def build_process_behavior_summaries(
    events: List[NormalizedEvent],
    statements: List[BehaviorStatement]
) -> List[ProcessBehaviorSummary]:
    """
    Produce process-level behavior summaries in execution order with lineage, event counts, high-value actions, and behavior phrases.
    """
    tree_nodes, _ = build_process_tree(events)

    # Group statements by process_id
    proc_stmts: Dict[int, List[BehaviorStatement]] = defaultdict(list)
    proc_events: Dict[int, List[NormalizedEvent]] = defaultdict(list)

    for stmt in statements:
        proc_stmts[stmt.process_id].append(stmt)
    for evt in events:
        proc_events[evt.process_id].append(evt)

    summaries: List[ProcessBehaviorSummary] = []

    for pid in sorted(tree_nodes.keys()):
        node = tree_nodes[pid]
        p_stmts = proc_stmts.get(pid, [])
        p_evts = proc_events.get(pid, [])

        # Calculate category event counts
        cat_counts: Dict[str, int] = defaultdict(int)
        for e in p_evts:
            cat_counts[e.category] += 1

        # Extract high-value actions (anchor rule names + high/critical severity phrases)
        high_value: List[str] = []
        for s in p_stmts:
            for rule in s.anchor_rules:
                if rule not in high_value:
                    high_value.append(rule)
            if s.severity in ("high", "critical") and s.rendered_phrase not in high_value:
                high_value.append(s.rendered_phrase[:100])

        # Formulate parent relationship string
        if node.is_root or node.parent_process_id == 0:
            parent_rel = "Root Process (No Parent)"
        else:
            parent_name = tree_nodes[node.parent_process_id].process_name if node.parent_process_id in tree_nodes else f"PID_{node.parent_process_id}"
            parent_rel = f"Child of {parent_name} (PID {node.parent_process_id})"

        summaries.append(
            ProcessBehaviorSummary(
                process_id=pid,
                process_name=node.process_name,
                parent_process_id=node.parent_process_id,
                readable_path=node.readable_path,
                parent_relationship=parent_rel,
                event_counts=dict(cat_counts),
                high_value_actions=high_value,
                behavior_statements=p_stmts
            )
        )

    return summaries


def build_trace_behavior_summary(
    events: List[NormalizedEvent],
    statements: List[BehaviorStatement]
) -> TraceBehaviorSummary:
    """
    Produce trace-level behavior summary containing roots, child processes, major categories, security anchors, and top behavior statements.
    """
    tree_nodes, _ = build_process_tree(events)
    proc_summaries = build_process_behavior_summaries(events, statements)

    sample_id = events[0].sample_id if events else "unknown_sample"

    roots = [node.process_id for node in tree_nodes.values() if node.is_root]
    children = [node.process_id for node in tree_nodes.values() if not node.is_root]

    # Major category counts
    major_cats: Dict[str, int] = defaultdict(int)
    for e in events:
        major_cats[e.category] += 1

    # Security anchors (statements with triggered anchor rules)
    anchors = [s for s in statements if s.anchor_rules]

    # Top behavior statements (high/critical severity or anchors)
    top_stmts = [s for s in statements if s.severity in ("high", "critical") or s.anchor_rules]
    if not top_stmts:
        top_stmts = statements[:10]

    return TraceBehaviorSummary(
        sample_id=sample_id,
        root_process_ids=roots,
        child_process_ids=children,
        major_categories=dict(major_cats),
        security_anchors=anchors,
        top_behavior_statements=top_stmts,
        process_summaries=proc_summaries
    )
