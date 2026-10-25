"""
Multi-Trace Differential Analysis Engine.
Compares two execution traces to identify shared behavioral infrastructure,
API distribution shifts, process lineage mutations, and ATT&CK technique overlaps.
"""

from pathlib import Path
from typing import Dict, Any, List, Set, Union, Optional
from collections import Counter
from pydantic import BaseModel, Field

from maltrace.ingestion.loader import load_trace_file
from maltrace.representation.normalizer import normalize_trace_events
from maltrace.features.process_tree import build_process_tree
from maltrace.attack_mapping.mapper import map_behavior_to_attack


class TraceDiffResult(BaseModel):
    sample_a_id: str
    sample_b_id: str
    behavioral_similarity_score: float
    total_events_a: int
    total_events_b: int
    category_distribution_a: Dict[str, int]
    category_distribution_b: Dict[str, int]
    shared_attack_techniques: List[str]
    unique_techniques_a: List[str]
    unique_techniques_b: List[str]
    process_names_a: List[str]
    process_names_b: List[str]
    shared_processes: List[str]
    unique_processes_a: List[str]
    unique_processes_b: List[str]
    unique_network_destinations_a: List[str]
    unique_network_destinations_b: List[str]
    summary: str


def compute_trace_diff(
    trace_a_path: Union[str, Path],
    trace_b_path: Union[str, Path]
) -> TraceDiffResult:
    """
    Perform a comprehensive differential comparison between two trace files.
    """
    raw_a = load_trace_file(Path(trace_a_path))
    raw_b = load_trace_file(Path(trace_b_path))

    norm_a = normalize_trace_events(raw_a.events)
    norm_b = normalize_trace_events(raw_b.events)

    preds_a = map_behavior_to_attack(norm_a, [])
    preds_b = map_behavior_to_attack(norm_b, [])

    tids_a = set(p.technique_id for p in preds_a)
    tids_b = set(p.technique_id for p in preds_b)

    shared_tids = sorted(list(tids_a.intersection(tids_b)))
    unique_tids_a = sorted(list(tids_a - tids_b))
    unique_tids_b = sorted(list(tids_b - tids_a))

    cats_a = Counter(e.category for e in norm_a)
    cats_b = Counter(e.category for e in norm_b)

    # Process extraction
    tree_a, _ = build_process_tree(norm_a)
    tree_b, _ = build_process_tree(norm_b)

    procs_a = set(p.process_name for p in tree_a.values() if p.process_name)
    procs_b = set(p.process_name for p in tree_b.values() if p.process_name)

    shared_procs = sorted(list(procs_a.intersection(procs_b)))
    unique_procs_a = sorted(list(procs_a - procs_b))
    unique_procs_b = sorted(list(procs_b - procs_a))

    # Network destinations
    nets_a: Set[str] = set()
    for e in norm_a:
        if e.category == "network":
            dest = str(e.safe_arguments.get("remote_address", "") or e.safe_arguments.get("target_path", "")).strip()
            if dest:
                nets_a.add(dest)

    nets_b: Set[str] = set()
    for e in norm_b:
        if e.category == "network":
            dest = str(e.safe_arguments.get("remote_address", "") or e.safe_arguments.get("target_path", "")).strip()
            if dest:
                nets_b.add(dest)

    # Compute Jaccard behavioral similarity score across categories, APIs, and techniques
    apis_a = set(e.api_name for e in norm_a)
    apis_b = set(e.api_name for e in norm_b)

    jaccard_apis = len(apis_a.intersection(apis_b)) / max(1, len(apis_a.union(apis_b)))
    jaccard_tids = len(tids_a.intersection(tids_b)) / max(1, len(tids_a.union(tids_b))) if (tids_a or tids_b) else 1.0
    jaccard_procs = len(procs_a.intersection(procs_b)) / max(1, len(procs_a.union(procs_b))) if (procs_a or procs_b) else 1.0

    similarity_score = round(0.4 * jaccard_apis + 0.4 * jaccard_tids + 0.2 * jaccard_procs, 3)

    summary = (
        f"Differential Analysis between '{raw_a.sample_id}' and '{raw_b.sample_id}': "
        f"Behavioral similarity is {similarity_score * 100:.1f}%. "
        f"Shared ATT&CK techniques: [{', '.join(shared_tids) or 'None'}]. "
        f"Shared processes: [{', '.join(shared_procs) or 'None'}]."
    )

    return TraceDiffResult(
        sample_a_id=raw_a.sample_id,
        sample_b_id=raw_b.sample_id,
        behavioral_similarity_score=similarity_score,
        total_events_a=len(norm_a),
        total_events_b=len(norm_b),
        category_distribution_a=dict(cats_a),
        category_distribution_b=dict(cats_b),
        shared_attack_techniques=shared_tids,
        unique_techniques_a=unique_tids_a,
        unique_techniques_b=unique_tids_b,
        process_names_a=sorted(list(procs_a)),
        process_names_b=sorted(list(procs_b)),
        shared_processes=shared_procs,
        unique_processes_a=unique_procs_a,
        unique_processes_b=unique_procs_b,
        unique_network_destinations_a=sorted(list(nets_a)),
        unique_network_destinations_b=sorted(list(nets_b)),
        summary=summary
    )
