"""
Feature extractor module.
Extracts text features (controlled behavior statements) and structured numerical feature vectors
(event category counts, process count, network count, persistence flags, security anchor counts).
"""

from typing import List, Dict, Any
import numpy as np

from maltrace.contracts.schemas import NormalizedEvent
from maltrace.models.dataset_builder import TraceSampleRecord

FEATURE_NAMES = [
    "count_category_file",
    "count_category_process",
    "count_category_registry",
    "count_category_network",
    "count_category_service",
    "count_category_memory",
    "count_category_synchronization",
    "count_category_other",
    "process_count",
    "network_count",
    "persistence_count",
    "anchor_count"
]


def extract_text_features(records: List[TraceSampleRecord]) -> List[str]:
    """
    Extract controlled behavior statement text strings for TF-IDF vectorization.
    """
    texts: List[str] = []
    for r in records:
        if r.behavior_text and r.behavior_text.strip():
            texts.append(r.behavior_text)
        else:
            # Fallback to API names if behavior text is empty
            apis = [e.api_name for e in r.events]
            texts.append(" ".join(apis) if apis else "empty_trace")
    return texts


def extract_single_structured_vector(events: List[NormalizedEvent]) -> np.ndarray:
    """
    Extract a 12-dimensional structured numerical feature vector from normalized events of a single trace.
    """
    cat_counts: Dict[str, int] = {
        "file": 0,
        "process": 0,
        "registry": 0,
        "network": 0,
        "service": 0,
        "memory": 0,
        "synchronization": 0,
        "other": 0
    }
    pids = set()
    net_count = 0
    pers_count = 0
    anchor_count = 0

    for e in events:
        cat_counts[e.category] = cat_counts.get(e.category, 0) + 1
        pids.add(e.process_id)
        if e.category == "network":
            net_count += 1
        if e.is_persistence:
            pers_count += 1

    # Check anchor triggers
    from maltrace.representation.anchors import evaluate_security_anchors
    for e in events:
        rules = evaluate_security_anchors(e)
        if rules:
            anchor_count += len(rules)

    vec = np.array([
        cat_counts["file"],
        cat_counts["process"],
        cat_counts["registry"],
        cat_counts["network"],
        cat_counts["service"],
        cat_counts["memory"],
        cat_counts["synchronization"],
        cat_counts["other"],
        len(pids),
        net_count,
        pers_count,
        anchor_count
    ], dtype=np.float64)

    return vec


def extract_structured_features(records: List[TraceSampleRecord]) -> np.ndarray:
    """
    Extract structured numerical matrix X from a list of trace records.
    """
    if not records:
        return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float64)

    matrix = [extract_single_structured_vector(r.events) for r in records]
    return np.vstack(matrix)
