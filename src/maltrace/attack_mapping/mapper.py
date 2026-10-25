"""
ATT&CK Mapping Engine.
Transparent, evidence-linked mapper mapping normalized events and controlled behavior statements
to a versioned catalog of MITRE ATT&CK techniques.
"""

from typing import List, Dict, Set, Optional
from maltrace.contracts.schemas import NormalizedEvent, BehaviorClaim, TechniquePrediction, BehaviorStatement
from maltrace.attack_mapping.catalog import load_technique_catalog, evaluate_technique_against_trace
from maltrace.representation.renderer import render_trace_statements


def map_behavior_to_attack(
    events: List[NormalizedEvent],
    claims: List[BehaviorClaim],
    statements: Optional[List[BehaviorStatement]] = None
) -> List[TechniquePrediction]:
    """
    Map trace events and behavior statements to ATT&CK technique predictions.
    Guarantees every returned technique has >= 1 valid supporting event ID and matched rules.
    """
    if statements is None:
        statements = render_trace_statements(events)

    catalog = load_technique_catalog()
    predictions: List[TechniquePrediction] = []
    seen_tids: Set[str] = set()

    for tech_def in catalog:
        pred = evaluate_technique_against_trace(tech_def, events, statements)
        if pred and pred.supporting_evidence_ids and pred.technique_id not in seen_tids:
            predictions.append(pred)
            seen_tids.add(pred.technique_id)

    return predictions
