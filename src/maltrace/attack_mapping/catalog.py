"""
ATT&CK Technique Catalog Loader and Rule Engine.
Loads catalog v1.0.0, matches events and controlled statements, enforces evidence-linking,
applies exclusion rules, and tags ambiguous matches with needs_review.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set, Optional
from pydantic import BaseModel

from maltrace.contracts.schemas import NormalizedEvent, BehaviorStatement, TechniquePrediction


class TechniqueDefinition(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    required_evidence_patterns: List[str]
    optional_supporting_patterns: List[str] = []
    exclusion_rules: List[str] = []
    base_confidence: float = 0.85


def load_technique_catalog(catalog_file: Optional[Path] = None) -> List[TechniqueDefinition]:
    """
    Load versioned ATT&CK technique catalog JSON file.
    """
    if catalog_file is None:
        catalog_file = Path(__file__).parent / "catalog.json"

    with open(catalog_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    return [TechniqueDefinition(**item) for item in data.get("techniques", [])]


def evaluate_technique_against_trace(
    tech_def: TechniqueDefinition,
    events: List[NormalizedEvent],
    statements: List[BehaviorStatement]
) -> Optional[TechniquePrediction]:
    """
    Evaluate a single technique definition against trace events and statements.
    Returns TechniquePrediction if evidence exists and not excluded, else None.
    """
    matched_event_ids: Set[str] = set()
    matched_rule_names: Set[str] = set()

    stmt_by_eid = {s.event_id: s for s in statements}

    for e in events:
        args_str = json.dumps(e.safe_arguments).lower()
        api_lower = e.api_name.lower()
        cat_lower = e.category.lower()
        stmt = stmt_by_eid.get(e.event_id)
        phrase_lower = stmt.rendered_phrase.lower() if stmt else ""

        full_text = f"{api_lower} {cat_lower} {args_str} {phrase_lower}".replace("\\\\", "\\")

        # 1. Check exclusions
        excluded_for_this_event = False
        for ex in tech_def.exclusion_rules:
            ex_lower = ex.lower().replace("\\\\", "\\")
            if ex_lower in full_text or (e.network_category == "loopback" and ex_lower in ("loopback", "private_network")):
                excluded_for_this_event = True
                break

        if excluded_for_this_event:
            continue

        # 2. Check required evidence patterns
        for req in tech_def.required_evidence_patterns:
            req_lower = req.lower().replace("\\\\", "\\")
            pattern_matched = False

            if req_lower in full_text:
                pattern_matched = True
            elif req_lower == "outbound_public_ip" and e.category == "network" and e.network_category != "loopback":
                pattern_matched = True

            elif req_lower in ("currentversion\\run", "currentversion\\runonce", "startup", "autorun") and (e.is_persistence or "run" in args_str):
                pattern_matched = True
            elif req_lower == "virtualalloc-remote" and api_lower in ("virtualallocex", "writeprocessmemory", "createremotethread"):
                pattern_matched = True
            elif req_lower in ("createservice", "service") and (e.category == "service" or "createservice" in api_lower):
                pattern_matched = True

            if pattern_matched:
                matched_event_ids.add(e.event_id)
                matched_rule_names.add(f"PATTERN:{req}")

        # 3. Check optional supporting patterns
        for opt in tech_def.optional_supporting_patterns:
            opt_lower = opt.lower().replace("\\\\", "\\")
            if opt_lower in full_text:
                matched_rule_names.add(f"OPTIONAL:{opt}")

    # ZERO EVIDENCE RULE: Technique predictions with 0 supporting event IDs MUST NEVER BE RETURNED!
    if not matched_event_ids:
        return None

    conf = tech_def.base_confidence
    needs_review = False
    conf_label = "High"

    if tech_def.technique_id in ("T1083", "T1082", "T1560") and len(matched_event_ids) == 1:
        needs_review = True
        conf = 0.55
        conf_label = "Needs Review"
    elif conf >= 0.8:
        conf_label = "High"
    elif conf >= 0.5:
        conf_label = "Medium"
    else:
        conf_label = "Low"

    explanation = (
        f"Technique {tech_def.technique_id} ({tech_def.technique_name}) identified with {len(matched_event_ids)} "
        f"supporting evidence event(s) matching rules: {', '.join(sorted(list(matched_rule_names)))}."
    )

    return TechniquePrediction(
        technique_id=tech_def.technique_id,
        technique_name=tech_def.technique_name,
        tactic=tech_def.tactic,
        confidence=round(conf, 2),
        confidence_label=conf_label,
        supporting_evidence_ids=sorted(list(matched_event_ids)),
        matched_rules=sorted(list(matched_rule_names)),
        explanation=explanation,
        needs_review=needs_review
    )
