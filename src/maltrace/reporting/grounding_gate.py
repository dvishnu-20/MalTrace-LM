"""
Grounding and Evidence Validation Gate.
Strictly validates LLM responses against verified analysis facts.
If any cited event ID is missing, category unsupported, or technique ID unmapped,
the LLM response is DISCARDED completely and the deterministic template report is returned safely.
"""

import re
import json
from typing import Dict, Any, List, Tuple, Optional, Set

from maltrace.contracts.schemas import (
    AnalysisResult,
    AnalystReport,
    LLMReportRequest,
    LLMReportResponse,
    RunManifest
)
from maltrace.reporting.report_generator import generate_deterministic_analyst_report
from maltrace.reporting.llm_provider import BaseLLMProvider, DisabledLLMProvider

TECHNIQUE_ID_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def validate_llm_response(
    response: LLMReportResponse,
    result: AnalysisResult
) -> Tuple[bool, List[str]]:
    """
    Validate LLM response against result facts.
    Returns (is_valid, list_of_warning_messages).
    """
    warnings: List[str] = []

    if response is None:
        return False, ["LLM response object is None or malformed."]

    # Valid event IDs in analysis result
    valid_eids: Set[str] = {ev.event_id for ev in result.cited_evidence}

    # Valid technique IDs in analysis result
    valid_tids: Set[str] = {t.technique_id for t in result.technique_predictions}

    # 1. Event ID Linkage Check
    if not response.cited_event_ids:
        warnings.append("LLM response cited zero event IDs.")

    for eid in response.cited_event_ids:
        if eid not in valid_eids:
            warnings.append(f"Grounding failure: LLM cited hallucinated/missing event_id '{eid}'.")

    # 2. Technique ID Alignment Check
    full_llm_text = f"{response.summary} {' '.join(response.behavior_claims)} {response.analyst_notes}"
    mentioned_tids = set(TECHNIQUE_ID_REGEX.findall(full_llm_text))

    for tid in mentioned_tids:
        if tid not in valid_tids:
            warnings.append(f"Grounding failure: LLM mentioned unmapped technique_id '{tid}'.")

    is_valid = len(warnings) == 0
    return is_valid, warnings


def build_analyst_report(
    result: AnalysisResult,
    llm_provider: Optional[BaseLLMProvider] = None
) -> AnalystReport:
    """
    Build AnalystReport with strict grounding validation and safe deterministic fallback.
    """
    det_report = generate_deterministic_analyst_report(result)
    manifest = result.manifest or RunManifest(
        run_id="run_det", timestamp="2026-07-28T00:00:00Z", input_file=result.sample_id, execution_time_ms=0.0
    )

    if llm_provider is None or isinstance(llm_provider, DisabledLLMProvider) or llm_provider.provider_name == "disabled":
        manifest.llm_provider = "disabled"
        manifest.validation_status = "disabled"
        det_report.manifest = manifest
        return det_report

    # Prepare privacy-safe LLM request
    controlled_phrases = []
    for proc in result.process_summaries:
        controlled_phrases.append({
            "process_name": proc.process_name,
            "readable_path": proc.readable_path,
            "categories": proc.categories_observed
        })

    attack_facts = [
        {"technique_id": t.technique_id, "name": t.technique_name, "tactic": t.tactic}
        for t in result.technique_predictions
    ]

    llm_request = LLMReportRequest(
        sample_id=result.sample_id,
        predicted_family=result.family_prediction.family_name,
        confidence=result.family_prediction.confidence,
        confidence_label=result.family_prediction.confidence_label,
        rule_triggered=result.family_prediction.rule_triggered,
        behavior_categories=result.trace_summary.get("categories_found", []),
        attack_techniques=attack_facts,
        process_summaries=controlled_phrases,
        controlled_phrases=controlled_phrases,
        cited_event_ids=[ev.event_id for ev in result.cited_evidence]
    )

    try:
        response, metadata = llm_provider.generate_summary(llm_request)
        is_valid, warnings = validate_llm_response(response, result)

        manifest.llm_provider = metadata.get("provider", llm_provider.provider_name)
        manifest.llm_model = metadata.get("model", llm_provider.model_name)
        manifest.temperature = metadata.get("temperature", 0.0)
        manifest.response_hash = metadata.get("response_hash")
        manifest.validation_warnings = warnings

        if is_valid:
            manifest.validation_status = "passed"
            det_report.generation_mode = "llm"
            det_report.executive_summary = f"{response.summary} (LLM Enhanced)"
            if response.analyst_notes:
                det_report.analyst_recommendations.insert(0, response.analyst_notes)
            det_report.manifest = manifest
            return det_report
        else:
            manifest.validation_status = "failed"
            det_report.manifest = manifest
            return det_report

    except Exception as err:
        manifest.llm_provider = llm_provider.provider_name
        manifest.llm_model = getattr(llm_provider, "model_name", "none")
        manifest.validation_status = "failed"
        manifest.validation_warnings = [f"LLM execution error: {err}"]
        det_report.manifest = manifest
        return det_report
