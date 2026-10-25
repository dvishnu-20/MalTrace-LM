"""
Evidence Verifier module.
Provides EvidenceVerifier to validate citations, check support matrix, detect contradictions,
compute confidence bands, decide family abstention, and produce verification summaries.
"""

from typing import List, Set, Dict, Any, Tuple, Optional
from maltrace.contracts.schemas import (
    NormalizedEvent,
    BehaviorClaim,
    FamilyPrediction,
    TechniquePrediction,
    AnalysisResult,
    VerificationSummary,
    ProcessSummary,
    RunManifest
)
from maltrace.verification.evidence_index import EvidenceIndex
from maltrace.verification.support_matrix import evaluate_claim_support


class EvidenceVerificationError(ValueError):
    """Raised when an evidence ID cited in claims or predictions does not exist in the trace events."""
    pass


def get_confidence_band_label(confidence: float, is_abstained: bool = False) -> str:
    """
    Convert numerical confidence into human-readable confidence band without forensic certainty.
    """
    if is_abstained or confidence < 0.40:
        return "Abstained (Insufficient Confidence)"
    elif confidence >= 0.85:
        return "High Confidence (Strong Evidence)"
    elif confidence >= 0.60:
        return "Moderate Confidence (Probable)"
    else:
        return "Low Confidence (Tentative)"


class EvidenceVerifier:
    """
    Evidence Verifier module placed between prediction engine and analyst report generator.
    Validates references via EvidenceIndex, enforces Claim Support Matrix, filters unsupported claims,
    evaluates human-readable confidence bands, and decides family abstention while preserving valid techniques.
    """
    def __init__(
        self,
        min_family_confidence: float = 0.60,
        min_usable_events: int = 1,
        min_citation_completeness: float = 0.50
    ):
        self.min_family_confidence = min_family_confidence
        self.min_usable_events = min_usable_events
        self.min_citation_completeness = min_citation_completeness

    def verify(
        self,
        events: List[NormalizedEvent],
        claims: List[BehaviorClaim],
        family_pred: FamilyPrediction,
        technique_preds: List[TechniquePrediction],
        process_summaries: Optional[List[ProcessSummary]] = None,
        manifest: Optional[RunManifest] = None
    ) -> Tuple[List[BehaviorClaim], FamilyPrediction, List[TechniquePrediction], VerificationSummary]:

        index = EvidenceIndex(events, process_summaries=process_summaries)
        sample_id = events[0].sample_id if events else (
            family_pred.supporting_evidence_ids[0] if family_pred.supporting_evidence_ids else "unknown"
        )

        supported_claims: List[BehaviorClaim] = []
        rejected_claim_details: List[Dict[str, Any]] = []

        supported_count = 0
        partially_supported_count = 0
        rejected_count = 0

        total_cited_ids = 0
        valid_cited_ids = 0

        # 1. Verify Behavior Claims
        for claim in claims:
            total_cited_ids += len(claim.evidence_event_ids)
            status, valid_eids, reason = evaluate_claim_support(claim, index, sample_id)
            valid_cited_ids += len(valid_eids)

            if status in ("supported", "partially_supported"):
                if status == "supported":
                    supported_count += 1
                else:
                    partially_supported_count += 1

                # Retain claim with updated valid evidence IDs
                updated_claim = claim.model_copy(update={"evidence_event_ids": valid_eids})
                supported_claims.append(updated_claim)
            else:
                rejected_count += 1
                rejected_claim_details.append({
                    "claim_id": claim.claim_id,
                    "description": claim.description,
                    "category": claim.category,
                    "support_status": status,
                    "rejection_reason": reason or "Unsupported claim",
                    "cited_evidence_ids": claim.evidence_event_ids
                })

        # 2. Verify Technique Predictions
        verified_techniques: List[TechniquePrediction] = []
        for tech in technique_preds:
            total_cited_ids += len(tech.supporting_evidence_ids)
            valid_tech_eids: List[str] = []
            for eid in tech.supporting_evidence_ids:
                ref_status = index.validate_reference(eid, target_sample_id=sample_id)
                if ref_status == "VALID":
                    valid_tech_eids.append(eid)
                    valid_cited_ids += 1

            if valid_tech_eids:
                band_label = get_confidence_band_label(tech.confidence)
                updated_tech = tech.model_copy(update={
                    "supporting_evidence_ids": valid_tech_eids,
                    "confidence_label": band_label
                })
                verified_techniques.append(updated_tech)

        # 3. Verify Family Prediction & Evaluate Abstention Criteria
        total_cited_ids += len(family_pred.supporting_evidence_ids)
        valid_fam_eids: List[str] = []
        for eid in family_pred.supporting_evidence_ids:
            ref_status = index.validate_reference(eid, target_sample_id=sample_id)
            if ref_status == "VALID":
                valid_fam_eids.append(eid)
                valid_cited_ids += 1

        citation_completeness = (valid_cited_ids / total_cited_ids) if total_cited_ids > 0 else 1.0

        abstention_reasons: List[str] = []

        if len(events) < self.min_usable_events:
            abstention_reasons.append(
                f"ABSTAINED_TOO_FEW_EVENTS: Trace contains {len(events)} usable event(s) (minimum required: {self.min_usable_events})."
            )

        if family_pred.confidence < self.min_family_confidence:
            abstention_reasons.append(
                f"ABSTAINED_LOW_CLASSIFIER_CONFIDENCE: Family classifier confidence ({family_pred.confidence:.2f}) is below threshold ({self.min_family_confidence:.2f})."
            )

        if manifest and any("critical" in w.lower() or "failed" in w.lower() or "truncated" in w.lower() for w in getattr(manifest, "validation_warnings", [])):
            abstention_reasons.append(
                "ABSTAINED_CRITICAL_PARSING_WARNINGS: Parsing manifest contains critical warnings."
            )

        if citation_completeness < self.min_citation_completeness:
            abstention_reasons.append(
                f"ABSTAINED_INSUFFICIENT_EVIDENCE_COVERAGE: Citation completeness ({citation_completeness:.2f}) is below threshold ({self.min_citation_completeness:.2f})."
            )

        if len(claims) > 0 and supported_count == 0 and partially_supported_count == 0:
            abstention_reasons.append(
                "ABSTAINED_INSUFFICIENT_EVIDENCE_COVERAGE: Zero supported claims remain after evidence verification."
            )

        family_abstained = len(abstention_reasons) > 0
        final_abstention_reason = " | ".join(abstention_reasons) if family_abstained else None

        if family_abstained:
            band_label = get_confidence_band_label(family_pred.confidence, is_abstained=True)
            updated_family = family_pred.model_copy(update={
                "family_name": "Abstained",
                "confidence_label": band_label,
                "rule_triggered": f"ABSTAINED: {final_abstention_reason}",
                "supporting_evidence_ids": valid_fam_eids
            })
        else:
            band_label = get_confidence_band_label(family_pred.confidence)
            updated_family = family_pred.model_copy(update={
                "confidence_label": band_label,
                "supporting_evidence_ids": valid_fam_eids
            })

        summary = VerificationSummary(
            total_claims=len(claims),
            supported_claims=supported_count,
            partially_supported_claims=partially_supported_count,
            rejected_claims=rejected_count,
            citation_completeness=round(citation_completeness, 4),
            family_abstained=family_abstained,
            abstention_reason=final_abstention_reason,
            rejected_claim_details=rejected_claim_details
        )

        return supported_claims, updated_family, verified_techniques, summary


def verify_evidence_references(
    events: List[NormalizedEvent],
    claims: List[BehaviorClaim],
    family_pred: FamilyPrediction,
    technique_preds: List[TechniquePrediction],
    strict: bool = True
) -> Dict[str, Any]:
    """
    Legacy verification helper function maintained for backward compatibility.
    Checks dangling event IDs and raises EvidenceVerificationError if strict=True.
    """
    valid_ids: Set[str] = {evt.event_id for evt in events}
    missing_references: List[Dict[str, Any]] = []

    for claim in claims:
        for eid in claim.evidence_event_ids:
            if eid not in valid_ids:
                missing_references.append({
                    "source": f"BehaviorClaim({claim.claim_id})",
                    "missing_event_id": eid
                })

    for eid in family_pred.supporting_evidence_ids:
        if eid not in valid_ids:
            missing_references.append({
                "source": f"FamilyPrediction({family_pred.family_name})",
                "missing_event_id": eid
            })

    for tech in technique_preds:
        for eid in tech.supporting_evidence_ids:
            if eid not in valid_ids:
                missing_references.append({
                    "source": f"TechniquePrediction({tech.technique_id})",
                    "missing_event_id": eid
                })

    if missing_references and strict:
        missing_ids = [m["missing_event_id"] for m in missing_references]
        raise EvidenceVerificationError(
            f"Evidence verification failed: {len(missing_references)} cited event ID(s) do not exist in trace: {missing_ids}"
        )

    return {
        "status": "VALIDATED" if not missing_references else "WARNINGS",
        "total_events_checked": len(valid_ids),
        "total_claims_verified": len(claims),
        "total_techniques_verified": len(technique_preds),
        "dangling_evidence_ids": [m["missing_event_id"] for m in missing_references]
    }


def verify_analysis_result(result: AnalysisResult, events: List[NormalizedEvent]) -> bool:
    """
    Convenience checker for complete AnalysisResult objects.
    """
    verify_evidence_references(
        events=events,
        claims=result.behavior_claims,
        family_pred=result.family_prediction,
        technique_preds=result.technique_predictions,
        strict=True
    )
    return True
