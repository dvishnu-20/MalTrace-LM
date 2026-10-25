import pytest
from pydantic import ValidationError
from maltrace.contracts.schemas import (
    RawEvent,
    NormalizedEvent,
    ProcessSummary,
    BehaviorClaim,
    FamilyPrediction,
    TechniquePrediction,
    AnalysisResult,
    RunManifest
)


def test_raw_event_schema_validation():
    evt = RawEvent(
        sample_id="s1",
        event_id="e1",
        event_order=1,
        process_id=100,
        api_name="NtCreateFile",
        arguments={"path": "C:\\test.txt"}
    )
    assert evt.sample_id == "s1"
    assert evt.schema_version == "1.0.0"

    with pytest.raises(ValidationError):
        # Missing required field api_name
        raw_kwargs = {"sample_id": "s1", "event_id": "e1", "event_order": 1, "process_id": 100}
        RawEvent(**raw_kwargs)


def test_behavior_claim_schema():
    claim = BehaviorClaim(
        claim_id="c1",
        description="Shadow copy deletion",
        category="Impact",
        evidence_event_ids=["e1", "e2"],
        confidence=0.95
    )
    assert claim.claim_id == "c1"
    assert len(claim.evidence_event_ids) == 2


def test_family_prediction_schema():
    pred = FamilyPrediction(
        family_name="Ransomware.WannaCry",
        confidence=0.92,
        confidence_label="High",
        rule_triggered="RULE_RANSOM",
        supporting_evidence_ids=["e1"]
    )
    assert pred.family_name == "Ransomware.WannaCry"
