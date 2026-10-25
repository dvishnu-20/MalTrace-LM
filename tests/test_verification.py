import pytest
from maltrace.contracts.schemas import (
    NormalizedEvent,
    BehaviorClaim,
    FamilyPrediction,
    TechniquePrediction
)
from maltrace.verification.validator import verify_evidence_references, EvidenceVerificationError


def test_verification_valid_ids():
    events = [
        NormalizedEvent(
            sample_id="s1",
            event_id="evt_100",
            event_order=1,
            process_id=1000,
            api_name="NtCreateFile",
            category="file",
            safe_arguments={},
            source_file="test.json"
        )
    ]
    claims = [
        BehaviorClaim(
            claim_id="c1",
            description="File access",
            category="File",
            evidence_event_ids=["evt_100"],
            confidence=1.0
        )
    ]
    fam = FamilyPrediction(
        family_name="Benign",
        confidence=0.9,
        confidence_label="High",
        rule_triggered="RULE_BENIGN",
        supporting_evidence_ids=["evt_100"]
    )
    techs = [
        TechniquePrediction(
            technique_id="T1005",
            technique_name="Data from Local System",
            tactic="Collection",
            confidence=0.5,
            supporting_evidence_ids=["evt_100"]
        )
    ]

    res = verify_evidence_references(events, claims, fam, techs)
    assert res["status"] == "VALIDATED"


def test_verification_dangling_evidence_id_raises_error():
    events = [
        NormalizedEvent(
            sample_id="s1",
            event_id="evt_100",
            event_order=1,
            process_id=1000,
            api_name="NtCreateFile",
            category="file",
            safe_arguments={},
            source_file="test.json"
        )
    ]
    # Claim cites evt_999 which does not exist in events
    claims = [
        BehaviorClaim(
            claim_id="c1",
            description="Shadow copy delete",
            category="Impact",
            evidence_event_ids=["evt_999"],
            confidence=1.0
        )
    ]
    fam = FamilyPrediction(
        family_name="Benign",
        confidence=0.9,
        confidence_label="High",
        rule_triggered="RULE_BENIGN",
        supporting_evidence_ids=["evt_100"]
    )
    techs = []

    with pytest.raises(EvidenceVerificationError) as exc_info:
        verify_evidence_references(events, claims, fam, techs)

    assert "evt_999" in str(exc_info.value)
