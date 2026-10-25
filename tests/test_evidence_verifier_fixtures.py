"""
Unit tests and fixture validation for Evidence Verifier, Support Matrix,
Contradiction Detection, Abstention Gate, and Audit Output.
"""

import pytest
from maltrace.contracts.schemas import (
    NormalizedEvent,
    BehaviorClaim,
    FamilyPrediction,
    TechniquePrediction,
    ProcessSummary
)
from maltrace.verification.evidence_index import EvidenceIndex
from maltrace.verification.validator import EvidenceVerifier, get_confidence_band_label


def make_event(sample_id="sample_A", event_id="evt_100", category="file", api_name="NtCreateFile", safe_args=None, order=1):
    return NormalizedEvent(
        sample_id=sample_id,
        event_id=event_id,
        event_order=order,
        process_id=1000,
        parent_process_id=500,
        api_name=api_name,
        category=category,
        safe_arguments=safe_args or {"file_path": "C:\\Users\\test\\doc.txt"},
        source_file="test.json"
    )


def test_missing_cited_events():
    events = [make_event(event_id="evt_100")]
    claims = [
        BehaviorClaim(
            claim_id="c1",
            description="Attempted volume shadow copy deletion",
            category="Ransomware/Impact",
            evidence_event_ids=["evt_9999"],  # Missing ID
            confidence=0.9
        )
    ]
    fam = FamilyPrediction(
        family_name="Ransomware.WannaCry",
        confidence=0.9,
        confidence_label="High",
        rule_triggered="RULE_RANSOM",
        supporting_evidence_ids=["evt_100"]
    )
    techs = []

    verifier = EvidenceVerifier()
    valid_claims, updated_fam, verified_techs, summary = verifier.verify(
        events=events,
        claims=claims,
        family_pred=fam,
        technique_preds=techs
    )

    assert len(valid_claims) == 0  # Missing claim removed from narrative conclusions
    assert summary.rejected_claims == 1
    assert "MISSING_EVENT_CITATION" in summary.rejected_claim_details[0]["rejection_reason"]


def test_cross_sample_citations():
    events_a = [make_event(sample_id="sample_A", event_id="evt_100")]
    events_b = [make_event(sample_id="sample_B", event_id="evt_200")]

    # Create index for sample_A but claim cites evt_200 (from sample_B)
    claims = [
        BehaviorClaim(
            claim_id="c1",
            description="Modified registry keys",
            category="Persistence/Registry",
            evidence_event_ids=["evt_200"],
            confidence=0.88
        )
    ]
    fam = FamilyPrediction(
        family_name="Trojan.AsyncRAT",
        confidence=0.85,
        confidence_label="High",
        rule_triggered="RULE_TROJAN",
        supporting_evidence_ids=["evt_100"]
    )

    verifier = EvidenceVerifier()
    valid_claims, updated_fam, verified_techs, summary = verifier.verify(
        events=events_a + events_b,
        claims=claims,
        family_pred=fam,
        technique_preds=[]
    )

    assert len(valid_claims) == 0
    assert summary.rejected_claims == 1
    assert "CROSS_SAMPLE_CITATION" in summary.rejected_claim_details[0]["rejection_reason"]


def test_contradictory_file_actions():
    # Evidence contains standard file open on normal file with no vssadmin/delete keywords
    events = [make_event(event_id="evt_100", api_name="NtOpenFile", safe_args={"file_path": "C:\\Windows\\notepad.exe"})]

    # Claim asserts shadow copy deletion
    claims = [
        BehaviorClaim(
            claim_id="c1",
            description="Attempted volume shadow copy deletion to prevent system recovery",
            category="Ransomware/Impact",
            evidence_event_ids=["evt_100"],
            confidence=0.95
        )
    ]
    fam = FamilyPrediction(
        family_name="Ransomware.WannaCry",
        confidence=0.9,
        confidence_label="High",
        rule_triggered="RULE_RANSOM",
        supporting_evidence_ids=["evt_100"]
    )

    verifier = EvidenceVerifier()
    valid_claims, updated_fam, verified_techs, summary = verifier.verify(
        events=events,
        claims=claims,
        family_pred=fam,
        technique_preds=[]
    )

    assert len(valid_claims) == 0
    assert summary.rejected_claims == 1
    assert summary.rejected_claim_details[0]["support_status"] == "contradictory"
    assert "CONTRADICTORY_EVIDENCE" in summary.rejected_claim_details[0]["rejection_reason"]


def test_too_short_trace_family_abstention():
    # Trace contains only 1 event (< min 3 usable events threshold)
    events = [make_event(event_id="evt_100")]
    claims = []
    fam = FamilyPrediction(
        family_name="Ransomware.WannaCry",
        confidence=0.9,
        confidence_label="High",
        rule_triggered="RULE_RANSOM",
        supporting_evidence_ids=["evt_100"]
    )

    verifier = EvidenceVerifier(min_usable_events=3)
    valid_claims, updated_fam, verified_techs, summary = verifier.verify(
        events=events,
        claims=claims,
        family_pred=fam,
        technique_preds=[]
    )

    assert summary.family_abstained is True
    assert updated_fam.family_name == "Abstained"
    assert summary.abstention_reason is not None
    assert "ABSTAINED_TOO_FEW_EVENTS" in summary.abstention_reason


def test_low_confidence_family_score_abstention():
    events = [
        make_event(event_id=f"evt_{i}", order=i) for i in range(1, 6)
    ]
    fam = FamilyPrediction(
        family_name="Dropper.Emotet",
        confidence=0.35,  # Low confidence (< 0.60 threshold)
        confidence_label="Low",
        rule_triggered="RULE_WEAK_SIGNAL",
        supporting_evidence_ids=["evt_1"]
    )

    verifier = EvidenceVerifier(min_family_confidence=0.60)
    valid_claims, updated_fam, verified_techs, summary = verifier.verify(
        events=events,
        claims=[],
        family_pred=fam,
        technique_preds=[]
    )

    assert summary.family_abstained is True
    assert updated_fam.family_name == "Abstained"
    assert summary.abstention_reason is not None
    assert "ABSTAINED_LOW_CLASSIFIER_CONFIDENCE" in summary.abstention_reason


def test_valid_technique_only_output_when_family_abstains():
    # 5 events present
    events = [make_event(event_id=f"evt_{i}", order=i) for i in range(1, 6)]

    # Low confidence family -> will abstain
    fam = FamilyPrediction(
        family_name="Trojan.AsyncRAT",
        confidence=0.30,
        confidence_label="Low",
        rule_triggered="WEAK_SIGNAL",
        supporting_evidence_ids=["evt_1"]
    )

    # Valid technique with valid evidence citation
    techs = [
        TechniquePrediction(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            confidence=0.90,
            confidence_label="High",
            supporting_evidence_ids=["evt_1"],
            matched_rules=["POWERSHELL_EXECUTION"],
            explanation="PowerShell interpreter execution observed."
        )
    ]

    verifier = EvidenceVerifier(min_family_confidence=0.60)
    valid_claims, updated_fam, verified_techs, summary = verifier.verify(
        events=events,
        claims=[],
        family_pred=fam,
        technique_preds=techs
    )

    # Family prediction abstains
    assert summary.family_abstained is True
    assert updated_fam.family_name == "Abstained"

    # BUT valid technique prediction is STILL returned!
    assert len(verified_techs) == 1
    assert verified_techs[0].technique_id == "T1059.001"
    assert verified_techs[0].supporting_evidence_ids == ["evt_1"]
    assert verified_techs[0].confidence_label == "High Confidence (Strong Evidence)"


def test_acceptance_gate_zero_unsupported_claims_reach_report():
    events = [make_event(event_id="evt_100")]
    claims = [
        BehaviorClaim(
            claim_id="c1",
            description="Fake claim with dangling event ID",
            category="CommandAndControl",
            evidence_event_ids=["evt_INVALID_999"],
            confidence=0.8
        )
    ]
    fam = FamilyPrediction(
        family_name="Benign.Activity",
        confidence=0.95,
        confidence_label="High",
        rule_triggered="RULE_BENIGN",
        supporting_evidence_ids=["evt_100"]
    )

    verifier = EvidenceVerifier()
    valid_claims, updated_fam, verified_techs, summary = verifier.verify(
        events=events,
        claims=claims,
        family_pred=fam,
        technique_preds=[]
    )

    # Acceptance gate check: claim with missing event reference NEVER reaches final output
    for c in valid_claims:
        for eid in c.evidence_event_ids:
            assert eid == "evt_100"
    assert len(valid_claims) == 0
