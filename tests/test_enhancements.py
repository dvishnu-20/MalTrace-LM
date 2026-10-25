import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from maltrace.contracts.schemas import NormalizedEvent, BehaviorClaim, AnalysisResult, ProcessSummary
from maltrace.models.family_classifier import classify_malware_family
from maltrace.attack_mapping.catalog import load_technique_catalog, evaluate_technique_against_trace
from maltrace.attack_mapping.stix_sync import parse_stix_bundle, sync_catalog_from_stix
from maltrace.attack_mapping.navigator import generate_navigator_layer, export_navigator_layer_file
from maltrace.detection.sigma_matcher import BehavioralSigmaEngine, SigmaRule
from maltrace.features.trace_diff import compute_trace_diff
from maltrace.models.anomaly import BehavioralAnomalyDetector
from maltrace.reporting.llm_provider import GeminiLLMProvider, AnthropicLLMProvider
from maltrace.api.app import app
from maltrace.ingestion.loader import load_trace_file
from maltrace.representation.normalizer import normalize_trace_events
from maltrace.reporting.generator import analyze_trace


def test_expanded_malware_families_heuristics():
    # 1. LockBit Ransomware
    raw_lb = load_trace_file(Path("data/samples/ransomware_lockbit.json"))
    norm_lb = normalize_trace_events(raw_lb.events)
    pred_lb = classify_malware_family(norm_lb, [])
    assert pred_lb.family_name == "Ransomware.LockBit"
    assert pred_lb.confidence >= 0.85
    assert len(pred_lb.supporting_evidence_ids) >= 1

    # 2. AgentTesla Infostealer
    raw_at = load_trace_file(Path("data/samples/infostealer_agenttesla.json"))
    norm_at = normalize_trace_events(raw_at.events)
    pred_at = classify_malware_family(norm_at, [])
    assert pred_at.family_name == "Stealer.AgentTesla"
    assert pred_at.confidence >= 0.85

    # 3. Qakbot Loader
    raw_qb = load_trace_file(Path("data/samples/loader_qakbot.json"))
    norm_qb = normalize_trace_events(raw_qb.events)
    pred_qb = classify_malware_family(norm_qb, [])
    assert pred_qb.family_name == "Loader.Qakbot"
    assert pred_qb.confidence >= 0.85

    # 4. HermeticWiper
    raw_wp = load_trace_file(Path("data/samples/wiper_hermetic.json"))
    norm_wp = normalize_trace_events(raw_wp.events)
    pred_wp = classify_malware_family(norm_wp, [])
    assert pred_wp.family_name == "Wiper.HermeticWiper"
    assert pred_wp.confidence >= 0.85


def test_expanded_attack_catalog_scope():
    catalog = load_technique_catalog()
    # Ensure catalog has over 35 techniques
    assert len(catalog) >= 35
    tids = [t.technique_id for t in catalog]

    # Verify key modern techniques
    assert "T1059.005" in tids  # VBScript
    assert "T1106" in tids      # Native API
    assert "T1218.010" in tids  # Regsvr32
    assert "T1056.001" in tids  # Keylogging
    assert "T1490" in tids      # Inhibit Recovery
    assert "T1485" in tids      # Data Destruction
    assert "T1048" in tids      # Exfiltration over Alternative Protocol


def test_stix_2_1_synchronization(tmp_path):
    mock_stix_bundle = {
        "type": "bundle",
        "id": "bundle--mock-attack-01",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--001",
                "name": "Exploitation for Privilege Escalation",
                "description": "Adversaries may exploit software vulnerabilities in an elevated context.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1068"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "privilege-escalation"
                    }
                ]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--002",
                "name": "Deprecated Technique",
                "x_mitre_deprecated": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]
            }
        ]
    }

    parsed = parse_stix_bundle(mock_stix_bundle)
    assert len(parsed) == 1
    assert parsed[0]["technique_id"] == "T1068"
    assert parsed[0]["tactic"] == "Privilege Escalation"

    # Test sync into a temporary catalog file
    out_catalog = tmp_path / "synced_catalog.json"
    total = sync_catalog_from_stix(mock_stix_bundle, output_catalog_path=out_catalog, merge_with_existing=True)
    assert total >= 1

    with open(out_catalog, "r", encoding="utf-8") as f:
        data = json.load(f)
    saved_tids = [t["technique_id"] for t in data["techniques"]]
    assert "T1068" in saved_tids


def test_attack_navigator_export(tmp_path):
    raw = load_trace_file(Path("data/samples/ransomware_wannacry.json"))
    result = analyze_trace(input_file=Path("data/samples/ransomware_wannacry.json"))

    layer = generate_navigator_layer(result)
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) >= 1

    out_file = tmp_path / "layer.json"
    export_navigator_layer_file(result, output_path=out_file)
    assert out_file.exists()


def test_behavioral_sigma_engine():
    engine = BehavioralSigmaEngine()
    assert len(engine.rules) >= 5

    # Test against LockBit ransomware sample
    raw = load_trace_file(Path("data/samples/ransomware_lockbit.json"))
    norm = normalize_trace_events(raw.events)
    matches = engine.evaluate_trace(norm)

    matched_rule_ids = [m.rule_id for m in matches]
    assert "SIGMA-001" in matched_rule_ids  # vssadmin shadow copy deletion
    assert "SIGMA-002" in matched_rule_ids  # bcdedit recovery disable


def test_multi_trace_differential_engine():
    diff_res = compute_trace_diff(
        trace_a_path="data/samples/ransomware_wannacry.json",
        trace_b_path="data/samples/ransomware_lockbit.json"
    )

    assert diff_res.sample_a_id == "ransomware_wannacry_01"
    assert diff_res.sample_b_id == "ransomware_lockbit_01"
    assert diff_res.behavioral_similarity_score > 0.0
    assert "T1486" in diff_res.shared_attack_techniques  # Data Encrypted for Impact
    assert len(diff_res.summary) > 10


def test_behavioral_anomaly_detector():
    detector = BehavioralAnomalyDetector()

    # Normal trace should have lower anomaly score
    raw_benign = load_trace_file(Path("data/samples/benign_notepad.json"))
    norm_benign = normalize_trace_events(raw_benign.events)
    res_benign = detector.evaluate_trace(norm_benign)
    assert res_benign["anomaly_score"] <= 0.60

    # Destructive / injection trace should have higher score or divergence factors
    raw_wiper = load_trace_file(Path("data/samples/wiper_hermetic.json"))
    norm_wiper = normalize_trace_events(raw_wiper.events)
    res_wiper = detector.evaluate_trace(norm_wiper)
    assert isinstance(res_wiper["divergence_factors"], list)


def test_api_security_and_new_endpoints():
    client = TestClient(app)

    # 1. Health and version
    r = client.get("/health")
    assert r.status_code == 200
    r_ver = client.get("/version")
    assert r_ver.status_code == 200
    assert r_ver.json()["maltrace_version"] == "0.1.0"

    # 2. Upload and analyze LockBit
    with open("data/samples/ransomware_lockbit.json", "rb") as f:
        r_up = client.post("/analyze", files={"file": ("ransomware_lockbit.json", f, "application/json")})
    assert r_up.status_code == 201
    ana_data = r_up.json()
    ana_id = ana_data["analysis_id"]

    # 3. Navigator layer endpoint
    r_nav = client.get(f"/analyses/{ana_id}/navigator")
    assert r_nav.status_code == 200
    assert r_nav.json()["domain"] == "enterprise-attack"

    # 4. Diff endpoint
    with open("data/samples/ransomware_wannacry.json", "rb") as f1, open("data/samples/ransomware_lockbit.json", "rb") as f2:
        r_diff = client.post(
            "/diff",
            files={
                "file_a": ("trace_a.json", f1, "application/json"),
                "file_b": ("trace_b.json", f2, "application/json")
            }
        )
    assert r_diff.status_code == 200
    diff_json = r_diff.json()
    assert "behavioral_similarity_score" in diff_json


def test_new_llm_provider_classes():
    gemini = GeminiLLMProvider(api_key="test_key_gemini")
    assert gemini.provider_name == "google-gemini"
    assert gemini.model_name == "gemini-1.5-flash"

    claude = AnthropicLLMProvider(api_key="test_key_claude")
    assert claude.provider_name == "anthropic-claude"
    assert claude.model_name == "claude-3-5-sonnet-20241022"
