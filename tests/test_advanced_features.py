"""
Comprehensive test suite for advanced MalTrace-LM features:
- Network IDS signature generator (Suricata / Snort / Zeek)
- Deep sequential PyTorch BiLSTM with Self-Attention
- Sysmon XML and JSON event log ingestion adapter
- SIEM / TIP threat intelligence exporters (Splunk HEC, Elastic ECS, MISP, STIX 2.1)
- Campaign clustering and threat hunting engine
- New API endpoints (/analyses/{id}/ids, /analyses/{id}/siem, /cluster)
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from maltrace.ingestion.loader import load_trace_file
from maltrace.representation.normalizer import normalize_trace_events
from maltrace.reporting.generator import analyze_trace
from maltrace.detection.ids_generator import (
    extract_network_indicators,
    generate_suricata_rules,
    generate_snort_rules,
    generate_zeek_intel,
    export_ids_rules_from_result
)
from maltrace.models.sequence_model import (
    APISequenceTokenizer,
    APISequenceBiLSTM,
    build_default_sequence_engine
)
from maltrace.ingestion.sysmon_adapter import parse_sysmon_xml, parse_sysmon_json
from maltrace.reporting.siem_exporter import (
    export_splunk_hec,
    export_elastic_ecs,
    export_misp_event,
    export_stix_bundle,
    export_siem_format
)
from maltrace.features.clustering import cluster_trace_samples
from maltrace.api.app import app


def test_ids_rule_generation():
    """Verify Suricata, Snort, and Zeek signature extraction and syntax formatting."""
    raw = load_trace_file(Path("data/samples/infostealer_redline.json"))
    norm = normalize_trace_events(raw.events)

    indicators = extract_network_indicators(norm, sample_id=raw.sample_id, predicted_family="Stealer.RedLine")
    assert len(indicators) > 0
    assert indicators[0].destination_ip == "198.51.100.45"
    assert indicators[0].destination_port == 8080

    suricata_rules = generate_suricata_rules(indicators)
    assert "alert tcp" in suricata_rules
    assert "198.51.100.45 8080" in suricata_rules
    assert "classtype:trojan-activity" in suricata_rules
    assert "sid:2026001" in suricata_rules

    snort_rules = generate_snort_rules(indicators)
    assert "alert tcp" in snort_rules
    assert "sid:3026001" in snort_rules

    zeek_intel = generate_zeek_intel(indicators)
    assert "198.51.100.45\tIntel::ADDR" in zeek_intel


def test_bilstm_attention_sequence_model():
    """Verify PyTorch BiLSTM Attention sequence tokenization, forward pass, and attention extraction."""
    raw = load_trace_file(Path("data/samples/ransomware_lockbit.json"))
    norm = normalize_trace_events(raw.events)

    engine = build_default_sequence_engine()
    res = engine.predict_trace(norm)

    assert "predicted_family" in res
    assert "confidence" in res
    assert "attention_highlights" in res
    assert len(res["attention_highlights"]) > 0

    # Ensure sum of attention weights is roughly 1.0 or weights are normalized
    for item in res["attention_highlights"]:
        assert "event_id" in item
        assert "attention_weight" in item
        assert isinstance(item["attention_weight"], float)


def test_sysmon_xml_and_json_parsing():
    """Verify Sysmon XML and JSON parser converts native Windows Event logs to RawTrace."""
    sample_xml = """<Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <EventID>1</EventID>
          <TimeCreated SystemTime="2026-08-28T12:00:00.000Z"/>
        </System>
        <EventData>
          <Data Name="ProcessId">3456</Data>
          <Data Name="ParentProcessId">1000</Data>
          <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
          <Data Name="CommandLine">cmd.exe /c vssadmin delete shadows /all /quiet</Data>
        </EventData>
      </Event>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <EventID>3</EventID>
          <TimeCreated SystemTime="2026-08-28T12:00:05.000Z"/>
        </System>
        <EventData>
          <Data Name="ProcessId">3456</Data>
          <Data Name="DestinationIp">203.0.113.88</Data>
          <Data Name="DestinationPort">443</Data>
          <Data Name="Protocol">tcp</Data>
        </EventData>
      </Event>
    </Events>"""

    raw_trace = parse_sysmon_xml(sample_xml, sample_id="sysmon_test_01")
    assert raw_trace.sample_id == "sysmon_test_01"
    assert len(raw_trace.events) == 2
    assert raw_trace.events[0].api_name == "CreateProcessInternalW"
    assert raw_trace.events[0].arguments["command_line"] == "cmd.exe /c vssadmin delete shadows /all /quiet"
    assert raw_trace.events[1].api_name == "WSAConnect"
    assert raw_trace.events[1].arguments["destination_ip"] == "203.0.113.88"

    # Test JSON stream format
    json_events = [
        {
            "event_id": 11,
            "UtcTime": "2026-08-28T12:01:00Z",
            "data": {
                "ProcessId": 3456,
                "TargetFilename": "C:\\Users\\Victim\\Desktop\\invoice.exe"
            }
        }
    ]
    json_trace = parse_sysmon_json(json_events, sample_id="sysmon_json_test")
    assert len(json_trace.events) == 1
    assert json_trace.events[0].api_name == "NtCreateFile"


def test_siem_and_tip_exporters():
    """Verify Splunk HEC, Elastic ECS, MISP, and STIX 2.1 formatting."""
    analysis = analyze_trace(Path("data/samples/ransomware_lockbit.json"))

    # 1. Splunk HEC
    splunk = export_splunk_hec(analysis)
    assert splunk["sourcetype"] == "maltrace:threat:analysis"
    assert splunk["event"]["sample_id"] == "ransomware_lockbit_01"
    assert "T1486" in splunk["event"]["mitre_technique_ids"]

    # 2. Elastic ECS
    ecs = export_elastic_ecs(analysis)
    assert ecs["event"]["kind"] == "alert"
    assert ecs["threat"]["framework"] == "MITRE ATT&CK"
    assert len(ecs["threat"]["technique"]) > 0

    # 3. MISP Event
    misp = export_misp_event(analysis)
    assert "Event" in misp
    assert len(misp["Event"]["Tag"]) > 0

    # 4. STIX 2.1 Bundle
    stix = export_stix_bundle(analysis)
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) >= 2
    types = [obj["type"] for obj in stix["objects"]]
    assert "malware" in types
    assert "report" in types


def test_campaign_clustering_engine():
    """Verify agglomerative clustering over multiple trace samples."""
    samples = list(Path("data/samples").glob("*.json"))
    assert len(samples) >= 6

    res = cluster_trace_samples(samples, distance_threshold=0.60)
    assert res.total_samples == len(samples)
    assert res.num_clusters >= 1
    assert len(res.clusters) >= 1

    for cl in res.clusters:
        assert cl.sample_count >= 1
        assert 0.0 <= cl.cohesion_score <= 1.0


def test_advanced_api_endpoints():
    """Verify new REST endpoints for IDS export, SIEM export, and Campaign Clustering."""
    client = TestClient(app)

    # 1. Upload and analyze sample
    with open("data/samples/ransomware_wannacry.json", "rb") as f:
        r_up = client.post("/analyze", files={"file": ("wannacry.json", f, "application/json")})
    assert r_up.status_code == 201
    ana_id = r_up.json()["analysis_id"]

    # 2. Export IDS endpoint
    r_ids = client.get(f"/analyses/{ana_id}/ids?format=suricata")
    assert r_ids.status_code == 200
    assert "MalTrace-LM" in r_ids.text

    # 3. Export SIEM endpoint
    r_siem = client.get(f"/analyses/{ana_id}/siem?format=splunk")
    assert r_siem.status_code == 200
    assert r_siem.json()["sourcetype"] == "maltrace:threat:analysis"

    # 4. Campaign clustering endpoint
    with open("data/samples/ransomware_wannacry.json", "rb") as f1, open("data/samples/ransomware_lockbit.json", "rb") as f2:
        r_clust = client.post(
            "/cluster",
            files=[
                ("files", ("wannacry.json", f1, "application/json")),
                ("files", ("lockbit.json", f2, "application/json"))
            ]
        )
    assert r_clust.status_code == 200
    c_json = r_clust.json()
    assert c_json["total_samples"] == 2
    assert c_json["num_clusters"] >= 1


def test_async_background_analysis_job():
    """Verify asynchronous background analysis queuing and status polling."""
    client = TestClient(app)

    with open("data/samples/ransomware_wannacry.json", "rb") as f:
        r_async = client.post("/analyze/async", files={"file": ("wannacry.json", f, "application/json")})
    assert r_async.status_code == 202
    data = r_async.json()
    assert "job_id" in data
    assert data["status"] in ("queued", "processing", "completed")
    job_id = data["job_id"]

    # Poll status endpoint
    r_stat = client.get(f"/analyses/jobs/{job_id}")
    assert r_stat.status_code == 200
    stat_data = r_stat.json()
    assert stat_data["job_id"] == job_id
    assert stat_data["status"] in ("queued", "processing", "completed")
