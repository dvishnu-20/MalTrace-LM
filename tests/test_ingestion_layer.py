import json
import tempfile
from pathlib import Path

import pytest
import pandas as pd

from maltrace.contracts.schemas import RawEvent, NormalizedEvent
from maltrace.ingestion.adapters import ReportAdapter
from maltrace.representation.normalizer import (
    normalize_event,
    normalize_api_category,
    sanitize_path_string,
    categorize_path,
    normalize_registry_hive,
    categorize_network_destination,
    collapse_consecutive_duplicates,
)
from maltrace.features.process_tree import build_process_tree, build_enhanced_process_summaries
from maltrace.ingestion.stream_parser import process_batch, stream_parse_file
from maltrace.reporting.audit import audit_dataset


def test_adapter_unknown_sections_and_missing_fields():
    report_data = {
        "sample_id": "test_sample_01",
        "family": "Trojan.Generic",
        "unknown_debug_section": {"foo": "bar"},
        "events": [
            {
                "event_id": "evt_1",
                "process_id": "1000",  # String PID converted to int
                "parent_process_id": "0",
                "api": "CreateProcessW",
                "arguments": {"image_name": "C:\\Windows\\System32\\cmd.exe"}
            }
        ]
    }
    s_id, label, raw_evts, warnings = ReportAdapter.extract(report_data, source_file="test.json")

    assert s_id == "test_sample_01"
    assert label == "Trojan.Generic"
    assert len(raw_evts) == 1
    assert raw_evts[0].process_id == 1000
    assert any("unknown_debug_section" in w for w in warnings)


def test_path_sanitization_and_categorization():
    raw_path = "C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\payload.exe"
    sanitized = sanitize_path_string(raw_path)
    assert "JohnDoe" not in sanitized
    assert "C:\\Users\\<USER>\\AppData\\Local\\Temp\\payload.exe" in sanitized

    assert categorize_path(sanitized) == "temporary_directory"
    assert categorize_path("C:\\Windows\\System32\\kernel32.dll") == "system_directory"
    assert categorize_path("C:\\Users\\<USER>\\Documents\\notes.txt") == "user_directory"
    assert categorize_path("C:\\ProgramData\\app\\data.db") == "application_data"


def test_registry_hive_normalization_and_persistence():
    assert normalize_registry_hive("HKCU\\Software\\Run") == "HKEY_CURRENT_USER\\Software\\Run"
    assert normalize_registry_hive("HKLM\\Software\\Microsoft\\Windows") == "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows"

    evt = RawEvent(
        sample_id="s1",
        event_id="e1",
        event_order=1,
        process_id=100,
        parent_process_id=0,
        api_name="RegSetValueExW",
        arguments={"registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "Autostart"}
    )
    norm = normalize_event(evt)
    assert norm.is_persistence is True
    assert norm.category == "registry"


def test_network_destination_categorization():
    assert categorize_network_destination("127.0.0.1") == "loopback"
    assert categorize_network_destination("192.168.1.50") == "private"
    assert categorize_network_destination("8.8.8.8") == "public"
    assert categorize_network_destination("malicious-c2-domain.com") == "domain-like"


def test_synchronization_category():
    assert normalize_api_category("CreateMutexW") == "synchronization"
    assert normalize_api_category("WaitForSingleObject") == "synchronization"
    assert normalize_api_category("NtOpenEvent") == "synchronization"


def test_duplicate_collapse():
    raw1 = RawEvent(sample_id="s1", event_id="e1", event_order=1, process_id=100, parent_process_id=0, api_name="WriteFile", arguments={"target": "test.txt"})
    raw2 = RawEvent(sample_id="s1", event_id="e2", event_order=2, process_id=100, parent_process_id=0, api_name="WriteFile", arguments={"target": "test.txt"})
    raw3 = RawEvent(sample_id="s1", event_id="e3", event_order=3, process_id=100, parent_process_id=0, api_name="WriteFile", arguments={"target": "test.txt"})

    # Event for DIFFERENT process - must NOT collapse across PIDs
    raw4 = RawEvent(sample_id="s1", event_id="e4", event_order=4, process_id=200, parent_process_id=100, api_name="WriteFile", arguments={"target": "test.txt"})

    norm_list = [normalize_event(r) for r in [raw1, raw2, raw3, raw4]]
    collapsed = collapse_consecutive_duplicates(norm_list)

    assert len(collapsed) == 2
    assert collapsed[0].repeat_count == 3
    assert collapsed[0].first_order == 1
    assert collapsed[0].last_order == 3
    assert collapsed[1].process_id == 200
    assert collapsed[1].repeat_count == 1


def test_process_tree_cycles_and_missing_parents():
    # Construct events with missing parent and cycle
    # P100 PPID 9999 (missing parent)
    # P200 PPID 300
    # P300 PPID 200 (cycle P200 <-> P300)
    evts = [
        NormalizedEvent(sample_id="s1", event_id="e1", event_order=1, process_id=100, parent_process_id=9999, api_name="CreateProcessW", category="process", safe_arguments={"image_name": "proc_a.exe"}, source_file="t.json"),
        NormalizedEvent(sample_id="s1", event_id="e2", event_order=2, process_id=200, parent_process_id=300, api_name="CreateProcessW", category="process", safe_arguments={"image_name": "proc_b.exe"}, source_file="t.json"),
        NormalizedEvent(sample_id="s1", event_id="e3", event_order=3, process_id=300, parent_process_id=200, api_name="CreateProcessW", category="process", safe_arguments={"image_name": "proc_c.exe"}, source_file="t.json"),
    ]

    nodes, warnings = build_process_tree(evts)

    assert nodes[100].is_orphan is True
    assert nodes[100].is_root is True
    assert any("Missing parent" in w for w in warnings)
    assert any("cycle detected" in w for w in warnings)
    assert nodes[200].has_cycle or nodes[300].has_cycle
    assert "proc_a.exe (100)" in nodes[100].readable_path


def test_streaming_batch_command():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        sample_file = tmp_path / "sample_trace.json"
        out_dir = tmp_path / "batch_out"

        trace_data = {
            "sample_id": "batch_test_01",
            "events": [
                {
                    "event_id": "e10",
                    "event_order": 1,
                    "process_id": 500,
                    "parent_process_id": 0,
                    "api_name": "CreateProcessInternalW",
                    "arguments": {"image_name": "C:\\Windows\\System32\\cmd.exe"}
                }
            ]
        }
        with open(sample_file, "w", encoding="utf-8") as f:
            json.dump(trace_data, f)

        manifest = process_batch(input_path=sample_file, output_dir=out_dir)

        assert manifest.total_files == 1
        assert manifest.successful_files == 1
        assert (out_dir / "events.jsonl").exists()
        assert (out_dir / "events.parquet").exists()
        assert (out_dir / "manifest.json").exists()

        # Check parquet file read
        df = pd.read_parquet(out_dir / "events.parquet")
        assert len(df) == 1
        assert df["process_id"].iloc[0] == 500


def test_dataset_audit():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        file1 = tmp_path / "t1.json"
        with open(file1, "w", encoding="utf-8") as f:
            json.dump({
                "sample_id": "s1",
                "label": "Ransomware.WannaCry",
                "events": [{"event_id": "e1", "process_id": 1, "api_name": "NtCreateFile", "arguments": {}}]
            }, f)

        audit_res = audit_dataset(tmp_path)
        assert audit_res["total_files"] == 1
        assert audit_res["successful_files"] == 1
        assert audit_res["parse_failures"] == 0
        assert "file" in audit_res["category_distribution"]
        assert "Ransomware.WannaCry" in audit_res["family_frequencies"]
