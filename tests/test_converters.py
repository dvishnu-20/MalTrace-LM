import json
import tempfile
from pathlib import Path
import pytest

from maltrace.ingestion.converters import convert_otrf_sysmon, convert_winmet, convert_cape
from maltrace.representation.normalizer import normalize_trace_events
from maltrace.contracts.schemas import RawEvent


def test_convert_otrf_sysmon():
    otrf_logs = [
        {
            "EventID": 1,
            "timestamp": "2026-07-28T10:00:01Z",
            "event_data": {
                "ProcessId": "4120",
                "ParentProcessId": "3100",
                "Image": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe Delete Shadows /All /Quiet"
            }
        },
        {
            "EventID": 3,
            "timestamp": "2026-07-28T10:00:02Z",
            "event_data": {
                "ProcessId": "3100",
                "DestinationIp": "198.51.100.25",
                "DestinationPort": "8080",
                "Protocol": "tcp"
            }
        },
        {
            "EventID": 11,
            "timestamp": "2026-07-28T10:00:03Z",
            "event_data": {
                "ProcessId": "3100",
                "TargetFilename": "C:\\Users\\Victim\\Desktop\\ransom_note.txt"
            }
        }
    ]

    with tempfile.TemporaryDirectory() as tmp_dir:
        in_p = Path(tmp_dir) / "otrf.json"
        out_p = Path(tmp_dir) / "converted.json"

        with open(in_p, "w", encoding="utf-8") as f:
            json.dump(otrf_logs, f)

        res = convert_otrf_sysmon(in_p, output_path=out_p)

        assert out_p.exists()
        assert len(res["events"]) == 3
        assert res["events"][0]["api_name"] == "CreateProcessInternalW"
        assert res["events"][1]["api_name"] == "connect"
        assert res["events"][2]["api_name"] == "NtCreateFile"

        # Verify normalizer can process converted events
        raw_events = [RawEvent(**e) for e in res["events"]]
        norm = normalize_trace_events(raw_events)
        assert len(norm) == 3
        assert norm[0].category == "process"
        assert norm[1].category == "network"
        assert norm[2].category == "file"


def test_convert_winmet():
    winmet_data = {
        "sample_id": "winmet_sample_01",
        "family": "Ransomware.WannaCry",
        "calls": [
            {
                "api": "NtCreateFile",
                "pid": 2048,
                "ppid": 1000,
                "args": {"target_path": "C:\\Windows\\system32\\calc.exe"}
            },
            {
                "api": "WriteFile",
                "pid": 2048,
                "ppid": 1000,
                "args": ["arg0_val", "arg1_val"]
            }
        ]
    }

    res = convert_winmet(winmet_data)
    assert res["sample_id"] == "winmet_sample_01"
    assert res["family"] == "Ransomware.WannaCry"
    assert len(res["events"]) == 2
    assert res["events"][0]["api_name"] == "NtCreateFile"
    assert res["events"][1]["api_name"] == "WriteFile"


def test_convert_cape():
    cape_data = {
        "info": {
            "id": 1234,
            "family": "Stealer.RedLine"
        },
        "behavior": {
            "processes": [
                {
                    "process_id": 4000,
                    "parent_id": 1000,
                    "calls": [
                        {
                            "api": "RegOpenKeyExW",
                            "timestamp": "2026-07-28T12:00:00Z",
                            "arguments": {"key_name": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}
                        }
                    ]
                }
            ]
        }
    }

    res = convert_cape(cape_data)
    assert res["sample_id"] == 1234
    assert res["family"] == "Stealer.RedLine"
    assert len(res["events"]) == 1
    assert res["events"][0]["api_name"] == "RegOpenKeyExW"
    assert res["events"][0]["process_id"] == 4000
