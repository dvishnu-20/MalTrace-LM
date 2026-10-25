import json
from pathlib import Path
from typer.testing import CliRunner
import pytest

from maltrace.cli import app
from maltrace.ingestion.loader import load_trace_file

runner = CliRunner()


def test_cli_analyze_example(tmp_path: Path):
    out_json = tmp_path / "report.json"
    result = runner.invoke(app, [
        "analyze",
        "data/samples/example.json",
        "--out",
        str(out_json),
        "--seed",
        "42"
    ])

    assert result.exit_code == 0
    assert out_json.exists()

    with open(out_json, "r") as f:
        data = json.load(f)

    assert data["sample_id"] in ["example_trace_01", "ransomware_wannacry_01"]
    assert data["family_prediction"]["family_name"] == "Ransomware.WannaCry"
    assert len(data["behavior_claims"]) > 0
    assert len(data["technique_predictions"]) > 0


def test_loader_invalid_json(tmp_path: Path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{ this is invalid json }")

    with pytest.raises(ValueError) as exc:
        load_trace_file(bad_json)
    assert "Invalid JSON" in str(exc.value)


def test_loader_missing_fields_fallback(tmp_path: Path):
    sparse_json = tmp_path / "sparse.json"
    sparse_json.write_text(json.dumps([
        {"action": "NtCreateFile", "args": "C:\\temp.txt"}
    ]))

    raw_trace = load_trace_file(sparse_json)
    assert len(raw_trace.events) == 1
    evt = raw_trace.events[0]
    assert evt.event_id == "evt_0001"
    assert evt.api_name == "NtCreateFile"
    assert evt.process_id == 1000
