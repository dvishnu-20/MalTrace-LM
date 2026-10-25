"""
FastAPI Service Integration Tests for MalTrace-LM.
Validates endpoints (/health, /version, /analyze, /analyses/{id}, /report, /events/{id}),
upload safety rules, persistence, and retention cleanup.
"""

import io
import json
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from maltrace.api.app import app
from maltrace.api.database import init_db, get_analysis_record, save_analysis_record
from maltrace.api.cleanup import cleanup_old_analyses


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """
    Configure isolated temporary database and storage dir for integration tests via environment variables.
    """
    test_db = tmp_path / "test_maltrace.db"
    test_storage = tmp_path / "test_storage"
    test_storage.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("MALTRACE_DB_PATH", str(test_db))
    monkeypatch.setenv("MALTRACE_STORAGE_DIR", str(test_storage))

    init_db(db_path=test_db)


def test_health_and_version_endpoints():
    with TestClient(app) as client:
        r_health = client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ok"

        r_version = client.get("/version")
        assert r_version.status_code == 200
        data = r_version.json()
        assert data["maltrace_version"] == "0.1.0"
        assert data["vocabulary_version"] == "1.0.0"


def test_analyze_valid_sample_trace():
    sample_file = Path("data/samples/ransomware_wannacry.json")
    assert sample_file.exists()

    with TestClient(app) as client:
        with open(sample_file, "rb") as f:
            response = client.post(
                "/analyze",
                files={"file": ("ransomware_wannacry.json", f, "application/json")}
            )

        assert response.status_code == 201
        data = response.json()
        assert "analysis_id" in data
        assert data["status"] == "completed"
        assert data["predicted_family"] == "Ransomware.WannaCry"
        assert "links" in data
        assert data["links"]["result"].startswith("/analyses/")


def test_get_analysis_by_id():
    sample_file = Path("data/samples/ransomware_wannacry.json")
    with TestClient(app) as client:
        with open(sample_file, "rb") as f:
            post_resp = client.post(
                "/analyze",
                files={"file": ("ransomware_wannacry.json", f, "application/json")}
            )
        aid = post_resp.json()["analysis_id"]

        get_resp = client.get(f"/analyses/{aid}")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["metadata"]["analysis_id"] == aid
        assert data["result"]["sample_id"] == "ransomware_wannacry_01"


def test_get_analysis_report_formats():
    sample_file = Path("data/samples/ransomware_wannacry.json")
    with TestClient(app) as client:
        with open(sample_file, "rb") as f:
            post_resp = client.post(
                "/analyze",
                files={"file": ("ransomware_wannacry.json", f, "application/json")}
            )
        aid = post_resp.json()["analysis_id"]

        # 1. HTML format (default)
        html_resp = client.get(f"/analyses/{aid}/report?format=html")
        assert html_resp.status_code == 200
        assert "text/html" in html_resp.headers["content-type"]
        assert "MalTrace-LM" in html_resp.text

        # 2. Markdown format
        md_resp = client.get(f"/analyses/{aid}/report?format=markdown")
        assert md_resp.status_code == 200
        assert "# MalTrace-LM" in md_resp.text

        # 3. JSON format
        json_resp = client.get(f"/analyses/{aid}/report?format=json")
        assert json_resp.status_code == 200
        assert json_resp.json()["sample_id"] == "ransomware_wannacry_01"


def test_get_evidence_event_by_id():
    sample_file = Path("data/samples/ransomware_wannacry.json")
    with TestClient(app) as client:
        with open(sample_file, "rb") as f:
            post_resp = client.post(
                "/analyze",
                files={"file": ("ransomware_wannacry.json", f, "application/json")}
            )
        aid = post_resp.json()["analysis_id"]

        event_resp = client.get(f"/analyses/{aid}/events/evt_1001")
        assert event_resp.status_code == 200
        ev_data = event_resp.json()
        assert ev_data["event_id"] == "evt_1001"


def test_invalid_json_upload_rejected():
    invalid_content = b"NOT A VALID JSON CONTENT {"
    with TestClient(app) as client:
        resp = client.post(
            "/analyze",
            files={"file": ("corrupt.json", invalid_content, "application/json")}
        )
        assert resp.status_code == 400
        assert "not valid JSON" in resp.json()["detail"]


def test_oversized_file_upload_rejected():
    oversized_content = b"a" * (10 * 1024 * 1024 + 100)  # > 10MB
    with TestClient(app) as client:
        resp = client.post(
            "/analyze",
            files={"file": ("huge_trace.json", oversized_content, "application/json")}
        )
        assert resp.status_code == 413
        assert "exceeds maximum limit" in resp.json()["detail"]


def test_blocked_extension_upload_rejected():
    with TestClient(app) as client:
        resp = client.post(
            "/analyze",
            files={"file": ("malware.exe", b"binary_data", "application/octet-stream")}
        )
        assert resp.status_code == 400
        assert "blocked" in resp.json()["detail"]


def test_path_traversal_filename_rejected():
    with TestClient(app) as client:
        resp = client.post(
            "/analyze",
            files={"file": ("../../etc/passwd.json", b'{"sample_id": "test"}', "application/json")}
        )
        assert resp.status_code == 400
        assert "path traversal" in resp.json()["detail"].lower()


def test_missing_analysis_id_returns_404():
    with TestClient(app) as client:
        r1 = client.get("/analyses/ana_nonexistent_9999")
        assert r1.status_code == 404

        r2 = client.get("/analyses/ana_nonexistent_9999/report")
        assert r2.status_code == 404

        r3 = client.get("/analyses/ana_nonexistent_9999/events/evt_1001")
        assert r3.status_code == 404


def test_missing_event_id_returns_404():
    sample_file = Path("data/samples/ransomware_wannacry.json")
    with TestClient(app) as client:
        with open(sample_file, "rb") as f:
            post_resp = client.post(
                "/analyze",
                files={"file": ("ransomware_wannacry.json", f, "application/json")}
            )
        aid = post_resp.json()["analysis_id"]

        ev_resp = client.get(f"/analyses/{aid}/events/evt_NON_EXISTENT_999")
        assert ev_resp.status_code == 404


def test_cleanup_policy(tmp_path, monkeypatch):
    test_db = tmp_path / "test_cleanup.db"
    test_storage = tmp_path / "test_cleanup_storage"
    test_storage.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("MALTRACE_DB_PATH", str(test_db))
    monkeypatch.setenv("MALTRACE_STORAGE_DIR", str(test_storage))

    init_db(db_path=test_db)

    old_aid = "ana_old_12345"
    old_folder = test_storage / "analyses" / old_aid
    old_folder.mkdir(parents=True, exist_ok=True)
    raw_file = old_folder / "raw_trace.json"
    raw_file.write_text("{}")

    old_record = {
        "analysis_id": old_aid,
        "sample_id": "old_sample",
        "sample_hash": "hash123",
        "pipeline_version": "0.1.0",
        "model_artifact_version": "0.1.0",
        "vocabulary_version": "1.0.0",
        "technique_catalog_version": "1.0.0",
        "created_at": "2026-01-01T00:00:00Z",
        "status": "completed",
        "raw_file_path": str(raw_file),
        "result_json_path": None,
        "report_html_path": None,
        "file_size_bytes": 2
    }
    save_analysis_record(old_record, db_path=test_db)

    res = cleanup_old_analyses(max_age_days=30, db_path=test_db, storage_dir=test_storage)
    assert res["analyses_cleaned"] == 1
    assert get_analysis_record(old_aid, db_path=test_db) is None
    assert not raw_file.exists()
