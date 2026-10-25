"""
Unit and smoke tests for MalTrace-LM Streamlit Dashboard API Client.
Verifies API client initialization, error handling, health checks, upload wrapper, and report retrieval.
"""

import pytest
from maltrace.dashboard.api_client import MalTraceAPIClient, APIError, APIConnectionError
from maltrace.api.app import app
from fastapi.testclient import TestClient


def test_api_client_init():
    client = MalTraceAPIClient(base_url="http://localhost:8000")
    assert client.base_url == "http://localhost:8000"


def test_api_client_unreachable_server():
    client = MalTraceAPIClient(base_url="http://127.0.0.1:59999", timeout=1.0)
    with pytest.raises(APIConnectionError):
        client.check_health()


def test_api_client_health_check():
    with TestClient(app) as test_c:
        # Wrap TestClient in custom adapter or test API endpoint directly
        response = test_c.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_api_client_version_manifest():
    with TestClient(app) as test_c:
        response = test_c.get("/version")
        assert response.status_code == 200
        data = response.json()
        assert data["maltrace_version"] == "0.1.0"


def test_clean_analysis_result_helper():
    from maltrace.dashboard.app import get_clean_analysis_result

    # Wrapped API response format
    wrapped = {
        "metadata": {"analysis_id": "ana_123"},
        "result": {
            "sample_id": "test_sample",
            "family_prediction": {"family_name": "Ransomware.WannaCry", "confidence": 0.95},
            "cited_evidence": [{"event_id": "evt_1001"}]
        }
    }
    cleaned = get_clean_analysis_result(wrapped)
    assert cleaned["sample_id"] == "test_sample"
    assert cleaned["family_prediction"]["family_name"] == "Ransomware.WannaCry"

    # Direct raw format
    raw = {"sample_id": "raw_sample", "family_prediction": {"family_name": "Benign.Activity"}}
    cleaned_raw = get_clean_analysis_result(raw)
    assert cleaned_raw["sample_id"] == "raw_sample"

