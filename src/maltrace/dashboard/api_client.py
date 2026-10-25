"""
REST API Client helper for MalTrace-LM Streamlit Analyst Dashboard.
Encapsulates all HTTP communications with the FastAPI backend service.
"""

import os
import requests
from typing import Dict, Any, List, Optional, Union


class APIError(Exception):
    """Base exception for MalTrace API client errors."""
    pass


class APIConnectionError(APIError):
    """Raised when unable to connect to the MalTrace FastAPI server."""
    pass


class MalTraceAPIClient:
    """
    Client for interacting with the MalTrace-LM FastAPI REST service endpoints.
    """
    def __init__(self, base_url: Optional[str] = None, timeout: float = 15.0):
        url = base_url or os.environ.get("MALTRACE_API_URL", "http://127.0.0.1:8000")
        self.base_url = url.rstrip("/")
        self.timeout = timeout

    def check_health(self) -> Dict[str, Any]:
        """
        Check service health status via GET /health.
        """
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError as e:
            raise APIConnectionError(f"Unable to connect to MalTrace API at {self.base_url}: {e}")
        except Exception as e:
            raise APIError(f"Health check failed: {e}")

    def get_version(self) -> Dict[str, Any]:
        """
        Retrieve component version manifest via GET /version.
        """
        try:
            resp = requests.get(f"{self.base_url}/version", timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError as e:
            raise APIConnectionError(f"Unable to connect to MalTrace API at {self.base_url}: {e}")
        except Exception as e:
            raise APIError(f"Version request failed: {e}")

    def analyze_file(self, file_bytes: bytes, filename: str = "trace.json") -> Dict[str, Any]:
        """
        Upload trace JSON file for analysis via POST /analyze.
        """
        files = {"file": (filename, file_bytes, "application/json")}
        try:
            resp = requests.post(f"{self.base_url}/analyze", files=files, timeout=self.timeout * 2)
            if resp.status_code == 400:
                raise APIError(f"Validation Error (400): {resp.json().get('detail', resp.text)}")
            elif resp.status_code == 413:
                raise APIError("Payload Too Large (413): File size exceeds maximum limit of 10MB.")
            elif resp.status_code >= 500:
                raise APIError(f"Server Error ({resp.status_code}): {resp.json().get('detail', resp.text)}")

            resp.raise_for_status()
            return resp.json()

        except requests.exceptions.ConnectionError as e:
            raise APIConnectionError(f"Unable to connect to MalTrace API at {self.base_url}: {e}")
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Trace analysis upload failed: {e}")

    def get_analysis(self, analysis_id: str) -> Dict[str, Any]:
        """
        Retrieve stored analysis metadata and result JSON via GET /analyses/{analysis_id}.
        """
        try:
            resp = requests.get(f"{self.base_url}/analyses/{analysis_id}", timeout=self.timeout)
            if resp.status_code == 404:
                raise APIError(f"Analysis ID '{analysis_id}' not found (404).")
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError as e:
            raise APIConnectionError(f"Unable to connect to MalTrace API at {self.base_url}: {e}")
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Failed to retrieve analysis '{analysis_id}': {e}")

    def get_report(self, analysis_id: str, format: str = "html") -> Union[str, Dict[str, Any]]:
        """
        Retrieve formatted report artifact via GET /analyses/{analysis_id}/report?format=...
        Returns string for html/markdown, or dict for json.
        """
        try:
            resp = requests.get(
                f"{self.base_url}/analyses/{analysis_id}/report",
                params={"format": format},
                timeout=self.timeout
            )
            if resp.status_code == 404:
                raise APIError(f"Report for analysis ID '{analysis_id}' not found (404).")
            resp.raise_for_status()

            if format.lower() == "json":
                return resp.json()
            else:
                return resp.text

        except requests.exceptions.ConnectionError as e:
            raise APIConnectionError(f"Unable to connect to MalTrace API at {self.base_url}: {e}")
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Failed to fetch report for analysis '{analysis_id}': {e}")

    def get_event(self, analysis_id: str, event_id: str) -> Dict[str, Any]:
        """
        Lookup evidence event details by ID via GET /analyses/{analysis_id}/events/{event_id}.
        """
        try:
            resp = requests.get(
                f"{self.base_url}/analyses/{analysis_id}/events/{event_id}",
                timeout=self.timeout
            )
            if resp.status_code == 404:
                raise APIError(f"Event ID '{event_id}' not found in analysis '{analysis_id}' (404).")
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError as e:
            raise APIConnectionError(f"Unable to connect to MalTrace API at {self.base_url}: {e}")
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Failed to lookup event '{event_id}' in analysis '{analysis_id}': {e}")

    def get_evidence_event(self, analysis_id: str, event_id: str) -> Dict[str, Any]:
        """
        Alias for get_event for backward compatibility.
        """
        return self.get_event(analysis_id=analysis_id, event_id=event_id)

    def get_navigator_layer(self, analysis_id: str) -> Dict[str, Any]:
        """
        Retrieve MITRE ATT&CK Navigator v4.5 JSON layer via GET /analyses/{analysis_id}/navigator.
        """
        try:
            resp = requests.get(
                f"{self.base_url}/analyses/{analysis_id}/navigator",
                timeout=self.timeout
            )
            if resp.status_code == 404:
                raise APIError(f"Navigator layer for analysis ID '{analysis_id}' not found (404).")
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError as e:
            raise APIConnectionError(f"Unable to connect to MalTrace API at {self.base_url}: {e}")
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Failed to fetch Navigator layer for analysis '{analysis_id}': {e}")

    def list_analyses(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve list of historical analysis records via GET /analyses?limit=...
        """
        try:
            resp = requests.get(f"{self.base_url}/analyses", params={"limit": limit}, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json().get("analyses", [])
        except requests.exceptions.ConnectionError as e:
            raise APIConnectionError(f"Unable to connect to MalTrace API at {self.base_url}: {e}")
        except Exception as e:
            raise APIError(f"Failed to list historical analyses: {e}")

