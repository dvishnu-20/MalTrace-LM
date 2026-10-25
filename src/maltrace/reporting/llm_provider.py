"""
Provider-neutral LLM interface and adapters.
Provides BaseLLMProvider interface with disabled-by-default adapters for local OpenAI-compatible endpoints,
Google Gemini API, Anthropic Claude API, and Mock providers for testing.
Privacy Safe: Sends ONLY structured analysis results and controlled behavior phrases. Never sends raw, unredacted trace logs.
"""

import json
import hashlib
from typing import Dict, Any, Tuple, Optional
import urllib.request
import urllib.error

from maltrace.contracts.schemas import LLMReportRequest, LLMReportResponse


class BaseLLMProvider:
    """
    Abstract interface for LLM report enhancement providers.
    """
    provider_name: str = "base"
    model_name: str = "none"

    def generate_summary(self, request: LLMReportRequest) -> Tuple[Optional[LLMReportResponse], Dict[str, Any]]:
        raise NotImplementedError()


class DisabledLLMProvider(BaseLLMProvider):
    """
    Default LLM provider: disabled by default.
    """
    provider_name: str = "disabled"
    model_name: str = "none"

    def generate_summary(self, request: LLMReportRequest) -> Tuple[Optional[LLMReportResponse], Dict[str, Any]]:
        raise RuntimeError("LLM Provider is disabled. Enable optional LLM provider via configuration.")


class OpenAICompatibleLLMProvider(BaseLLMProvider):
    """
    OpenAI-compatible local or remote endpoint adapter (disabled by default).
    Sends ONLY structured LLMReportRequest facts.
    """

    def __init__(
        self,
        endpoint_url: str = "http://localhost:11434/v1/chat/completions",
        api_key: str = "local",
        model_name: str = "llama3",
        temperature: float = 0.0,
        timeout_seconds: int = 10
    ):
        self.provider_name = "openai-compatible"
        self.endpoint_url = endpoint_url
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds

    def generate_summary(self, request: LLMReportRequest) -> Tuple[Optional[LLMReportResponse], Dict[str, Any]]:
        prompt = (
            "You are a defensive malware analyst assistant. Synthesize the provided structured facts into a concise "
            "JSON report. Respond ONLY in valid JSON matching schema keys: summary, behavior_claims, cited_event_ids, "
            "uncertainty_statement, analyst_notes.\n\n"
            f"FACTS: {json.dumps(request.model_dump())}"
        )

        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a defensive security analyst assistant emitting strict JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"}
        }

        data_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        req = urllib.request.Request(self.endpoint_url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_bytes = resp.read()
                resp_json = json.loads(resp_bytes.decode("utf-8"))
                content = resp_json["choices"][0]["message"]["content"]
                response_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

                parsed_dict = json.loads(content)
                parsed_response = LLMReportResponse(**parsed_dict)

                metadata = {
                    "provider": self.provider_name,
                    "model": self.model_name,
                    "temperature": self.temperature,
                    "response_hash": response_hash,
                    "raw_response": content
                }
                return parsed_response, metadata

        except Exception as err:
            raise RuntimeError(f"LLM Provider endpoint request failed: {err}")


class GeminiLLMProvider(BaseLLMProvider):
    """
    Google Gemini REST API connector with structured JSON synthesis.
    """

    def __init__(
        self,
        api_key: str,
        model_name: str = "gemini-1.5-flash",
        temperature: float = 0.0,
        timeout_seconds: int = 15
    ):
        self.provider_name = "google-gemini"
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds

    def generate_summary(self, request: LLMReportRequest) -> Tuple[Optional[LLMReportResponse], Dict[str, Any]]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        prompt = (
            "You are a defensive malware analyst assistant. Synthesize the provided structured facts into a concise "
            "JSON report. Respond ONLY in valid JSON matching schema keys: summary, behavior_claims, cited_event_ids, "
            "uncertainty_statement, analyst_notes.\n\n"
            f"FACTS: {json.dumps(request.model_dump())}"
        )
        payload = {
            "contents": [
                {"parts": [{"text": prompt}]}
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "responseMimeType": "application/json"
            }
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_bytes = resp.read()
                resp_json = json.loads(resp_bytes.decode("utf-8"))
                content = resp_json["candidates"][0]["content"]["parts"][0]["text"]
                response_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

                parsed_dict = json.loads(content)
                parsed_response = LLMReportResponse(**parsed_dict)
                metadata = {
                    "provider": self.provider_name,
                    "model": self.model_name,
                    "temperature": self.temperature,
                    "response_hash": response_hash,
                    "raw_response": content
                }
                return parsed_response, metadata
        except Exception as err:
            raise RuntimeError(f"Gemini LLM Provider request failed: {err}")


class AnthropicLLMProvider(BaseLLMProvider):
    """
    Anthropic Claude API connector for structured analyst reporting.
    """

    def __init__(
        self,
        api_key: str,
        model_name: str = "claude-3-5-sonnet-20241022",
        temperature: float = 0.0,
        timeout_seconds: int = 15
    ):
        self.provider_name = "anthropic-claude"
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds

    def generate_summary(self, request: LLMReportRequest) -> Tuple[Optional[LLMReportResponse], Dict[str, Any]]:
        url = "https://api.anthropic.com/v1/messages"
        prompt = (
            "You are a defensive malware analyst assistant. Synthesize the provided structured facts into a concise "
            "JSON report. Respond ONLY in valid raw JSON with keys: summary, behavior_claims, cited_event_ids, "
            "uncertainty_statement, analyst_notes.\n\n"
            f"FACTS: {json.dumps(request.model_dump())}"
        )
        payload = {
            "model": self.model_name,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_bytes = resp.read()
                resp_json = json.loads(resp_bytes.decode("utf-8"))
                content = resp_json["content"][0]["text"]
                response_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

                parsed_dict = json.loads(content)
                parsed_response = LLMReportResponse(**parsed_dict)
                metadata = {
                    "provider": self.provider_name,
                    "model": self.model_name,
                    "temperature": self.temperature,
                    "response_hash": response_hash,
                    "raw_response": content
                }
                return parsed_response, metadata
        except Exception as err:
            raise RuntimeError(f"Anthropic LLM Provider request failed: {err}")


class MockLLMProvider(BaseLLMProvider):
    """
    Configurable mock LLM provider for unit testing grounding gates and fallback behaviors.
    """

    def __init__(self, mode: str = "valid", response_override: Optional[Dict[str, Any]] = None):
        self.provider_name = "mock"
        self.model_name = "mock-analyst-v1"
        self.mode = mode
        self.response_override = response_override

    def generate_summary(self, request: LLMReportRequest) -> Tuple[Optional[LLMReportResponse], Dict[str, Any]]:
        if self.mode == "timeout":
            raise TimeoutError("Mock LLM Provider timed out after 10.0s")
        elif self.mode == "failure":
            raise RuntimeError("Mock LLM Provider connection refused")
        elif self.mode == "malformed_json":
            raw_str = "INVALID_JSON_RESPONSE {unclosed_key:"
            res_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16]
            # Will fail json parsing in grounding gate
            return None, {"provider": self.provider_name, "model": self.model_name, "response_hash": res_hash, "raw_response": raw_str}
        elif self.mode == "hallucinated_event_id":
            resp_dict = {
                "summary": f"LLM summary for {request.sample_id}",
                "behavior_claims": ["Process executed shadow copy deletion"],
                "cited_event_ids": ["evt_999999_hallucinated"],  # Does not exist in request!
                "uncertainty_statement": "Trace bounds apply.",
                "analyst_notes": "Verify host memory."
            }
        elif self.mode == "invalid_technique":
            resp_dict = {
                "summary": f"LLM summary for {request.sample_id} citing T9999",
                "behavior_claims": ["Process executed invalid technique T9999"],
                "cited_event_ids": request.cited_event_ids[:1],
                "uncertainty_statement": "Trace bounds apply.",
                "analyst_notes": "Verify host memory."
            }
        elif self.mode == "semantic_hallucination":
            resp_dict = {
                "summary": f"LLM summary for {request.sample_id}",
                "behavior_claims": ["Malware executed process injection via CreateRemoteThread into svchost.exe"],
                "cited_event_ids": request.cited_event_ids[:1],  # Valid ID, but semantically contradictory/unsupported
                "uncertainty_statement": "Trace bounds apply.",
                "analyst_notes": "Verify host memory."
            }
        else:  # valid
            resp_dict = self.response_override or {
                "summary": f"LLM enhanced executive summary for trace sample '{request.sample_id}'. The host displayed activity consistent with '{request.predicted_family}'.",
                "behavior_claims": [f"Observed behavior across categories: {', '.join(request.behavior_categories)}."],
                "cited_event_ids": request.cited_event_ids if request.cited_event_ids else ["evt_1001"],
                "uncertainty_statement": "Grounded strictly in cited trace events.",
                "analyst_notes": "Recommend host isolation and key audit."
            }

        raw_str = json.dumps(resp_dict)
        res_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16]

        response_obj = LLMReportResponse(
            summary=str(resp_dict["summary"]),
            behavior_claims=list(resp_dict["behavior_claims"]),
            cited_event_ids=list(resp_dict["cited_event_ids"]),
            uncertainty_statement=str(resp_dict["uncertainty_statement"]),
            analyst_notes=str(resp_dict["analyst_notes"])
        )
        metadata = {
            "provider": self.provider_name,
            "model": self.model_name,
            "temperature": 0.0,
            "response_hash": res_hash,
            "raw_response": raw_str
        }
        return response_obj, metadata
