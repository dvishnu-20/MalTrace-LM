import json
from pathlib import Path
import pytest

from maltrace.reporting.generator import analyze_trace
from maltrace.reporting.report_generator import (
    generate_deterministic_analyst_report,
    render_report_json,
    render_report_markdown,
    render_report_html
)
from maltrace.reporting.llm_provider import (
    DisabledLLMProvider,
    MockLLMProvider,
    OpenAICompatibleLLMProvider
)
from maltrace.reporting.grounding_gate import build_analyst_report, validate_llm_response


def test_deterministic_report_generation_and_export_formats():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result = analyze_trace(sample_path)

    report = generate_deterministic_analyst_report(result)

    assert report.generation_mode == "deterministic"
    assert report.sample_id == "ransomware_wannacry_01"
    assert "Ransomware.WannaCry" in report.executive_summary
    assert report.predicted_family == "Ransomware.WannaCry"
    assert len(report.observed_categories) >= 1
    assert len(report.attack_techniques) >= 1
    assert len(report.process_tree_overview) >= 1
    assert len(report.key_evidence_table) >= 1
    assert "Uncertainty & Limitations" in report.uncertainty_and_limitations

    # Export Formats
    json_output = render_report_json(report)
    md_output = render_report_markdown(report)
    html_output = render_report_html(report)

    assert json.loads(json_output)["sample_id"] == "ransomware_wannacry_01"
    assert "# MalTrace-LM Defensive Analyst Report" in md_output
    assert "<h1>🛡️ MalTrace-LM Defensive Analyst Report</h1>" in html_output


def test_deterministic_report_idempotency():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result1 = analyze_trace(sample_path, seed=42)
    result2 = analyze_trace(sample_path, seed=42)

    rep1 = generate_deterministic_analyst_report(result1)
    rep2 = generate_deterministic_analyst_report(result2)

    d1 = rep1.model_dump(exclude={"manifest"})
    d2 = rep2.model_dump(exclude={"manifest"})
    assert d1 == d2



def test_mock_llm_valid_response_acceptance():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result = analyze_trace(sample_path)

    mock_provider = MockLLMProvider(mode="valid")
    report = build_analyst_report(result, llm_provider=mock_provider)

    assert report.generation_mode == "llm"
    assert report.manifest is not None
    assert report.manifest.llm_provider == "mock"
    assert report.manifest.validation_status == "passed"
    assert "(LLM Enhanced)" in report.executive_summary


def test_mock_llm_malformed_json_fallback():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result = analyze_trace(sample_path)

    mock_provider = MockLLMProvider(mode="malformed_json")
    report = build_analyst_report(result, llm_provider=mock_provider)

    assert report.generation_mode == "deterministic"
    assert report.manifest is not None
    assert report.manifest.validation_status == "failed"
    assert len(report.manifest.validation_warnings) >= 1


def test_mock_llm_hallucinated_event_id_fallback():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result = analyze_trace(sample_path)

    mock_provider = MockLLMProvider(mode="hallucinated_event_id")
    report = build_analyst_report(result, llm_provider=mock_provider)

    assert report.generation_mode == "deterministic"
    assert report.manifest is not None
    assert report.manifest.validation_status == "failed"
    assert any("hallucinated" in w.lower() for w in report.manifest.validation_warnings)


def test_mock_llm_invalid_technique_id_fallback():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result = analyze_trace(sample_path)

    mock_provider = MockLLMProvider(mode="invalid_technique")
    report = build_analyst_report(result, llm_provider=mock_provider)

    assert report.generation_mode == "deterministic"
    assert report.manifest is not None
    assert report.manifest.validation_status == "failed"
    assert any("unmapped technique_id" in w.lower() for w in report.manifest.validation_warnings)


def test_mock_llm_timeout_and_provider_failure_fallback():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result = analyze_trace(sample_path)

    # Timeout
    timeout_provider = MockLLMProvider(mode="timeout")
    rep_timeout = build_analyst_report(result, llm_provider=timeout_provider)
    assert rep_timeout.generation_mode == "deterministic"
    assert rep_timeout.manifest is not None
    assert rep_timeout.manifest.validation_status == "failed"

    # Connection failure
    fail_provider = MockLLMProvider(mode="failure")
    rep_fail = build_analyst_report(result, llm_provider=fail_provider)
    assert rep_fail.generation_mode == "deterministic"
    assert rep_fail.manifest is not None
    assert rep_fail.manifest.validation_status == "failed"


def test_acceptance_gate_no_llm_configured_default():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result = analyze_trace(sample_path)

    report_default = build_analyst_report(result, llm_provider=None)
    assert report_default.generation_mode == "deterministic"
    assert report_default.manifest is not None
    assert report_default.manifest.validation_status == "disabled"


def test_mock_llm_semantic_hallucination_fallback():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    result = analyze_trace(sample_path)

    mock_provider = MockLLMProvider(mode="semantic_hallucination")
    report = build_analyst_report(result, llm_provider=mock_provider)

    # Must safely discard hallucinated claim and return deterministic fallback
    assert report.generation_mode == "deterministic"
    assert report.manifest is not None
    assert report.manifest.validation_status == "failed"
    assert any("semantic grounding failure" in w.lower() for w in report.manifest.validation_warnings)
