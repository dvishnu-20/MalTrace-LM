# MalTrace-LM Implementation Handoff

**Project Name**: MalTrace-LM  
**Date**: 2026-07-28  
**Status**: Reporting Layer, Deterministic Generator & Grounded Optional LLM Complete & Verified  

---

## 📁 Project Overview & Package Structure

1. **Package Configuration & Build**:
   - [`pyproject.toml`](file:///c:/Users/duddu/Downloads/MalTrace-LM/pyproject.toml): Dependencies (`pydantic`, `pandas`, `scikit-learn`, `fastapi`, `uvicorn`, `orjson`, `typer`, `pytest`, `pyarrow`, `joblib`, `streamlit`), CLI script (`maltrace`).

2. **Core Modules**:
   - [`src/maltrace/contracts/schemas.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/contracts/schemas.py): Pydantic v2 contracts (`NormalizedEvent`, `BehaviorStatement`, `FamilyPrediction`, `TechniquePrediction`, `AnalystReport`, `VerificationSummary`, `LLMReportRequest`, `LLMReportResponse`, `RunManifest`).
   - [`src/maltrace/verification/evidence_index.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/verification/evidence_index.py): In-memory index mapping event ID to normalized event, controlled phrase, process context, and source provenance.
   - [`src/maltrace/verification/support_matrix.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/verification/support_matrix.py): Claim support rules, category matrix, contradiction detection, and claim support evaluation.
   - [`src/maltrace/verification/validator.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/verification/validator.py): Evidence Verifier gate, human-readable confidence band formatting, and family prediction abstention engine.
   - [`src/maltrace/reporting/report_generator.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/reporting/report_generator.py): Deterministic template analyst report generator exporting JSON, Markdown, and styled printable HTML.
   - [`src/maltrace/reporting/llm_provider.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/reporting/llm_provider.py): Provider-neutral LLM interface (`BaseLLMProvider`, `DisabledLLMProvider`, `OpenAICompatibleLLMProvider`, `MockLLMProvider`).
   - [`src/maltrace/reporting/grounding_gate.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/reporting/grounding_gate.py): Strict grounding validation gate enforcing event ID linkage, category support, and technique ID alignment with safe fallback to deterministic report.
   - [`src/maltrace/attack_mapping/catalog.json`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/attack_mapping/catalog.json): Version `1.0.0` technique catalog covering 13 techniques.
   - [`src/maltrace/attack_mapping/mapper.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/attack_mapping/mapper.py): Evidence-linked mapper combining duplicate evidence per technique ID.
   - [`src/maltrace/dashboard/app.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/dashboard/app.py): Service-backed Streamlit Analyst Portal (Analyze, Results, Evidence Inspector, and History pages).
   - [`src/maltrace/dashboard/api_client.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/dashboard/api_client.py): REST API Client helper (`MalTraceAPIClient`) connecting Streamlit UI to FastAPI service.
   - [`src/maltrace/api/app.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/api/app.py): Production FastAPI application exposing `/health`, `/version`, `/analyze`, `/analyses`, `/analyses/{id}`, `/report`, and `/events/{id}`.
   - [`src/maltrace/api/database.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/api/database.py): SQLite metadata persistence manager (`data/maltrace.db`).
   - [`src/maltrace/api/cleanup.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/api/cleanup.py): Retention policy artifact cleanup manager.
   - [`src/maltrace/cli.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/cli.py): Typer CLI exposing `analyze`, `report`, `batch`, `render`, `audit`, `train`, `evaluate`, `predict`, `serve`, `cleanup`, and `version`.

3. **Documentation & Reports**:
   - [`docs/demo.md`](file:///c:/Users/duddu/Downloads/MalTrace-LM/docs/demo.md): Complete user walkthrough, golden demo trace execution (`ransomware_wannacry.json` & abstention case), UI workflow guide, and manual demo verification checklist.
   - [`reports/evidence_verifier.md`](file:///c:/Users/duddu/Downloads/MalTrace-LM/reports/evidence_verifier.md): Comprehensive documentation of verification thresholds, support matrix rules, contradiction criteria, confidence bands, abstention policy, audit summary, and before/after claim removal example.
   - [`reports/reporting_layer.md`](file:///c:/Users/duddu/Downloads/MalTrace-LM/reports/reporting_layer.md): Comprehensive documentation of report generation modes, privacy safeguards, grounding gate rules, and export examples.
   - [`reports/attack_mapping.md`](file:///c:/Users/duddu/Downloads/MalTrace-LM/reports/attack_mapping.md): Catalog v1.0.0 documentation and gold benchmark evaluation.
   - [`reports/model_baseline.md`](file:///c:/Users/duddu/Downloads/MalTrace-LM/reports/model_baseline.md): Machine learning model baseline evaluation.
   - [`tests/test_api_integration.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/tests/test_api_integration.py): Integration tests for FastAPI endpoints, upload validation (10MB limit, blocked extensions, path traversal rejection), SQLite persistence, report formats, event lookup, and cleanup policy.
   - [`tests/test_dashboard.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/tests/test_dashboard.py): Smoke and unit tests for Streamlit dashboard API client wrapper.
   - [`tests/test_evidence_verifier_fixtures.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/tests/test_evidence_verifier_fixtures.py): Unit and fixture tests for missing events, cross-sample citations, contradictory file actions, trace length thresholds, low-confidence abstention, and technique preservation.
   - [`tests/test_reporting_layer.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/tests/test_reporting_layer.py): Unit tests for deterministic generation, HTML export, mock LLM provider validation, grounding gate, and safe fallback.

---

## 🌐 FastAPI Web Service & Streamlit Analyst Portal

### Startup Commands
```bash
# 1. Start FastAPI REST Server:
maltrace serve --port 8000

# 2. Start Streamlit Analyst Portal:
streamlit run src/maltrace/dashboard/app.py
```

### API Endpoints
- `GET /health` - Health status check.
- `GET /version` - Version manifest (`maltrace_version`, `vocabulary_version`, `technique_catalog_version`, `model_version`).
- `POST /analyze` - Single trace upload (10MB limit, path traversal rejection, blocked extension checks, SHA-256 hash). Returns `analysis_id` and links.
- `GET /analyses` - List persisted historical analyses.
- `GET /analyses/{analysis_id}` - Retrieve analysis metadata and full result JSON.
- `GET /analyses/{analysis_id}/report` - Retrieve rendered report (HTML, Markdown, or JSON formats).
- `GET /analyses/{analysis_id}/events/{event_id}` - Look up specific evidence event by ID.

### Storage Layout & Retention Cleanup
- **Database**: SQLite database stored at `data/maltrace.db`.
- **Filesystem Storage**: Artifacts stored at `data/storage/analyses/{analysis_id}/` (`raw_trace.json`, `result.json`, `report.html`).
- **Retention Cleanup Command**:
```bash
maltrace cleanup --max-age-days 30
```

---

## 💻 Running the Full Test Suite

```bash
# Execute entire unit & integration test suite across all modules:
pytest -v
```
