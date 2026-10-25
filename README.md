# MalTrace-LM: Execution Trace Behavior Engine & ATT&CK Mapper

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Safety: Defensive Only](https://img.shields.io/badge/Safety-Defensive_Only-green.svg)](#safety-boundary)

**MalTrace-LM** is a defensive software system that converts previously generated Windows execution traces (JSON format) into concise behavior descriptions, predicts malware family labels, maps observed behavior to a small MITRE ATT&CK technique set, and produces evidence-linked analyst reports.

---

## 🛡️ Purpose & Safety Boundary

### Purpose
MalTrace-LM addresses the challenge of analyzing raw Windows API execution traces by structuring unstructured execution logs into evidence-backed behavioral claims, categorizing threats into known malware families (e.g., Ransomware, Infostealer, Trojan, Dropper, Coinminer), and mapping behavioral indicators directly to MITRE ATT&CK techniques.

### Safety Boundary
> [!IMPORTANT]
> **STRICTLY DEFENSIVE & OFFLINE ONLY**: MalTrace-LM works **only** with JSON trace files and synthetic fixtures.
> - **NO** malware execution capabilities.
> - **NO** live network C2 command dispatch or payload downloading.
> - **NO** offensive exploitation tooling or dynamic injection routines.
> - Safe for deployment in restricted analyst environments and automated CI/CD security pipelines.

---

## ⚙️ Installation

### Standard Installation
Clone the repository and install dependencies in editable mode:

```bash
git clone https://github.com/maltrace-lm/maltrace-lm.git
cd MalTrace-LM
pip install -e .
```

### Optional LLM Integration
To install optional language model dependencies (`openai`, `langchain`, `transformers`):

```bash
pip install -e ".[llm]"
```

---

## 🚀 Quick Start

### 1. CLI Analysis Command
Analyze a JSON trace sample and generate an evidence-linked analyst report:

```bash
python -m maltrace analyze data/samples/example.json --out reports/example.json
```

Or using the installed executable shortcut:

```bash
maltrace analyze data/samples/ransomware_wannacry.json --out reports/wannacry_report.json
```

### 2. Interactive Streamlit Dashboard
Launch the visual analyst dashboard to inspect trace event timelines, process hierarchies, behavior claims, and MITRE ATT&CK mappings:

```bash
streamlit run src/maltrace/dashboard/app.py
```

### 3. REST API Server & Persistence Layer
Launch the production-style FastAPI server:

```bash
# Using maltrace CLI:
maltrace serve --port 8000

# Or via uvicorn directly:
uvicorn maltrace.api.app:app --host 127.0.0.1 --port 8000
```

#### API Endpoints & Usage Examples

```bash
# 1. Health & Version Checks
curl http://localhost:8000/health
curl http://localhost:8000/version

# 2. Upload Trace JSON for Analysis (Returns analysis_id and artifact links)
curl -X POST "http://localhost:8000/analyze" \
  -H "Accept: application/json" \
  -F "file=@data/samples/ransomware_wannacry.json"

# 3. Retrieve Analysis Metadata & Full Result JSON
curl http://localhost:8000/analyses/{analysis_id}

# 4. Fetch Rendered Report (Formats: html, markdown, json)
curl http://localhost:8000/analyses/{analysis_id}/report?format=html -o report.html
curl http://localhost:8000/analyses/{analysis_id}/report?format=markdown
curl http://localhost:8000/analyses/{analysis_id}/report?format=json

# 5. Lookup Specific Evidence Event by ID
curl http://localhost:8000/analyses/{analysis_id}/events/evt_1001

# 6. Execute Retention Cleanup Job (Remove files older than 30 days)
maltrace cleanup --max-age-days 30
```

#### Storage Layout & Persistence
- **Metadata Database**: SQLite database stored at `data/maltrace.db` holding sample hashes, pipeline versions, component vocabulary versions, status, timestamps, and artifact links.
- **Report & Raw Storage**: Filesystem storage under `data/storage/analyses/{analysis_id}/` containing `raw_trace.json`, `result.json`, and `report.html`.
- **Retention Policy**: `cleanup_old_analyses(max_age_days)` removes raw uploads, result JSONs, HTML reports, and database records older than the configured max age.
- **Upload Safety & Validation**: Rejects files > 10MB (HTTP 413), blocks dangerous extensions (`.exe`, `.dll`, `.zip`, etc.), sanitizes path traversal characters (`..`, `/`, `\`), and validates JSON payload syntax without executing uploaded content.

---

## 📊 Sample Report Output (`reports/example.json`)

```json
{
  "sample_id": "ransomware_wannacry_01",
  "trace_summary": {
    "total_raw_events": 3,
    "total_normalized_events": 3,
    "total_processes": 2,
    "categories_found": ["file", "process"]
  },
  "family_prediction": {
    "family_name": "Ransomware.WannaCry",
    "confidence": 0.92,
    "confidence_label": "High",
    "rule_triggered": "RULE_RANSOMWARE_FILE_ENCRYPTION_VSS_DELETE",
    "supporting_evidence_ids": ["evt_1001", "evt_1002", "evt_1003"]
  },
  "technique_predictions": [
    {
      "technique_id": "T1486",
      "technique_name": "Data Encrypted for Impact",
      "tactic": "Impact",
      "confidence": 0.95,
      "supporting_evidence_ids": ["evt_1001"]
    }
  ],
  "cited_evidence": [
    {
      "event_id": "evt_1001",
      "event_order": 1,
      "api_name": "CreateProcessInternalW",
      "category": "process",
      "snippet": "PID 4120 | CreateProcessInternalW | {'image_name': 'C:\\\\Windows\\\\System32\\\\vssadmin.exe', ...}"
    }
  ]
}
```

---

## 🗺️ Repository Map

```
MalTrace-LM/
├── .env.example               # Environment variables template
├── .gitignore                 # Git ignore configuration
├── .pre-commit-config.yaml    # Formatting and linting hooks
├── Makefile                   # Developer task automation runner
├── pyproject.toml             # Python package dependencies & entrypoints
├── README.md                  # System overview and usage instructions
├── HANDOFF.md                 # Implementation progress & handoff specification
├── data/
│   └── samples/               # Synthetic WinMET JSON trace fixtures
│       ├── benign_notepad.json
│       ├── coinminer_xmrig.json
│       ├── dropper_emotet.json
│       ├── example.json
│       ├── infostealer_redline.json
│       ├── ransomware_wannacry.json
│       └── trojan_asyncrat.json
├── src/
│   └── maltrace/
│       ├── __init__.py
│       ├── __main__.py        # Module entrypoint (python -m maltrace)
│       ├── cli.py             # Typer CLI application
│       ├── api/               # FastAPI REST API endpoints
│       ├── attack_mapping/    # MITRE ATT&CK mapping engine
│       ├── contracts/         # Pydantic schemas & data contracts
│       ├── dashboard/         # Streamlit visual dashboard
│       ├── features/          # Process summarizer & claim extractor
│       ├── ingestion/         # WinMET JSON trace file loader
│       ├── models/            # Family classifier & heuristic rules
│       ├── reporting/         # Report generator & manifest builder
│       ├── representation/    # API normalizer & argument sanitizer
│       ├── utils/             # Deterministic seed & helper utilities
│       └── verification/      # Evidence reference validator
└── tests/                     # Test suite (pytest)
    ├── test_cli.py
    ├── test_end_to_end.py
    ├── test_normalizer.py
    ├── test_schemas.py
    :
```

---

## ⚠️ Current Limitations & Roadmap

1. **Rule-Based Family Classification**: Current vertical slice relies on deterministic heuristic rules for 6 primary family categories. Phase 2 will introduce supervised ML classifiers (`scikit-learn` models trained on TF-IDF / N-gram API sequences).
2. **WinMET Input Format**: Support is currently optimized for compact WinMET-style event arrays. Future releases will support streaming NDJSON trace logs and Cuckoo / CAPE sandbox JSON reports.
3. **ATT&CK Coverage**: Initial mapping targets 6 primary technique IDs (T1486, T1547.001, T1059.001, T1555, T1071.001, T1543.003). Phase 2 will expand technique coverage to STIX 2.1 ATT&CK matrices.
