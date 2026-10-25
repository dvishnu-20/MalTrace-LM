# MalTrace-LM Reporting Layer Report

**Project**: MalTrace-LM  
**Report Version**: `v1.0.0`  
**Modes Supported**: 100% Deterministic (Default) & Optional LLM-Enhanced (Disabled by default)  

---

## 🛠️ CLI Usage & Report Commands

```bash
# 1. Generate Deterministic Analyst Report in HTML:
python -m maltrace report data/samples/ransomware_wannacry.json --format html --out reports/sample_report.html

# 2. Generate Deterministic Analyst Report in Markdown:
python -m maltrace report data/samples/ransomware_wannacry.json --format markdown --out reports/sample_report.md

# 3. Generate Deterministic Analyst Report in JSON:
python -m maltrace report data/samples/ransomware_wannacry.json --format json --out reports/sample_report.json

# 4. Generate Report with Optional LLM Enhancement (OpenAI-compatible local endpoint):
python -m maltrace report data/samples/ransomware_wannacry.json --format html --out reports/llm_report.html --enable-llm --llm-provider openai-compatible --llm-endpoint http://localhost:11434/v1/chat/completions
```

---

## 🔒 Privacy & Grounding Safeguards

1. **100% Deterministic Base Engine**:
   - Works completely without an external LLM dependency.
   - All executive summaries, family predictions, ATT&CK mappings, process tree overviews, evidence tables, and recommendations are generated using predefined templates populated strictly with validated fields from `AnalysisResult`.

2. **Privacy-Safe LLM Fact Payload**:
   - When an LLM provider is explicitly enabled, MalTrace-LM sends **ONLY** structured facts (`LLMReportRequest`) containing:
     - Sample ID, predicted family, confidence score, and primary signal rule.
     - Observed behavioral categories.
     - Mapped ATT&CK technique IDs and names.
     - Process names, lineage paths, and rendered controlled behavior phrases.
   - **Zero Raw Traces**: Unredacted raw JSON trace files, raw binary payloads, or user paths are NEVER sent to the LLM.

3. **Strict Grounding & Evidence Validation Gate**:
   - LLM outputs MUST conform to Pydantic schema `LLMReportResponse` (`summary`, `behavior_claims`, `cited_event_ids`, `uncertainty_statement`, `analyst_notes`).
   - Every cited event ID in `cited_event_ids` is checked against `AnalysisResult.cited_evidence`. If any event ID is missing or hallucinated, **the LLM response is discarded instantly**.
   - Every technique ID mentioned in the LLM output is checked against mapper predictions. If any unmapped technique ID is mentioned, **the LLM response is discarded instantly**.
   - **Safe Fallback**: On ANY validation failure, timeout, or provider error, MalTrace-LM falls back 100% safely to the deterministic template analyst report and records a warning in the manifest (`validation_status: "failed"`).

4. **Prompt & Run Manifest Versioning**:
   - Manifest stores prompt version (`1.0.0`), schema version (`1.0.0`), provider name (`disabled`, `openai-compatible`, `mock`), model name, temperature, SHA-256 response hash, and validation status (`passed`, `failed`, `disabled`).

---

## 📊 Comparison: Deterministic vs. Optional LLM Modes

| Feature | Deterministic Mode (Default) | Optional LLM Mode |
|---|---|---|
| **External Dependency** | None (100% Offline Python) | Local or Remote API Endpoint |
| **Output Formats** | JSON, Markdown, Printable HTML | JSON, Markdown, Printable HTML |
| **Generation Speed** | Instant (<10ms) | Depends on Endpoint Latency |
| **Grounding Guarantee** | 100% Guaranteed Template | 100% Validated by Grounding Gate |
| **Fallback Strategy** | N/A (Primary Engine) | Safe Fallback to Deterministic Mode on Failure |

---

## 📄 Sample Report Output Excerpt (Markdown)

```markdown
# MalTrace-LM Defensive Analyst Report: ransomware_wannacry_01
**Generation Mode**: `DETERMINISTIC` | **Schema Version**: `1.0.0`

---
## Executive Summary
> Executive Summary: Execution trace sample 'ransomware_wannacry_01' exhibits behavior classified under family 'Ransomware.WannaCry' with High confidence (0.92). The trace contains 2 processes interacting across behavioral categories [file, process]. Primary classification signal: 'FALLBACK_RULE_RANSOMWARE_FILE_ENCRYPTION_VSS_DELETE'.

## Classification & Primary Signal
- **Predicted Family**: `Ransomware.WannaCry`
- **Confidence**: `0.92` (High)
- **Signal / Rule Triggered**: `FALLBACK_RULE_RANSOMWARE_FILE_ENCRYPTION_VSS_DELETE`
- **Observed Categories**: `file`, `process`

## Mapped MITRE ATT&CK Techniques
### [T1486] Data Encrypted for Impact
- **Tactic**: `Impact` | **Confidence**: `0.85` (High)
- **Matched Rules**: `PATTERN:vssadmin`
- **Supporting Evidence Event IDs**: `evt_1001`
- **Explanation**: Technique T1486 (Data Encrypted for Impact) identified with 1 supporting evidence event(s) matching rules: PATTERN:vssadmin.

## Process Tree Overview
- **PID 4120**: `C:\Windows\System32\vssadmin.exe` (Parent PID: 3100)
  - Lineage: `budget_2026.docx.locked (3100) -> vssadmin.exe (4120)`
  - Categories: process

## Key Evidence Table
| Event ID | Order | Category | API Name | Snippet |
|---|---|---|---|---|
| `evt_1001` | 1 | `process` | `CreateProcessInternalW` | PID 4120 | CreateProcessInternalW | {'image_name': 'C:\\Windows\\System32\\vssadmin.exe', ...} |
| `evt_1002` | 2 | `file` | `WriteFile` | PID 3100 | WriteFile | {'target_path': 'C:\\Users\\<USER>\\Documents\\budget_2026.docx.locked', ...} |

## Defensive Recommendations
- Isolate affected host endpoint from local network subnets.
- Terminate processes associated with suspicious command execution lineage.
- Block outbound remote IP destinations identified in network event citations.
- Audit autostart registry keys and scheduled tasks for unauthorized persistence entries.

## Uncertainty & Limitations
_Uncertainty & Limitations: Analysis is strictly grounded in observed trace events. Unexecuted code branches, dynamic evasion delays, and kernel driver interactions not present in the input trace log are outside the scope of this report._
```
