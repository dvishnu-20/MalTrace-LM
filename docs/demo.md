# MalTrace-LM Analyst Portal — Demo & User Walkthrough

## Overview
The **MalTrace-LM Analyst Portal** is a service-backed web dashboard enabling security analysts to ingest Windows API execution traces, verify behavior claims against evidence, inspect MITRE ATT&CK technique mappings, explore process lineages, and download audit-ready report artifacts without using command line scripts.

---

## 🚀 Service & Dashboard Launch Commands

To run the complete system locally:

```bash
# 1. Terminal 1: Start the MalTrace-LM FastAPI REST Server
maltrace serve --host 127.0.0.1 --port 8000

# 2. Terminal 2: Start the Streamlit Analyst Portal
streamlit run src/maltrace/dashboard/app.py
```

Open your browser to `http://localhost:8501` to access the portal.

---

## 🌟 Golden Demo Trace Walkthrough

### Demo Trace 1: Ransomware Classification & Evidence Verification (`data/samples/ransomware_wannacry.json`)

1. **Ingestion & Safety Validation**:
   - Navigate to **📤 Analyze Trace**.
   - Select `ransomware_wannacry.json` from **Built-in Fixtures** (or upload the file).
   - Notice the **Defensive Safety Notice** banner.
   - Click **🚀 Run Defensive Analysis Pipeline**.
   - Watch progress states (`Uploading trace...`, `Validating citations...`, `Retrieving results...`).

2. **Viewing Findings & Scorecard**:
   - Navigate to **📊 Analysis Results**.
   - **Family Prediction**: `Ransomware.WannaCry` with `High Confidence (Strong Evidence)` (Score: `0.92`).
   - **Signal Triggered**: `FALLBACK_RULE_RANSOMWARE_FILE_ENCRYPTION_VSS_DELETE`.
   - **Verification Scorecard**:
     - Total Claims: `2` | Supported Claims: `2` | Rejected Claims: `0` | Citation Completeness: `100.0%`.
   - **Mapped MITRE ATT&CK Techniques**:
     - `T1486`: Data Encrypted for Impact (Supporting events: `evt_1002`, `evt_1003`).
     - `T1547.001`: Registry Run Keys / Startup Folder (Supporting events: `evt_1001`).

3. **Interactive Evidence & Process Hierarchy Inspection**:
   - Navigate to **🔍 Evidence Inspector**.
   - **Process Lineage Tree**: View PID `4120` (`tasksche.exe`) spawned by PID `1050` (`cmd.exe`).
   - **Direct Event ID Lookup**: Select `evt_1001` or `evt_1002`. Click **Inspect Event**.
   - View exact API parameters (`CreateProcessInternalW`, `NtWriteFile`), controlled natural-language phrases, and security anchor flags.

4. **Report Artifact Downloads**:
   - On **📊 Analysis Results** -> **📥 Report Artifact Downloads**:
     - Click **Download HTML Report** to receive a styled printable report (`ana_..._report.html`).
     - Click **Download Markdown Report** (`ana_..._report.md`).
     - Click **Download JSON Result** (`ana_..._result.json`).

5. **Historical Analysis Browsing**:
   - Navigate to **📜 Persisted History**.
   - View SQLite database records with status filters (`completed`, `failed`) and family filters (`Ransomware`, `Stealer`, etc.).
   - Select any historical `analysis_id` and click **📖 Load Selected Analysis** to reload findings into the dashboard session.

---

### Demo Trace 2: Low-Evidence Family Prediction Abstention

1. Upload or run trace with low confidence or trace length < min threshold.
2. In **📊 Analysis Results**, observe the prominent amber callout banner:
   > **⚠️ Family Classification Abstained**  
   > *Reason: ABSTAINED_LOW_CLASSIFIER_CONFIDENCE: Classifier confidence (0.35) is below threshold (0.60).*
3. Observe that valid technique predictions (`T1059.001` PowerShell execution) are **STILL returned** with verified evidence links, ensuring defensive utility even when family classification abstains.

---

## 📋 Manual Demo Verification Checklist

- [x] **API Connectivity**: Sidebar displays `🟢 API Service Connected`.
- [x] **Defensive Notice**: Upload page shows defensive safety boundary statement.
- [x] **Trace Upload**: Uploading `ransomware_wannacry.json` returns HTTP 201 Created and Analysis ID.
- [x] **Validation Rules**: Uploading a `.exe` or `> 10MB` file returns clear error messages.
- [x] **Verification Scorecard**: Scorecard renders total, supported, and rejected claims.
- [x] **Abstention Handling**: Low-confidence or short traces trigger clear abstention banners while preserving techniques.
- [x] **Evidence Inspection**: Direct lookup for `evt_1001` returns normalized API arguments and process context.
- [x] **Report Downloads**: Analyst can download HTML, Markdown, and JSON reports directly from browser.
- [x] **Persisted History**: Browse SQLite database records and reload past analyses in one click.
