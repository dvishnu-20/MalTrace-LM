# Evidence Verifier & Trustworthiness Framework

## Overview
The **Evidence Verifier** operates between the prediction engine and final report generation in MalTrace-LM. It acts as an automated verification gate ensuring that:
1. Every claim and technique prediction cites existing execution events from the active trace sample.
2. Behavioral claims adhere to acceptable categories and required attributes defined in the **Support Matrix**.
3. Contradictory evidence (e.g., claiming shadow copy deletion on a file read event or file creation on a pure file delete event) is detected and rejected.
4. Raw confidence scores are mapped to human-readable confidence bands without forensic over-claiming.
5. The system abstains from malware family predictions when evidence is insufficient, while preserving valid technique predictions.

---

## 1. Configurable Verification Thresholds

| Parameter | Default Value | Description |
|---|---|---|
| `min_family_confidence` | `0.60` | Minimum classifier confidence score required to assert a malware family label. Below this, family prediction abstains. |
| `min_usable_events` | `3` | Minimum number of usable normalized events in the trace log required for family classification. |
| `min_citation_completeness` | `0.50` | Minimum ratio of valid event citations (`valid_cited_ids / total_cited_ids`). |

---

## 2. Claim Support Matrix & Rules

| Claim Category | Acceptable Event Categories | Required Attributes / Keywords | Contradiction Criteria |
|---|---|---|---|
| `Ransomware/Impact` | `process`, `file` | `vssadmin`, `delete`, `bcdedit`, `wbadmin`, `shadows`, `recoveryenabled` | Cited events lack `vssadmin` or `delete` keywords or perform non-vssadmin file reads. |
| `Ransomware/FileModification` | `file` | `.locked`, `.wncry`, `.crypto`, `.encrypted`, `ransom`, `decrypt`, `readme` | Cited events are pure process creations or file deletions with no write/encryption indicators. |
| `Persistence/Registry` | `registry` | `run`, `runonce`, `startup`, `currentversion`, `services`, `is_persistence` | Cited events contain zero registry interactions. |
| `CredentialAccess` | `file`, `registry` | `logindata`, `cookies`, `vault`, `passwords`, `lsass`, `sam`, `web data` | Cited events contain zero credential or browser storage interactions. |
| `CommandAndControl` | `network` | Outbound destination IP/domain or network event | Cited events contain zero network events. |
| `Persistence/Service` | `service` | `createservice`, `startservice`, `service` | Cited events contain zero service management calls. |
| `Execution/Scripting` | `process` | `powershell`, `cmd`, `wscript`, `cscript`, `bash`, `sh` | Cited events contain no script interpreter execution. |

---

## 3. Human-Readable Confidence Bands

To prevent misleading claims of absolute forensic certainty, continuous confidence scores are mapped into standardized bands:

- **0.85 – 1.00**: `High Confidence (Strong Evidence)`
- **0.60 – 0.84**: `Moderate Confidence (Probable)`
- **0.40 – 0.59**: `Low Confidence (Tentative)`
- **< 0.40 / Abstained**: `Abstained (Insufficient Confidence)`

---

## 4. Abstention Policy

Family classification abstains (`family_name: "Abstained"`) whenever **ANY** of the following conditions occur:

1. **Low Classifier Confidence**: `confidence < 0.60`
2. **Too Few Usable Events**: Trace log contains `< 3` usable events.
3. **Critical Parsing Warnings**: Trace manifest contains critical parse errors or truncation warnings.
4. **Insufficient Citation Coverage**: `citation_completeness < 0.50` or zero supported claims remain after verifier filtering.

> [!NOTE]
> **Technique Preservation**: When family classification abstains, mapped ATT&CK technique predictions with valid evidence citations are **STILL returned** as valid conclusions.

---

## 5. Audit Output (`verification_summary`)

The internal `AnalysisResult` and final `AnalystReport` record an audit summary:

```json
{
  "verification_summary": {
    "total_claims": 2,
    "supported_claims": 1,
    "partially_supported_claims": 0,
    "rejected_claims": 1,
    "citation_completeness": 1.0,
    "family_abstained": false,
    "abstention_reason": null,
    "rejected_claim_details": [
      {
        "claim_id": "claim_002",
        "description": "Attempted volume shadow copy deletion",
        "category": "Ransomware/Impact",
        "support_status": "unsupported",
        "rejection_reason": "MISSING_EVENT_CITATION: Cited event ID(s) ['evt_9999'] do not exist in sample trace.",
        "cited_evidence_ids": ["evt_9999"]
      }
    ]
  }
}
```

---

## 6. Before / After Example: Unsupported Claim Removal

### Before Evidence Verification (Raw Claims)
```json
"behavior_claims": [
  {
    "claim_id": "claim_001",
    "description": "Wrote ransom note or encrypted files with ransom extension",
    "category": "Ransomware/FileModification",
    "evidence_event_ids": ["evt_005"],
    "confidence": 0.90
  },
  {
    "claim_id": "claim_002",
    "description": "Attempted volume shadow copy deletion to prevent system recovery",
    "category": "Ransomware/Impact",
    "evidence_event_ids": ["evt_9999"],
    "confidence": 0.95
  }
]
```

### After Evidence Verification (Final Narrative Report)
```json
"behavior_claims": [
  {
    "claim_id": "claim_001",
    "description": "Wrote ransom note or encrypted files with ransom extension",
    "category": "Ransomware/FileModification",
    "evidence_event_ids": ["evt_005"],
    "confidence": 0.90
  }
],
"verification_summary": {
  "total_claims": 2,
  "supported_claims": 1,
  "rejected_claims": 1,
  "rejected_claim_details": [
    {
      "claim_id": "claim_002",
      "rejection_reason": "MISSING_EVENT_CITATION: Cited event ID(s) ['evt_9999'] do not exist in sample trace."
    }
  ]
}
```
