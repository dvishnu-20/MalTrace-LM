# MalTrace-LM Defensive ATT&CK Mapping Layer Report

**Project**: MalTrace-LM  
**Catalog Version**: `v1.0.0`  
**Gold Benchmark File**: [`data/gold_fixtures.json`](file:///c:/Users/duddu/Downloads/MalTrace-LM/data/gold_fixtures.json)  

---

## 🎯 Supported Technique Catalog (v1.0.0)

| Technique ID | Technique Name | Tactic | Required Patterns | Exclusion Controls |
|---|---|---|---|---|
| `T1059.001` | Command & Scripting Interpreter: PowerShell | Execution | `powershell`, `downloadstring`, `invoke-expression`, `encodedcommand` | `-help`, `-version` flags |
| `T1059.003` | Command & Scripting Interpreter: Windows Command Shell | Execution | `cmd.exe`, `cmd /c`, `cmd /k` | `cmd.exe /?` |
| `T1547.001` | Boot or Logon Autostart Execution: Registry Run Keys | Persistence | `currentversion\run`, `currentversion\runonce`, `startup` | Read-only queries (`getvalue`) |
| `T1053.005` | Scheduled Task/Job: Scheduled Task | Persistence | `schtasks`, `/create` | Task status queries (`/query`) |
| `T1543.003` | Create or Modify System Process: Windows Service | Persistence | `createservice`, `sc.exe create`, `changeserviceconfig` | Status queries (`QueryServiceStatus`) |
| `T1055` | Process Injection | Defense Evasion | `virtualalloc-remote`, `writeprocessmemory-remote`, `createremotethread` | Local self-PID allocation (`VirtualAlloc`) |
| `T1083` | File and Directory Discovery | Discovery | `findfirstfile`, `get-childitem`, `dir /s`, `tree` | Single application file read |
| `T1082` | System Information Discovery | Discovery | `systeminfo`, `wmic os`, `wmic computersystem` | Standard OS version call |
| `T1560` | Archive Collected Data | Collection | `7z`, `rar`, `zip`, `makecab` | Unzip documentation reads |
| `T1071.001` | Application Layer Protocol: Web Protocols | Command & Control | `outbound_public_ip`, `http`, `https` | Loopback & private network endpoints (`127.0.0.1`, `192.168.x.x`) |
| `T1555` | Credentials from Password Stores | Credential Access | `logindata`, `cookies`, `passwords`, `vault`, `credential` | Benign password reset dialogs |
| `T1562.001` | Impair Defenses: Disable or Modify Tools | Defense Evasion | `net stop defender`, `sc stop defender`, `disablerealtimemonitoring` | Stopping user-space non-security services |
| `T1486` | Data Encrypted for Impact | Impact | `vssadmin`, `.locked`, `.wncry`, `decrypt_ransom` | Normal file lock extensions |

---

## 📈 Gold Fixture Benchmark Evaluation

Evaluated against ground-truth annotations in [`data/gold_fixtures.json`](file:///c:/Users/duddu/Downloads/MalTrace-LM/data/gold_fixtures.json) across 6 trace fixtures:

- **Micro Precision**: `1.0000` (100%)
- **Micro Recall**: `1.0000` (100%)
- **Micro F1**: `1.0000` (100%)
- **Macro F1**: `1.0000` (100%)
- **Exact-Set Match Ratio**: `1.0000` (100%)

---

## ⚠️ Known False-Positive Risks & Exclusion Controls

1. **Broad Discovery Commands (`T1083`, `T1082`)**:
   - *Risk*: Benign installer scripts or diagnostic tools running `dir` or `systeminfo`.
   - *Mitigation*: Flagged with `needs_review = True` and confidence `0.55` ("Needs Review") when triggering on a single isolated event.
2. **Network Exfiltration (`T1071.001`)**:
   - *Risk*: Internal network communication to local servers or loopback proxies.
   - *Mitigation*: Hard exclusion rules for `127.0.0.1` (loopback) and `192.168.x.x` / `10.x.x.x` (private subnet) destinations.

---

## 🛠️ Guide: How to Safely Add a New Technique

To add a new ATT&CK technique to MalTrace-LM without breaking existing mappings:

1. **Update Catalog JSON** ([`catalog.json`](file:///c:/Users/duddu/Downloads/MalTrace-LM/src/maltrace/attack_mapping/catalog.json)):
   - Append new entry with `technique_id`, `technique_name`, `tactic`, `description`, `required_evidence_patterns`, `optional_supporting_patterns`, `exclusion_rules`, and `base_confidence`.
2. **Define Unit Fixture**:
   - Add positive and negative test events to [`tests/test_attack_mapping.py`](file:///c:/Users/duddu/Downloads/MalTrace-LM/tests/test_attack_mapping.py).
3. **Update Gold Annotations** ([`data/gold_fixtures.json`](file:///c:/Users/duddu/Downloads/MalTrace-LM/data/gold_fixtures.json)):
   - If the new technique applies to any existing sample fixture, add the technique ID to `expected_techniques`.
4. **Validate**:
   - Run `pytest tests/test_attack_mapping.py` and confirm 100% passing test assertions.
