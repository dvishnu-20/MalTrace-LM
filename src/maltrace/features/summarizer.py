from typing import List, Dict, Tuple
from maltrace.contracts.schemas import NormalizedEvent, ProcessSummary, BehaviorClaim
from maltrace.features.process_tree import build_enhanced_process_summaries


def build_process_summaries(events: List[NormalizedEvent]) -> List[ProcessSummary]:
    """
    Aggregate normalized events into process summaries and construct parent-child relationships using ProcessTree.
    """
    summaries, _ = build_enhanced_process_summaries(events)
    return summaries



def extract_behavior_claims(events: List[NormalizedEvent]) -> List[BehaviorClaim]:
    """
    Extract structured behavior claims with linked evidence event IDs.
    """
    claims: List[BehaviorClaim] = []
    claim_idx = 1

    # 1. Shadow copy deletion pattern
    vss_evts = [
        e for e in events
        if "vssadmin" in str(e.safe_arguments).lower() and "delete" in str(e.safe_arguments).lower()
    ]
    if vss_evts:
        claims.append(
            BehaviorClaim(
                claim_id=f"claim_{claim_idx:03d}",
                description="Attempted volume shadow copy deletion to prevent system recovery",
                category="Ransomware/Impact",
                evidence_event_ids=[e.event_id for e in vss_evts],
                confidence=0.95
            )
        )
        claim_idx += 1

    # 2. File encryption / suspicious extension change
    enc_evts = [
        e for e in events
        if any(ext in str(e.safe_arguments).lower() for ext in [".locked", ".wncry", ".encrypted", ".crypto"])
        or "ransom" in str(e.safe_arguments).lower()
    ]
    if enc_evts:
        claims.append(
            BehaviorClaim(
                claim_id=f"claim_{claim_idx:03d}",
                description="Wrote ransom note or encrypted files with ransom extension",
                category="Ransomware/FileModification",
                evidence_event_ids=[e.event_id for e in enc_evts],
                confidence=0.90
            )
        )
        claim_idx += 1

    # 3. Registry Autorun Persistence
    reg_run_evts = [
        e for e in events
        if e.category == "registry" and any(k in str(e.safe_arguments).lower() for k in ["run", "runonce", "startup"])
    ]
    if reg_run_evts:
        claims.append(
            BehaviorClaim(
                claim_id=f"claim_{claim_idx:03d}",
                description="Modified Windows Registry startup run keys for persistent execution",
                category="Persistence/Registry",
                evidence_event_ids=[e.event_id for e in reg_run_evts],
                confidence=0.88
            )
        )
        claim_idx += 1

    # 4. Browser Credential / Sensitive Data Access
    cred_evts = [
        e for e in events
        if any(path_key in str(e.safe_arguments).lower() for path_key in ["logindata", "web data", "cookies", "vault", "passwords.txt"])
    ]
    if cred_evts:
        claims.append(
            BehaviorClaim(
                claim_id=f"claim_{claim_idx:03d}",
                description="Accessed browser credential storage or saved password files",
                category="CredentialAccess",
                evidence_event_ids=[e.event_id for e in cred_evts],
                confidence=0.92
            )
        )
        claim_idx += 1

    # 5. Network Exfiltration / Outbound C2 Connection
    net_evts = [e for e in events if e.category == "network"]
    if net_evts:
        claims.append(
            BehaviorClaim(
                claim_id=f"claim_{claim_idx:03d}",
                description=f"Initiated {len(net_evts)} outbound network connection(s) to external server",
                category="CommandAndControl",
                evidence_event_ids=[e.event_id for e in net_evts],
                confidence=0.85
            )
        )
        claim_idx += 1

    # 6. Service Manipulation
    svc_evts = [e for e in events if e.category == "service"]
    if svc_evts:
        claims.append(
            BehaviorClaim(
                claim_id=f"claim_{claim_idx:03d}",
                description="Created or modified a Windows Service for execution or persistence",
                category="Persistence/Service",
                evidence_event_ids=[e.event_id for e in svc_evts],
                confidence=0.87
            )
        )
        claim_idx += 1

    # 7. Shell Scripting Interpreter Execution (Powershell / Cmd)
    script_evts = [
        e for e in events
        if e.category == "process" and any(p in str(e.safe_arguments).lower() for p in ["powershell", "cmd.exe", "wscript", "cscript"])
    ]
    if script_evts:
        claims.append(
            BehaviorClaim(
                claim_id=f"claim_{claim_idx:03d}",
                description="Spawned command shell or PowerShell interpreter",
                category="Execution/Scripting",
                evidence_event_ids=[e.event_id for e in script_evts],
                confidence=0.82
            )
        )
        claim_idx += 1

    # 8. Benign / Standard File Access Fallback
    if not claims:
        claims.append(
            BehaviorClaim(
                claim_id=f"claim_{claim_idx:03d}",
                description="Performed standard file operations without suspicious security indicators",
                category="BenignActivity",
                evidence_event_ids=[e.event_id for e in events[:5]],
                confidence=0.99
            )
        )

    return claims
