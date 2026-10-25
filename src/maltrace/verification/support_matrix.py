"""
Claim support rules and support matrix for behavior validation.
Defines acceptable event categories, required attributes, contradiction detection, and claim support rules.
"""

from typing import Dict, Any, List, Set, Tuple, Optional
from maltrace.contracts.schemas import BehaviorClaim
from maltrace.verification.evidence_index import EvidenceIndex, EvidenceEntry


# Support Matrix mapping claim categories to acceptable event categories and required keywords/attributes
SUPPORT_MATRIX: Dict[str, Dict[str, Any]] = {
    "Ransomware/Impact": {
        "acceptable_categories": {"process", "file"},
        "required_keywords": ["vssadmin", "delete", "bcdedit", "wbadmin", "shadows", "recoveryenabled"],
        "description": "Shadow copy deletion or recovery prevention"
    },
    "Ransomware/FileModification": {
        "acceptable_categories": {"file"},
        "required_keywords": [".locked", ".wncry", ".crypto", ".encrypted", "ransom", "decrypt", "readme", ".lockbit"],
        "description": "Ransom note creation or file encryption"
    },
    "Persistence/Registry": {
        "acceptable_categories": {"registry"},
        "required_keywords": ["run", "runonce", "startup", "currentversion", "services", "is_persistence"],
        "description": "Windows Registry autostart persistence"
    },
    "CredentialAccess": {
        "acceptable_categories": {"file", "registry"},
        "required_keywords": ["logindata", "cookies", "vault", "passwords", "lsass", "sam", "web data", "wallet"],
        "description": "Browser credential, cryptocurrency wallet or sensitive data access"
    },
    "CredentialAccess/Keylogger": {
        "acceptable_categories": {"process", "memory", "file", "network"},
        "required_keywords": ["keylog", "getasynckeystate", "setwindowshookex", "smtp", "mail", "ftp_exfil"],
        "description": "Keystroke logging or credential exfiltration"
    },
    "Wiper/DiskCorruption": {
        "acceptable_categories": {"file", "process", "other"},
        "required_keywords": ["physicaldrive", "rawdisk", "drvdump", "hermetic", "wipe", "mbr", "partition"],
        "description": "Raw disk destruction or MBR corruption"
    },
    "DefenseEvasion/Obfuscation": {
        "acceptable_categories": {"process", "file", "registry", "other"},
        "required_keywords": ["encodedcommand", "base64", "xor", "obfus", "regsvr32", "rundll32", "stager"],
        "description": "Payload obfuscation and proxy execution"
    },
    "Discovery/Network": {
        "acceptable_categories": {"process", "network"},
        "required_keywords": ["ipconfig", "netstat", "arp", "route", "ping", "telnet", "scan"],
        "description": "Network configuration and port discovery"
    },
    "CommandAndControl": {
        "acceptable_categories": {"network"},
        "required_keywords": [],
        "description": "Outbound C2 network connection"
    },
    "Persistence/Service": {
        "acceptable_categories": {"service"},
        "required_keywords": ["createservice", "startservice", "service"],
        "description": "Service creation or manipulation"
    },
    "Execution/Scripting": {
        "acceptable_categories": {"process"},
        "required_keywords": ["powershell", "cmd", "wscript", "cscript", "bash", "sh"],
        "description": "Scripting interpreter execution"
    },
    "BenignActivity": {
        "acceptable_categories": {"file", "process", "registry", "network", "service", "memory", "synchronization", "other"},
        "required_keywords": [],
        "description": "Standard benign system activity"
    }
}


def _check_contradictions(claim: BehaviorClaim, entries: List[EvidenceEntry]) -> Optional[str]:
    """
    Detect explicit contradictions between claim description/category and evidence.
    Returns contradiction reason string if contradiction found, else None.
    """
    desc_lower = claim.description.lower()
    cat_lower = claim.category.lower()

    # Contradiction 1: Shadow copy deletion claim backed only by non-vssadmin file read operations
    if "shadow" in desc_lower or "vssadmin" in desc_lower:
        has_vss_or_del = any(
            "vssadmin" in str(e.event.safe_arguments).lower() or "delete" in str(e.event.safe_arguments).lower()
            for e in entries
        )
        if not has_vss_or_del:
            return "CONTRADICTORY_EVIDENCE: Claim asserts shadow copy deletion but evidence contains no vssadmin/delete arguments."

    # Contradiction 2: Claim asserts file write/creation/encryption but evidence contains only explicit DeleteFile/NtDeleteFile
    if "write" in desc_lower or "encrypt" in desc_lower or "filemodification" in cat_lower:
        only_deletions = all(
            "delete" in e.event.api_name.lower()
            for e in entries
        )
        if only_deletions and len(entries) > 0:
            return "CONTRADICTORY_EVIDENCE: Claim asserts file creation/encryption but cited events are file deletions."

    # Contradiction 3: Network C2 claim backed purely by offline registry/file events
    if "network" in cat_lower or "commandandcontrol" in cat_lower or "exfiltration" in desc_lower:
        has_net = any(e.event.category == "network" for e in entries)
        if not has_net:
            return "CONTRADICTORY_EVIDENCE: Claim asserts network C2/exfiltration but cited events contain zero network activities."

    return None


def evaluate_claim_support(
    claim: BehaviorClaim,
    index: EvidenceIndex,
    sample_id: str
) -> Tuple[str, List[str], Optional[str]]:
    """
    Evaluate a BehaviorClaim against EvidenceIndex using SupportMatrix rules.

    Returns tuple of:
    - support_status: 'supported', 'partially_supported', 'unsupported', or 'contradictory'
    - valid_event_ids: list of valid, non-dangling event IDs supporting claim
    - reason: explanation if rejected or partially supported
    """
    if not claim.evidence_event_ids:
        return "unsupported", [], "MISSING_EVIDENCE_CITATIONS: Claim contains zero evidence event IDs."

    valid_entries: List[EvidenceEntry] = []
    missing_ids: List[str] = []
    cross_sample_ids: List[str] = []

    for eid in claim.evidence_event_ids:
        status = index.validate_reference(eid, target_sample_id=sample_id)
        if status == "VALID":
            valid_entries.append(index.get(eid))  # type: ignore
        elif status == "MISSING":
            missing_ids.append(eid)
        elif status == "CROSS_SAMPLE":
            cross_sample_ids.append(eid)

    if missing_ids:
        reason = f"MISSING_EVENT_CITATION: Cited event ID(s) {missing_ids} do not exist in sample trace."
        if not valid_entries:
            return "unsupported", [], reason

    if cross_sample_ids:
        reason = f"CROSS_SAMPLE_CITATION: Cited event ID(s) {cross_sample_ids} belong to another sample."
        if not valid_entries:
            return "unsupported", [], reason

    if not valid_entries:
        return "unsupported", [], "NO_VALID_EVIDENCE: None of the cited event IDs exist in the active sample."

    # Contradiction Check
    contradiction_reason = _check_contradictions(claim, valid_entries)
    if contradiction_reason:
        return "contradictory", [], contradiction_reason

    # Category Support Matrix Check
    cat_rules = SUPPORT_MATRIX.get(claim.category)
    if not cat_rules:
        # Fallback category matching (e.g. "File", "Process", "Registry", etc.)
        claim_cat_lower = claim.category.split("/")[0].lower()
        acceptable_cats = {claim_cat_lower}
        required_keywords = []
    else:
        acceptable_cats = cat_rules["acceptable_categories"]
        required_keywords = cat_rules["required_keywords"]

    matching_entries: List[EvidenceEntry] = []
    for entry in valid_entries:
        if entry.event.category in acceptable_cats:
            if required_keywords:
                args_str = (str(entry.event.safe_arguments) + " " + entry.event.api_name).lower()
                if entry.event.is_persistence or any(kw in args_str for kw in required_keywords):
                    matching_entries.append(entry)
            else:
                matching_entries.append(entry)

    valid_eids = [e.event_id for e in valid_entries]
    matching_eids = [e.event_id for e in matching_entries]

    if not matching_entries:
        return (
            "unsupported",
            [],
            f"CATEGORY_MISMATCH: Claim category '{claim.category}' is unsupported by cited event categories "
            f"[{', '.join(set(e.event.category for e in valid_entries))}]."
        )

    if len(matching_eids) == len(claim.evidence_event_ids):
        return "supported", matching_eids, None
    elif len(matching_eids) > 0:
        return (
            "partially_supported",
            matching_eids,
            f"PARTIAL_SUPPORT: {len(matching_eids)} of {len(claim.evidence_event_ids)} cited events match support matrix rules."
        )
    else:
        return "unsupported", [], "INSUFFICIENT_MATCHING_ATTRIBUTES: Cited events do not satisfy required claim attributes."
