"""
STIX 2.1 Enterprise ATT&CK Synchronization Module.
Parses STIX 2.1 JSON bundles, extracts attack-patterns, normalizes tactics and external IDs,
and synchronizes with the MalTrace-LM technique catalog.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import urllib.request

from maltrace.attack_mapping.catalog import TechniqueDefinition, load_technique_catalog

TACTIC_NAME_MAP = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact"
}


def parse_stix_bundle(bundle_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse a STIX 2.1 JSON bundle and extract active attack-pattern techniques.
    """
    objects = bundle_data.get("objects", [])
    extracted_techniques: List[Dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Extract technique ID (e.g. T1059.001)
        ext_refs = obj.get("external_references", [])
        technique_id = None
        for ref in ext_refs:
            if ref.get("source_name") in ("mitre-attack", "mitre-enterprise-attack"):
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            continue

        # Extract tactic
        kill_chain = obj.get("kill_chain_phases", [])
        tactic_name = "Execution"
        for phase in kill_chain:
            if phase.get("kill_chain_name") in ("mitre-attack", "mitre-enterprise-attack"):
                raw_tactic = phase.get("phase_name", "")
                tactic_name = TACTIC_NAME_MAP.get(raw_tactic, raw_tactic.replace("-", " ").title())
                break

        name = obj.get("name", "Unknown Technique")
        description = obj.get("description", "").split("\n")[0]  # First paragraph/line

        # Default evidence patterns based on name and ID
        clean_name_word = name.split(":")[-1].strip().lower()
        extracted_techniques.append({
            "technique_id": technique_id,
            "technique_name": name,
            "tactic": tactic_name,
            "description": description or f"MITRE ATT&CK technique {technique_id}: {name}",
            "required_evidence_patterns": [clean_name_word] if clean_name_word else [technique_id.lower()],
            "optional_supporting_patterns": [],
            "exclusion_rules": [],
            "base_confidence": 0.75
        })

    return extracted_techniques


def sync_catalog_from_stix(
    stix_source: Union[str, Path, Dict[str, Any]],
    output_catalog_path: Optional[Path] = None,
    merge_with_existing: bool = True
) -> int:
    """
    Synchronize catalog with a STIX 2.1 source (file path, URL, or dict).
    Preserves existing custom rules while adding newly discovered techniques.
    Returns the total number of techniques in the synchronized catalog.
    """
    if isinstance(stix_source, dict):
        bundle = stix_source
    elif isinstance(stix_source, (str, Path)):
        source_str = str(stix_source)
        if source_str.startswith("http://") or source_str.startswith("https://"):
            req = urllib.request.Request(source_str, headers={"User-Agent": "MalTrace-STIX-Sync/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                bundle = json.loads(resp.read().decode("utf-8"))
        else:
            with open(source_str, "r", encoding="utf-8") as f:
                bundle = json.load(f)
    else:
        raise ValueError("Invalid STIX source provided.")

    stix_techniques = parse_stix_bundle(bundle)

    if output_catalog_path is None:
        output_catalog_path = Path(__file__).parent / "catalog.json"

    existing_catalog_defs = []
    if merge_with_existing and output_catalog_path.exists():
        try:
            existing_catalog_defs = load_technique_catalog(output_catalog_path)
        except Exception:
            existing_catalog_defs = []

    technique_map: Dict[str, Dict[str, Any]] = {}

    # Load existing custom rules first
    for ex in existing_catalog_defs:
        technique_map[ex.technique_id] = ex.model_dump()

    # Merge in new STIX techniques
    for stix_t in stix_techniques:
        tid = stix_t["technique_id"]
        if tid not in technique_map:
            technique_map[tid] = stix_t
        else:
            # Update metadata while keeping tailored evidence patterns
            technique_map[tid]["technique_name"] = stix_t["technique_name"]
            technique_map[tid]["tactic"] = stix_t["tactic"]
            if not technique_map[tid].get("description"):
                technique_map[tid]["description"] = stix_t["description"]

    # Sort techniques by ID
    sorted_techniques = sorted(technique_map.values(), key=lambda x: x["technique_id"])
    catalog_data = {
        "catalog_version": "1.2.0",
        "techniques": sorted_techniques
    }

    with open(output_catalog_path, "w", encoding="utf-8") as f:
        json.dump(catalog_data, f, indent=2)

    return len(sorted_techniques)
