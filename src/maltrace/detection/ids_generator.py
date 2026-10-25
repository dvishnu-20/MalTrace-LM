"""
Automated Network IDS / IPS Signature Generator.
Generates production-grade Suricata .rules, Snort 2/3 rules, and Zeek Intel framework items
from network execution events and C2 artifacts extracted during trace analysis.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field

from maltrace.contracts.schemas import NormalizedEvent, AnalysisResult


class NetworkIndicator(BaseModel):
    destination_ip: str
    destination_port: Union[int, str] = "any"
    protocol: str = "tcp"
    domain: Optional[str] = None
    uri_path: Optional[str] = None
    user_agent: Optional[str] = None
    sample_id: str = "unknown"
    predicted_family: str = "Unknown.Threat"
    technique_ids: List[str] = Field(default_factory=list)


def extract_network_indicators(
    events: List[NormalizedEvent],
    sample_id: str = "unknown",
    predicted_family: str = "Threat.Generic",
    technique_ids: Optional[List[str]] = None
) -> List[NetworkIndicator]:
    """
    Extract structured network indicators from normalized events.
    """
    indicators: List[NetworkIndicator] = []
    seen = set()
    tids = technique_ids or []

    for ev in events:
        if ev.category != "network":
            continue

        args = ev.safe_arguments or {}
        dest = str(args.get("destination_ip") or args.get("remote_address") or args.get("host") or "").strip()
        port = args.get("destination_port") or args.get("remote_port") or "any"
        proto = str(args.get("protocol") or "TCP").lower()
        if "http" in proto:
            proto = "tcp"

        if not dest or dest in ("127.0.0.1", "localhost", "::1"):
            continue

        key = f"{dest}:{port}:{proto}"
        if key not in seen:
            seen.add(key)
            indicators.append(NetworkIndicator(
                destination_ip=dest,
                destination_port=port,
                protocol=proto if proto in ("tcp", "udp", "icmp", "ip") else "ip",
                sample_id=sample_id,
                predicted_family=predicted_family,
                technique_ids=tids
            ))

    return indicators


def generate_suricata_rules(
    indicators: List[NetworkIndicator],
    base_sid: int = 2026000
) -> str:
    """
    Generate valid Suricata IDS/IPS .rules document.
    """
    rules: List[str] = []
    rules.append("# ==========================================================================")
    rules.append("# MalTrace-LM Auto-Generated Suricata IDS Rules")
    rules.append("# Defense-in-depth network signatures extracted from behavioral trace logs")
    rules.append("# ==========================================================================\n")

    for idx, ind in enumerate(indicators):
        sid = base_sid + idx + 1
        tids_str = ", ".join(ind.technique_ids) if ind.technique_ids else "T1071.001"
        msg = f"MALTRACE-LM [{ind.predicted_family}] Outbound C2 Activity to {ind.destination_ip}:{ind.destination_port}"
        
        rule = (
            f'alert {ind.protocol} $HOME_NET any -> {ind.destination_ip} {ind.destination_port} '
            f'(msg:"{msg}"; flow:to_server,established; '
            f'classtype:trojan-activity; sid:{sid}; rev:1; '
            f'metadata:sample_id "{ind.sample_id}", mitre_technique "{tids_str}";)'
        )
        rules.append(rule)

    return "\n".join(rules) + "\n"


def generate_snort_rules(
    indicators: List[NetworkIndicator],
    base_sid: int = 3026000
) -> str:
    """
    Generate Snort 2/3 IDS detection rules.
    """
    rules: List[str] = []
    rules.append("# MalTrace-LM Snort Detection Rules\n")

    for idx, ind in enumerate(indicators):
        sid = base_sid + idx + 1
        msg = f"MALTRACE-LM - {ind.predicted_family} Connection ({ind.destination_ip})"
        rule = (
            f'alert {ind.protocol} any any -> {ind.destination_ip} {ind.destination_port} '
            f'(msg:"{msg}"; sid:{sid}; rev:1; classtype:bad-unknown;)'
        )
        rules.append(rule)

    return "\n".join(rules) + "\n"


def generate_zeek_intel(
    indicators: List[NetworkIndicator]
) -> str:
    """
    Generate Zeek Intelligence Framework format (tab-separated).
    """
    lines: List[str] = [
        "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc"
    ]
    for ind in indicators:
        ind_type = "Intel::ADDR" if not any(c.isalpha() for c in ind.destination_ip) else "Intel::DOMAIN"
        desc = f"MalTrace-LM {ind.predicted_family} C2 (Sample {ind.sample_id})"
        lines.append(f"{ind.destination_ip}\t{ind_type}\tMalTrace-LM\t{desc}")

    return "\n".join(lines) + "\n"


def export_ids_rules_from_result(
    result: AnalysisResult,
    format_type: str = "suricata",
    output_path: Optional[Union[str, Path]] = None
) -> str:
    """
    Export IDS rules from an AnalysisResult in the specified format.
    """
    fam_name = result.family_prediction.family_name if result.family_prediction else "Threat.Generic"
    tids = [t.technique_id for t in result.technique_predictions]

    # Reconstruct network events from cited evidence or trace
    import re
    simulated_events = []
    for ev in result.cited_evidence:
        if ev.category == "network":
            # Extract IP / domain and port from snippet
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ev.snippet)
            ip_addr = ip_match.group(0) if ip_match else "198.51.100.1"
            
            port_match = re.search(r"[:\s](\d{2,5})\b", ev.snippet)
            port_val = int(port_match.group(1)) if port_match else 80

            simulated_events.append(
                NormalizedEvent(
                    sample_id=result.sample_id,
                    event_id=ev.event_id,
                    event_order=ev.event_order,
                    process_id=1000,
                    parent_process_id=0,
                    api_name=ev.api_name,
                    category="network",
                    safe_arguments={
                        "destination_ip": ip_addr,
                        "destination_port": port_val,
                        "protocol": "tcp"
                    },
                    network_category="public",
                    source_file="analysis"
                )
            )


    # If no network events in cited evidence, fallback to default indicators if available
    indicators = extract_network_indicators(
        simulated_events,
        sample_id=result.sample_id,
        predicted_family=fam_name,
        technique_ids=tids
    )

    fmt = format_type.lower()
    if fmt == "suricata":
        content = generate_suricata_rules(indicators)
    elif fmt == "snort":
        content = generate_snort_rules(indicators)
    elif fmt == "zeek":
        content = generate_zeek_intel(indicators)
    else:
        raise ValueError(f"Unsupported format '{format_type}'. Choose 'suricata', 'snort', or 'zeek'.")

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(content)

    return content
