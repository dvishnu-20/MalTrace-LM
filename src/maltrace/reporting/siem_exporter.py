"""
SIEM, TIP & Webhook Alert Exporter.
Converts AnalysisResult objects into production schemas for:
- Splunk HTTP Event Collector (HEC)
- Elastic Common Schema (ECS v8.x)
- MISP Threat Event JSON
- STIX 2.1 Threat Report Bundle
- Slack / Microsoft Teams Alert Webhook Dispatcher
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import urllib.request
import urllib.error

from maltrace.contracts.schemas import AnalysisResult


def _get_analysis_id(result: AnalysisResult) -> str:
    return getattr(result, "analysis_id", None) or (result.manifest.run_id if result.manifest else f"ana_{result.sample_id}")


def _get_behavior_summary(result: AnalysisResult) -> str:
    return getattr(result, "behavior_summary", None) or (result.family_prediction.rule_triggered if result.family_prediction else f"Behavioral trace analyzed for {result.sample_id}.")


def export_splunk_hec(result: AnalysisResult) -> Dict[str, Any]:
    """
    Format analysis result as a Splunk HTTP Event Collector (HEC) payload.
    """
    fam_name = result.family_prediction.family_name if result.family_prediction else "Unknown"
    fam_conf = result.family_prediction.confidence if result.family_prediction else 0.0

    tids = [t.technique_id for t in result.technique_predictions]
    tnames = [f"{t.technique_id}: {t.technique_name}" for t in result.technique_predictions]
    aid = _get_analysis_id(result)

    return {
        "time": int(time.time()),
        "host": "maltrace-engine",
        "source": "maltrace-lm",
        "sourcetype": "maltrace:threat:analysis",
        "event": {
            "analysis_id": aid,
            "sample_id": result.sample_id,
            "malware_family": fam_name,
            "confidence_score": fam_conf,
            "threat_severity": "critical" if fam_conf >= 0.8 else "high" if fam_conf >= 0.6 else "medium",
            "mitre_technique_ids": tids,
            "mitre_techniques": tnames,
            "total_evidence_events": len(result.cited_evidence),
            "evidence_snippets": [
                {
                    "event_id": ev.event_id,
                    "api": ev.api_name,
                    "category": ev.category,
                    "snippet": ev.snippet
                } for ev in result.cited_evidence[:10]
            ],
            "behavior_summary": _get_behavior_summary(result)
        }
    }


def export_elastic_ecs(result: AnalysisResult) -> Dict[str, Any]:
    """
    Format analysis result according to Elastic Common Schema (ECS v8.x) standards.
    """
    fam_name = result.family_prediction.family_name if result.family_prediction else "Generic"
    fam_conf = result.family_prediction.confidence if result.family_prediction else 0.0
    aid = _get_analysis_id(result)

    techniques = []
    tactics = set()
    for t in result.technique_predictions:
        tactics.add(t.tactic)
        techniques.append({
            "id": t.technique_id,
            "name": t.technique_name,
            "reference": f"https://attack.mitre.org/techniques/{t.technique_id.replace('.', '/')}"
        })

    return {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": {
            "kind": "alert",
            "category": ["malware", "threat"],
            "type": ["info"],
            "outcome": "success",
            "module": "maltrace",
            "dataset": "maltrace.behavioral_analysis",
            "action": "trace_analyzed"
        },
        "rule": {
            "name": f"MalTrace Detection: {fam_name}",
            "id": aid
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "name": sorted(list(tactics))
            },
            "technique": techniques
        },
        "malware": {
            "name": fam_name,
            "type": fam_name.split(".")[0] if "." in fam_name else "malware"
        },
        "labels": {
            "sample_id": result.sample_id,
            "confidence": str(fam_conf)
        },
        "message": f"MalTrace-LM detected {fam_name} (Confidence {fam_conf*100:.1f}%) on sample {result.sample_id}."
    }


def export_misp_event(result: AnalysisResult) -> Dict[str, Any]:
    """
    Format analysis result as a MISP (Malware Information Sharing Platform) event object.
    """
    fam_name = result.family_prediction.family_name if result.family_prediction else "Malware"
    attributes = []

    # Add MISP attributes for cited evidence
    for idx, ev in enumerate(result.cited_evidence):
        attributes.append({
            "type": "text",
            "category": "Antivirus detection",
            "value": f"{ev.api_name} -> {ev.snippet}",
            "comment": f"MalTrace Evidence Event {ev.event_id} ({ev.category})"
        })

    tags = [{"name": f"maltrace:family=\"{fam_name}\""}]
    for t in result.technique_predictions:
        tags.append({"name": f"misp-galaxy:mitre-attack-pattern=\"{t.technique_name} - {t.technique_id}\""})

    return {
        "Event": {
            "info": f"MalTrace-LM Behavioral Analysis - {result.sample_id} ({fam_name})",
            "threat_level_id": "1",  # High
            "analysis": "2",        # Completed
            "distribution": "0",    # Your organisation only
            "Attribute": attributes,
            "Tag": tags
        }
    }


def export_stix_bundle(result: AnalysisResult) -> Dict[str, Any]:
    """
    Generate a STIX 2.1 JSON bundle representing the analyzed threat.
    """
    fam_name = result.family_prediction.family_name if result.family_prediction else "Unknown Malware"
    fam_id = f"malware--{abs(hash(fam_name)) % 10000000:08d}"
    aid = _get_analysis_id(result)

    objects: List[Dict[str, Any]] = []

    # 1. Malware SDO
    objects.append({
        "type": "malware",
        "spec_version": "2.1",
        "id": fam_id,
        "name": fam_name,
        "is_family": True,
        "description": f"Malware family identified by MalTrace-LM for sample {result.sample_id}."
    })

    # 2. Attack Pattern SDOs & Relationships
    for t in result.technique_predictions:
        ap_id = f"attack-pattern--{t.technique_id.lower().replace('.', '-')}"
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "name": t.technique_name,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": t.technique_id
                }
            ]
        })
        # Relationship
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{abs(hash(fam_id + ap_id)) % 10000000:08d}",
            "relationship_type": "uses",
            "source_ref": fam_id,
            "target_ref": ap_id
        })

    # 3. Report SDO
    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{abs(hash(aid)) % 10000000:08d}",
        "name": f"MalTrace Analysis Report: {result.sample_id}",
        "published": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "object_refs": [obj["id"] for obj in objects]
    })

    return {
        "type": "bundle",
        "id": f"bundle--{abs(hash(aid + 'bundle')) % 10000000:08d}",
        "objects": objects
    }



def export_siem_format(
    result: AnalysisResult,
    format_type: str = "splunk",
    output_path: Optional[Union[str, Path]] = None
) -> Dict[str, Any]:
    """
    Main entrypoint for exporting an AnalysisResult to SIEM / TIP schemas.
    """
    fmt = format_type.lower().strip()
    if fmt == "splunk":
        data = export_splunk_hec(result)
    elif fmt == "ecs":
        data = export_elastic_ecs(result)
    elif fmt == "misp":
        data = export_misp_event(result)
    elif fmt in ("stix", "stix2"):
        data = export_stix_bundle(result)
    else:
        raise ValueError(f"Unsupported format '{format_type}'. Choose 'splunk', 'ecs', 'misp', or 'stix'.")

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    return data


def dispatch_webhook_alert(
    result: AnalysisResult,
    webhook_url: str,
    channel: str = "slack"
) -> bool:
    """
    Send an automated alert notification with evidence highlights to a Slack/Teams webhook.
    """
    fam_name = result.family_prediction.family_name if result.family_prediction else "Unknown Threat"
    conf = result.family_prediction.confidence if result.family_prediction else 0.0

    tids = [t.technique_id for t in result.technique_predictions]
    tids_str = ", ".join(tids) if tids else "None"

    if channel.lower() == "slack":
        payload = {
            "text": f":rotating_light: *MalTrace-LM Threat Alert: {fam_name} Detected*",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 MalTrace Threat Detection: {fam_name}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Sample ID:*\n`{result.sample_id}`"},
                        {"type": "mrkdwn", "text": f"*Confidence:*\n`{conf*100:.1f}%`"},
                        {"type": "mrkdwn", "text": f"*ATT&CK Techniques:*\n`{tids_str}`"},
                        {"type": "mrkdwn", "text": f"*Evidence Count:*\n`{len(result.cited_evidence)} events`"}
                    ]
                }
            ]
        }
    else:
        # Generic / Teams JSON payload
        payload = {
            "title": f"MalTrace Alert: {fam_name}",
            "text": f"Sample `{result.sample_id}` flagged as `{fam_name}` with {conf*100:.1f}% confidence. ATT&CK: {tids_str}"
        }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status in (200, 204)
    except Exception:
        return False
