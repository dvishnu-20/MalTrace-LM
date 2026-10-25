"""
Trace-to-language renderer module.
Renders normalized events into controlled natural language behavior statements using only observed fields,
substituting explicit neutral phrases when fields are absent.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from maltrace.contracts.schemas import NormalizedEvent, BehaviorStatement
from maltrace.representation.anchors import evaluate_security_anchors

logger = logging.getLogger(__name__)

# Load behavior vocabulary JSON definition
VOCAB_PATH = Path(__file__).parent / "vocabulary.json"

def load_vocabulary() -> Dict[str, Any]:
    with open(VOCAB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


_VOCAB_CACHE: Optional[Dict[str, Any]] = None

def get_vocabulary() -> Dict[str, Any]:
    global _VOCAB_CACHE
    if _VOCAB_CACHE is None:
        _VOCAB_CACHE = load_vocabulary()
    return _VOCAB_CACHE


def map_event_to_vocab_category(event: NormalizedEvent) -> str:
    """
    Map normalized event category & API features to one of the 12 vocabulary categories.
    """
    args_str = str(event.safe_arguments).lower()
    api_lower = event.api_name.lower()

    if ("vssadmin" in args_str and "delete" in args_str) or "bcdedit" in args_str:
        return "defense_impairment"

    if any(p in args_str or p in api_lower for p in ["logindata", "web data", "cookies", "vault", "passwords.txt"]):
        return "credential_access"

    if event.is_persistence or (event.category == "registry" and any(k in args_str for k in ["run", "runonce", "startup"])):
        return "startup_persistence"

    if event.category == "service" or "service" in api_lower:
        return "service_changes"

    if any(p in args_str or p in api_lower for p in ["powershell", "cmd.exe", "wscript", "cscript"]):
        return "command_interpreters"

    if event.category == "memory" or any(k in api_lower for k in ["virtualalloc", "writeprocessmemory", "createremotethread", "unmapview"]):
        return "injection_activity"

    if event.category == "network":
        return "network_connections"

    if any(ext in args_str for ext in [".zip", ".rar", ".7z", ".tar", ".gz"]):
        return "archive_activity"

    if event.category == "registry":
        return "registry_changes"

    if any(k in api_lower for k in ["query", "enum", "find"]) or "desired_access" in event.safe_arguments:
        return "discovery"

    if event.category == "process":
        return "process_execution"

    return "file_operations"


def render_event_statement(event: NormalizedEvent, vocab_dict: Optional[Dict[str, Any]] = None) -> BehaviorStatement:
    """
    Render a single NormalizedEvent into a BehaviorStatement with controlled phrase and metadata.
    """
    if vocab_dict is None:
        vocab_dict = get_vocabulary()

    cat_name = map_event_to_vocab_category(event)
    categories = vocab_dict.get("categories", {})
    entry = categories.get(cat_name, categories.get("file_operations", {}))

    template: str = entry.get("template", "Process {process_name} (PID {process_id}) executed action {api_name}.")
    severity: str = entry.get("severity_hint", "info")
    candidate_techniques: List[str] = entry.get("candidate_attack_techniques", [])

    # Extract observed fields with explicit neutral placeholders for missing fields
    safe = event.safe_arguments
    process_name = safe.get("process_name") or safe.get("image_name")
    if process_name:
        p_name = str(process_name).replace("/", "\\").split("\\")[-1]
    else:
        p_name = f"proc_{event.process_id}.exe"

    target_path = safe.get("target_path") or safe.get("path") or safe.get("file") or "<unspecified path>"
    target_image = safe.get("image_name") or safe.get("path") or "<unspecified target>"
    command_line = safe.get("command_line") or "<unspecified command_line>"
    registry_key = safe.get("registry_key") or safe.get("key") or "<unspecified registry_key>"
    value_name = safe.get("value_name") or "<unspecified value_name>"
    value_data = safe.get("value_data") or safe.get("value") or "<unspecified value_data>"
    service_name = safe.get("service_name") or "<unspecified service_name>"
    binary_path = safe.get("binary_path") or safe.get("image_name") or "<unspecified binary_path>"
    destination_ip = safe.get("destination_ip") or safe.get("ip") or safe.get("host") or "<unspecified destination_ip>"
    destination_port = str(safe.get("destination_port") or safe.get("port") or "<unspecified port>")
    protocol = safe.get("protocol") or safe.get("type") or "<unspecified protocol>"
    interpreter_name = p_name if p_name in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"] else (safe.get("image_name") or "<unspecified interpreter>")

    # Interpolate template using dict format
    fmt_map = {
        "process_name": p_name,
        "process_id": str(event.process_id),
        "target_image": str(target_image),
        "command_line": str(command_line),
        "interpreter_name": str(interpreter_name),
        "api_action": event.api_name,
        "api_name": event.api_name,
        "target_path": str(target_path),
        "registry_key": str(registry_key),
        "value_name": str(value_name),
        "value_data": str(value_data),
        "service_name": str(service_name),
        "binary_path": str(binary_path),
        "destination_ip": str(destination_ip),
        "destination_port": str(destination_port),
        "network_category": event.network_category or "unknown",
        "protocol": str(protocol)
    }

    try:
        phrase = template.format(**fmt_map)
    except KeyError as e:
        missing_key = str(e).strip("'")
        fmt_map[missing_key] = f"<unspecified {missing_key}>"
        phrase = template.format(**fmt_map)

    if event.repeat_count > 1:
        phrase += f" (Repeated {event.repeat_count} times)"

    # Evaluate security anchor rules
    anchor_rules = evaluate_security_anchors(event)

    stmt_id = f"stmt_{event.event_id}"

    evidence_meta = {
        "sample_id": event.sample_id,
        "process_id": event.process_id,
        "parent_process_id": event.parent_process_id,
        "event_id": event.event_id,
        "event_order": event.event_order,
        "source_category": event.category,
        "repeat_count": event.repeat_count,
        "deterministic_hash": event.deterministic_hash
    }

    return BehaviorStatement(
        statement_id=stmt_id,
        sample_id=event.sample_id,
        process_id=event.process_id,
        event_id=event.event_id,
        event_order=event.event_order,
        category=cat_name,
        severity=severity,
        rendered_phrase=phrase,
        anchor_rules=anchor_rules,
        candidate_attack_techniques=candidate_techniques,
        evidence_metadata=evidence_meta
    )


def render_trace_statements(events: List[NormalizedEvent]) -> List[BehaviorStatement]:
    """
    Render a list of normalized events into behavior statements.
    """
    vocab = get_vocabulary()
    return [render_event_statement(evt, vocab) for evt in events]
