"""
Adapter interfaces and section extractors for Windows execution trace report formats.
Supports graceful extraction when fields are absent or named differently,
issuing warnings for unknown sections without crashing.
"""

from typing import Dict, Any, List, Tuple, Optional
import logging
from pathlib import Path
from maltrace.contracts.schemas import RawEvent

logger = logging.getLogger(__name__)

# Standard known top-level report sections
KNOWN_REPORT_SECTIONS = {
    "sample_id",
    "events",
    "behavior",
    "processes",
    "calls",
    "network",
    "signatures",
    "target",
    "target_metadata",
    "metadata",
    "info",
    "labels",
    "label",
    "family",
    "malware_family",
    "schema_version",
    "summary"
}


class ReportAdapter:
    """
    Adapter interface to normalize diverse execution report structures into RawEvent list + metadata.
    """

    @staticmethod
    def extract(
        data: Any,
        source_file: str = "unknown.json",
        benchmark_mode: bool = False
    ) -> Tuple[str, Optional[str], List[RawEvent], List[str]]:
        """
        Extract sample_id, label, list of RawEvent, and list of warning strings from report data.
        In benchmark_mode=True, filename-based label inference is strictly disabled.
        """
        warnings: List[str] = []
        raw_events: List[RawEvent] = []
        sample_id = Path(source_file).stem
        label: Optional[str] = None

        if isinstance(data, list):
            # Direct event list format: [...]
            raw_events = ReportAdapter._parse_event_list(data, sample_id, source_file)
            return sample_id, label, raw_events, warnings

        if not isinstance(data, dict):
            warnings.append(f"Invalid root JSON structure in {source_file}: expected dict or list, got {type(data).__name__}")
            return sample_id, label, [], warnings

        # Track unknown sections
        for key in data.keys():
            if key.lower() not in KNOWN_REPORT_SECTIONS:
                warnings.append(f"Ignored unknown section: '{key}'")

        # Extract sample_id
        if "sample_id" in data:
            sample_id = str(data["sample_id"])
        elif "info" in data and isinstance(data["info"], dict) and "id" in data["info"]:
            sample_id = str(data["info"]["id"])
        elif "target" in data and isinstance(data["target"], dict) and "name" in data["target"]:
            sample_id = str(data["target"]["name"])
        elif "target_metadata" in data and isinstance(data["target_metadata"], dict) and "sample_id" in data["target_metadata"]:
            sample_id = str(data["target_metadata"]["sample_id"])

        # Extract label/family
        if "family" in data:
            label = str(data["family"])
        elif "label" in data:
            label = str(data["label"])
        elif "malware_family" in data:
            label = str(data["malware_family"])
        elif "labels" in data and isinstance(data["labels"], list) and data["labels"]:
            label = str(data["labels"][0])
        elif "info" in data and isinstance(data["info"], dict) and "family" in data["info"]:
            label = str(data["info"]["family"])

        # Filename inference is strictly forbidden in benchmark mode to preserve scientific evaluation integrity
        if not label and not benchmark_mode:
            sid_lower = (sample_id + "_" + Path(source_file).stem).lower()
            if "wannacry" in sid_lower or "ransomware" in sid_lower:
                label = "Ransomware.WannaCry"
            elif "redline" in sid_lower or "infostealer" in sid_lower or "stealer" in sid_lower:
                label = "Stealer.RedLine"
            elif "asyncrat" in sid_lower or "trojan" in sid_lower:
                label = "Trojan.AsyncRAT"
            elif "emotet" in sid_lower or "dropper" in sid_lower:
                label = "Dropper.Emotet"
            elif "xmrig" in sid_lower or "coinminer" in sid_lower:
                label = "Coinminer.XMRig"
            elif "notepad" in sid_lower or "benign" in sid_lower:
                label = "Benign.Activity"

        # Extract events from various possible locations
        events_list: List[Any] = []
        if "events" in data and isinstance(data["events"], list):
            events_list = data["events"]
        elif "calls" in data and isinstance(data["calls"], list):
            events_list = data["calls"]
        elif "behavior" in data and isinstance(data["behavior"], dict):
            behavior = data["behavior"]
            if "processes" in behavior and isinstance(behavior["processes"], list):
                # Cuckoo style: behavior.processes -> array of process dicts with "calls"
                for proc in behavior["processes"]:
                    if isinstance(proc, dict):
                        pid = proc.get("process_id") or proc.get("pid", 1000)
                        ppid = proc.get("parent_id") or proc.get("ppid", 0)
                        pname = proc.get("process_name") or proc.get("name", "unknown.exe")
                        calls = proc.get("calls", [])
                        if isinstance(calls, list):
                            for call in calls:
                                if isinstance(call, dict):
                                    call_item = dict(call)
                                    call_item.setdefault("process_id", pid)
                                    call_item.setdefault("parent_process_id", ppid)
                                    call_item.setdefault("process_name", pname)
                                    events_list.append(call_item)
            elif "generic" in behavior and isinstance(behavior["generic"], list):
                events_list = behavior["generic"]
            elif "summary" in behavior and isinstance(behavior["summary"], list):
                events_list = behavior["summary"]
        elif "processes" in data and isinstance(data["processes"], list):
            for proc in data["processes"]:
                if isinstance(proc, dict) and "calls" in proc and isinstance(proc["calls"], list):
                    pid = proc.get("process_id") or proc.get("pid", 1000)
                    ppid = proc.get("parent_id") or proc.get("ppid", 0)
                    for call in proc["calls"]:
                        if isinstance(call, dict):
                            call_item = dict(call)
                            call_item.setdefault("process_id", pid)
                            call_item.setdefault("parent_process_id", ppid)
                            events_list.append(call_item)

        raw_events = ReportAdapter._parse_event_list(events_list, sample_id, source_file)
        return sample_id, label, raw_events, warnings

    @staticmethod
    def _parse_event_list(events_list: List[Any], sample_id: str, source_file: str) -> List[RawEvent]:
        raw_events: List[RawEvent] = []
        for idx, item in enumerate(events_list):
            if not isinstance(item, dict):
                continue

            event_id = str(item.get("event_id", item.get("id", f"evt_{idx + 1:04d}")))
            event_order = item.get("event_order", item.get("order", idx + 1))
            process_id = item.get("process_id", item.get("pid", 1000))
            parent_pid = item.get("parent_process_id", item.get("ppid", item.get("parent_id", 0)))
            timestamp = item.get("timestamp", item.get("time", item.get("date")))
            api_name = item.get("api_name", item.get("action", item.get("api", item.get("category", "UnknownAPI"))))

            args = item.get("arguments", item.get("args", item.get("params", {})))
            if not isinstance(args, dict):
                args = {"raw_value": str(args)}
            else:
                args = dict(args)

            # Copy top-level process_name/target_path into arguments if missing
            for extra_key in ["process_name", "target_path", "registry_key", "destination_ip", "service_name", "command_line", "image_name"]:
                if extra_key in item and extra_key not in args:
                    args[extra_key] = item[extra_key]

            try:
                p_id = int(process_id)
            except (ValueError, TypeError):
                p_id = 1000

            try:
                pp_id = int(parent_pid)
            except (ValueError, TypeError):
                pp_id = 0

            try:
                e_order = int(event_order)
            except (ValueError, TypeError):
                e_order = idx + 1

            raw_events.append(
                RawEvent(
                    sample_id=sample_id,
                    event_id=event_id,
                    event_order=e_order,
                    process_id=p_id,
                    parent_process_id=pp_id,
                    timestamp=str(timestamp) if timestamp is not None else None,
                    api_name=str(api_name),
                    arguments=args,
                    source_file=source_file,
                    schema_version="1.0.0"
                )
            )

        return raw_events
