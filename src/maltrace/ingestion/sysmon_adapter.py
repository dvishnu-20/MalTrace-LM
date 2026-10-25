"""
Sysmon XML & Windows Event Log Ingestion Adapter.
Parses native Windows Sysmon XML and JSON event exports (Event IDs 1, 3, 7, 8, 11, 12, 13, 22)
and translates them into canonical RawTrace / RawEvent schemas for end-to-end analysis.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

from maltrace.contracts.schemas import RawEvent, RawTrace


def _extract_sysmon_event_data(event_elem: ET.Element) -> Dict[str, str]:
    """
    Extract key-value pairs from Sysmon <EventData><Data Name="...">value</Data> structure.
    """
    data: Dict[str, str] = {}
    for elem in event_elem.iter():
        if elem.tag.endswith("Data") and "Name" in elem.attrib:
            data[elem.attrib["Name"]] = elem.text or ""
    return data


def _map_sysmon_event_to_raw_event(
    event_id_num: int,
    data: Dict[str, str],
    order: int,
    sample_id: str,
    timestamp: Optional[str] = None
) -> Optional[RawEvent]:
    """
    Map a single Sysmon Event ID and its field dictionary to a MalTrace RawEvent.
    """
    pid = int(data.get("ProcessId") or data.get("SourceProcessId") or 1000)
    ppid = int(data.get("ParentProcessId") or 0)
    ts = timestamp or data.get("UtcTime") or "2026-08-28T00:00:00Z"

    # Event ID 1: Process Creation
    if event_id_num == 1:
        return RawEvent(
            sample_id=sample_id,
            event_id=f"sysmon_{order:04d}",
            event_order=order,
            process_id=pid,
            parent_process_id=ppid,
            timestamp=ts,
            api_name="CreateProcessInternalW",
            arguments={
                "image_name": data.get("Image", "unknown.exe"),
                "command_line": data.get("CommandLine", ""),
                "current_directory": data.get("CurrentDirectory", ""),
                "user": data.get("User", "")
            }
        )

    # Event ID 3: Network Connection
    elif event_id_num == 3:
        return RawEvent(
            sample_id=sample_id,
            event_id=f"sysmon_{order:04d}",
            event_order=order,
            process_id=pid,
            parent_process_id=ppid,
            timestamp=ts,
            api_name="WSAConnect",
            arguments={
                "destination_ip": data.get("DestinationIp", ""),
                "destination_port": int(data.get("DestinationPort", 0)) if data.get("DestinationPort", "").isdigit() else 0,
                "protocol": data.get("Protocol", "tcp"),
                "source_ip": data.get("SourceIp", ""),
                "image_name": data.get("Image", "")
            }
        )

    # Event ID 7: Image Loaded (DLL Load)
    elif event_id_num == 7:
        return RawEvent(
            sample_id=sample_id,
            event_id=f"sysmon_{order:04d}",
            event_order=order,
            process_id=pid,
            parent_process_id=ppid,
            timestamp=ts,
            api_name="LoadLibraryW",
            arguments={
                "image_loaded": data.get("ImageLoaded", ""),
                "image_name": data.get("Image", ""),
                "is_signed": data.get("Signed", "")
            }
        )

    # Event ID 8: CreateRemoteThread (Injection)
    elif event_id_num == 8:
        target_pid = int(data.get("TargetProcessId", 0)) if data.get("TargetProcessId", "").isdigit() else pid
        return RawEvent(
            sample_id=sample_id,
            event_id=f"sysmon_{order:04d}",
            event_order=order,
            process_id=pid,
            parent_process_id=ppid,
            timestamp=ts,
            api_name="CreateRemoteThread",
            arguments={
                "target_process_id": target_pid,
                "start_address": data.get("StartAddress", ""),
                "source_image": data.get("SourceImage", ""),
                "target_image": data.get("TargetImage", "")
            }
        )

    # Event ID 11: File Created
    elif event_id_num == 11:
        return RawEvent(
            sample_id=sample_id,
            event_id=f"sysmon_{order:04d}",
            event_order=order,
            process_id=pid,
            parent_process_id=ppid,
            timestamp=ts,
            api_name="NtCreateFile",
            arguments={
                "target_path": data.get("TargetFilename", ""),
                "image_name": data.get("Image", "")
            }
        )

    # Event ID 12/13/14: Registry Modification
    elif event_id_num in (12, 13, 14):
        return RawEvent(
            sample_id=sample_id,
            event_id=f"sysmon_{order:04d}",
            event_order=order,
            process_id=pid,
            parent_process_id=ppid,
            timestamp=ts,
            api_name="RegSetValueExW" if event_id_num != 14 else "RegDeleteKeyW",
            arguments={
                "registry_key": data.get("TargetObject", ""),
                "value_data": data.get("Details", ""),
                "event_type": data.get("EventType", "")
            }
        )

    # Event ID 22: DNS Query
    elif event_id_num == 22:
        return RawEvent(
            sample_id=sample_id,
            event_id=f"sysmon_{order:04d}",
            event_order=order,
            process_id=pid,
            parent_process_id=ppid,
            timestamp=ts,
            api_name="WSAConnect",
            arguments={
                "remote_address": data.get("QueryName", ""),
                "query_results": data.get("QueryResults", ""),
                "image_name": data.get("Image", "")
            }
        )

    return None


def parse_sysmon_xml(
    xml_input: Union[str, Path],
    sample_id: Optional[str] = None
) -> RawTrace:
    """
    Parse a Sysmon XML export file or raw XML string into a canonical RawTrace object.
    """
    if isinstance(xml_input, Path) or (isinstance(xml_input, str) and (xml_input.endswith(".xml") or Path(xml_input).exists())):
        tree = ET.parse(xml_input)
        root = tree.getroot()
        sid = sample_id or Path(xml_input).stem
    else:
        root = ET.fromstring(xml_input)
        sid = sample_id or "sysmon_sample_01"

    events: List[RawEvent] = []
    order = 1

    # Find all Event elements
    for event_elem in root.iter():
        if event_elem.tag.endswith("Event"):
            # Extract System -> EventID
            sys_elem = None
            for child in event_elem:
                if child.tag.endswith("System"):
                    sys_elem = child
                    break

            event_id_num = 0
            ts_str = None
            if sys_elem is not None:
                for s_child in sys_elem:
                    if s_child.tag.endswith("EventID"):
                        try:
                            event_id_num = int(s_child.text or "0")
                        except ValueError:
                            pass
                    elif s_child.tag.endswith("TimeCreated") and "SystemTime" in s_child.attrib:
                        ts_str = s_child.attrib["SystemTime"]

            data = _extract_sysmon_event_data(event_elem)
            if event_id_num > 0:
                raw_evt = _map_sysmon_event_to_raw_event(event_id_num, data, order, sid, ts_str)
                if raw_evt:
                    events.append(raw_evt)
                    order += 1

    return RawTrace(
        sample_id=sid,
        events=events,
        source_format="sysmon_xml"
    )


def parse_sysmon_json(
    json_input: Union[str, Path, List[Dict[str, Any]]],
    sample_id: Optional[str] = None
) -> RawTrace:
    """
    Parse Sysmon JSON event streams (e.g. from Winlogbeat / Splunk export).
    """
    if isinstance(json_input, (str, Path)) and Path(str(json_input)).exists():
        with open(json_input, "r", encoding="utf-8") as f:
            data = json.load(f)
        sid = sample_id or Path(json_input).stem
    elif isinstance(json_input, str):
        data = json.loads(json_input)
        sid = sample_id or "sysmon_json_01"
    else:
        data = json_input
        sid = sample_id or "sysmon_json_01"

    if isinstance(data, dict) and "events" in data:
        data = data["events"]

    events: List[RawEvent] = []
    order = 1

    for idx, item in enumerate(data):
        eid = int(item.get("event_id") or item.get("EventID") or item.get("winlog", {}).get("event_id", 0))
        event_data = item.get("event_data") or item.get("data") or item
        ts = item.get("@timestamp") or item.get("timestamp") or item.get("UtcTime")

        raw_evt = _map_sysmon_event_to_raw_event(eid, event_data, order, sid, ts)
        if raw_evt:
            events.append(raw_evt)
            order += 1

    return RawTrace(
        sample_id=sid,
        events=events,
        source_format="sysmon_json"
    )
