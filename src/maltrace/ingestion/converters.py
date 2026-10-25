"""
External dataset schema converters.
Translates external dataset formats (OTRF / OSSEM Sysmon, WinMET API sequences, CAPE sandbox)
into canonical MalTrace NormalizedEvent format.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import json
import orjson


def convert_otrf_sysmon(
    input_source: Union[str, Path, List[Dict[str, Any]]],
    output_path: Optional[Union[str, Path]] = None,
    sample_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convert OTRF / OSSEM Sysmon event logs into canonical MalTrace trace dictionary.
    Maps Sysmon Event IDs (1=ProcessCreate, 3=NetworkConnect, 7=ImageLoaded, 8=CreateRemoteThread,
    11=FileCreate, 12/13/14=Registry) to canonical APIs.
    """
    raw_events: List[Dict[str, Any]] = []

    if isinstance(input_source, (str, Path)):
        p = Path(input_source)
        if not p.exists():
            raise FileNotFoundError(f"OTRF input file not found: {p}")
        if sample_id is None:
            sample_id = p.stem

        with open(p, "rb") as f:
            content = f.read().strip()
            if content.startswith(b"["):
                raw_events = orjson.loads(content)
            else:
                for line in content.split(b"\n"):
                    if line.strip():
                        raw_events.append(orjson.loads(line))
    else:
        raw_events = list(input_source)
        if sample_id is None:
            sample_id = "otrf_sample"

    events: List[Dict[str, Any]] = []

    for idx, rev in enumerate(raw_events, start=1):
        # Support both nested event_data and flat fields
        ed = rev.get("event_data", rev)
        event_id = str(rev.get("event_id") or rev.get("EventID") or "1")

        pid = int(ed.get("ProcessId") or ed.get("process_id") or 1000)
        ppid = int(ed.get("ParentProcessId") or ed.get("parent_process_id") or 0)
        ts = str(rev.get("timestamp") or rev.get("@timestamp") or "2026-07-28T10:00:00Z")

        api_name = "UnknownAPI"
        args: Dict[str, Any] = {}

        if event_id in ("1", "ProcessCreate"):
            api_name = "CreateProcessInternalW"
            args = {
                "image_name": ed.get("Image") or ed.get("process_path") or "cmd.exe",
                "command_line": ed.get("CommandLine") or ed.get("process_command_line") or "",
                "parent_image": ed.get("ParentImage") or ""
            }
        elif event_id in ("3", "NetworkConnect"):
            api_name = "connect"
            args = {
                "destination_ip": ed.get("DestinationIp") or ed.get("dst_ip") or "127.0.0.1",
                "destination_port": ed.get("DestinationPort") or ed.get("dst_port") or 443,
                "protocol": ed.get("Protocol") or "tcp",
                "image_name": ed.get("Image") or ""
            }
        elif event_id in ("7", "ImageLoaded"):
            api_name = "LoadLibraryW"
            args = {
                "loaded_image": ed.get("ImageLoaded") or ed.get("dll_path") or "",
                "image_name": ed.get("Image") or ""
            }
        elif event_id in ("8", "CreateRemoteThread"):
            api_name = "CreateRemoteThread"
            args = {
                "target_process_id": int(ed.get("TargetProcessId") or 0),
                "start_address": ed.get("StartAddress") or "0x0"
            }
        elif event_id in ("11", "FileCreate"):
            api_name = "NtCreateFile"
            args = {
                "target_path": ed.get("TargetFilename") or ed.get("file_name") or "C:\\temp\\file.txt",
                "desired_access": "GENERIC_WRITE"
            }
        elif event_id in ("12", "13", "14", "RegistryEvent"):
            api_name = "RegSetValueExW"
            args = {
                "target_object": ed.get("TargetObject") or ed.get("registry_key") or "",
                "details": ed.get("Details") or ""
            }
        else:
            api_name = "SystemEvent"
            args = {k: str(v) for k, v in ed.items()}

        events.append({
            "sample_id": sample_id,
            "event_id": f"otrf_evt_{idx:04d}",
            "event_order": idx,
            "process_id": pid,
            "parent_process_id": ppid,
            "timestamp": ts,
            "api_name": api_name,
            "arguments": args
        })

    trace_doc = {
        "sample_id": sample_id,
        "format": "otrf_converted",
        "events": events
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(trace_doc, f, indent=2)

    return trace_doc


def convert_winmet(
    input_source: Union[str, Path, Dict[str, Any]],
    output_path: Optional[Union[str, Path]] = None,
    sample_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convert WinMET API sequence traces into canonical MalTrace format.
    WinMET stores sequential API call records with process identifiers and parameters.
    """
    if isinstance(input_source, (str, Path)):
        p = Path(input_source)
        if not p.exists():
            raise FileNotFoundError(f"WinMET input file not found: {p}")
        if sample_id is None:
            sample_id = p.stem
        with open(p, "rb") as f:
            data = orjson.loads(f.read())
    else:
        data = input_source
        if sample_id is None:
            sample_id = data.get("sample_id", "winmet_sample")

    call_list = data.get("calls", data.get("apis", data.get("events", [])))
    events: List[Dict[str, Any]] = []

    for idx, call in enumerate(call_list, start=1):
        api = call.get("api", call.get("api_name", "NtCreateFile"))
        pid = int(call.get("pid", call.get("process_id", 1000)))
        ppid = int(call.get("ppid", call.get("parent_process_id", 0)))
        args = call.get("args", call.get("arguments", {}))
        if isinstance(args, list):
            args = {f"arg_{i}": v for i, v in enumerate(args)}

        events.append({
            "sample_id": sample_id,
            "event_id": f"winmet_{idx:04d}",
            "event_order": idx,
            "process_id": pid,
            "parent_process_id": ppid,
            "timestamp": f"2026-07-28T10:00:{idx % 60:02d}Z",
            "api_name": api,
            "arguments": args
        })

    trace_doc = {
        "sample_id": sample_id,
        "family": data.get("family", data.get("label")),
        "format": "winmet_converted",
        "events": events
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(trace_doc, f, indent=2)

    return trace_doc


def convert_cape(
    input_source: Union[str, Path, Dict[str, Any]],
    output_path: Optional[Union[str, Path]] = None,
    sample_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convert CAPE / Cuckoo sandbox dynamic execution reports into canonical MalTrace format.
    Extracts behavior.processes and sequential API calls.
    """
    if isinstance(input_source, (str, Path)):
        p = Path(input_source)
        if not p.exists():
            raise FileNotFoundError(f"CAPE input file not found: {p}")
        if sample_id is None:
            sample_id = p.stem
        with open(p, "rb") as f:
            data = orjson.loads(f.read())
    else:
        data = input_source
        if sample_id is None:
            sample_id = data.get("info", {}).get("id", "cape_sample")

    events: List[Dict[str, Any]] = []
    order_idx = 1

    behavior = data.get("behavior", {})
    processes = behavior.get("processes", [])

    for proc in processes:
        pid = int(proc.get("process_id") or proc.get("pid", 1000))
        ppid = int(proc.get("parent_id") or proc.get("ppid", 0))
        calls = proc.get("calls", [])

        for call in calls:
            api = call.get("api", "UnknownAPI")
            args = call.get("arguments", {})
            if isinstance(args, list):
                args = {f"arg_{i}": v for i, v in enumerate(args)}

            events.append({
                "sample_id": sample_id,
                "event_id": f"cape_{order_idx:04d}",
                "event_order": order_idx,
                "process_id": pid,
                "parent_process_id": ppid,
                "timestamp": call.get("timestamp", "2026-07-28T10:00:00Z"),
                "api_name": api,
                "arguments": args
            })
            order_idx += 1

    family = None
    if "info" in data and isinstance(data["info"], dict):
        family = data["info"].get("family")
    if not family and "malware_family" in data:
        family = data["malware_family"]

    trace_doc = {
        "sample_id": sample_id,
        "family": family,
        "format": "cape_converted",
        "events": events
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(trace_doc, f, indent=2)

    return trace_doc
