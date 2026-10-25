"""
Canonical normalization engine for Win32/Native API trace events.
Categorizes APIs, sanitizes path strings, scrubs sensitive usernames,
normalizes registry hives, highlights persistence, classifies network endpoints,
generates deterministic hashes, and collapses consecutive duplicate events.
"""

import re
import json
import hashlib
import ipaddress
from typing import List, Dict, Any, Tuple, Optional
from maltrace.contracts.schemas import RawEvent, NormalizedEvent

# Extended API Category Mapping
API_CATEGORY_MAP: Dict[str, str] = {
    # Process management
    "createprocess": "process",
    "createprocessinternalw": "process",
    "createprocessa": "process",
    "createprocessw": "process",
    "ntcreateuserprocess": "process",
    "winexec": "process",
    "shellexecutew": "process",
    "shellexecutea": "process",
    "terminateprocess": "process",
    "openprocess": "process",

    # Registry management
    "regsetvalueexw": "registry",
    "regsetvalueexa": "registry",
    "regcreatekeyexw": "registry",
    "regcreatekeyexa": "registry",
    "regdeletekeyw": "registry",
    "regqueryvalueexw": "registry",
    "ntsetvaluekey": "registry",
    "ntopenkey": "registry",
    "ntcreatekey": "registry",

    # File system
    "ntcreatefile": "file",
    "createfilew": "file",
    "createfilea": "file",
    "writefile": "file",
    "readfile": "file",
    "deletefilew": "file",
    "movefilew": "file",
    "copyfilew": "file",

    # Network communication
    "wsaconnect": "network",
    "connect": "network",
    "httpsendrequestw": "network",
    "internetopenurlw": "network",
    "winhttpconnect": "network",
    "send": "network",
    "recv": "network",

    # Windows Service management
    "createservicew": "service",
    "createservicea": "service",
    "startservicew": "service",
    "changeserviceconfigw": "service",
    "controlservice": "service",

    # Memory & Process Injection
    "virtualallocex": "memory",
    "writeprocessmemory": "memory",
    "readprocessmemory": "memory",
    "createremotethread": "memory",
    "ntunmapviewofsection": "memory",
    "virtualprotectex": "memory",

    # Synchronization
    "createmutexw": "synchronization",
    "createmutexa": "synchronization",
    "openmutexw": "synchronization",
    "ntcreatemutex": "synchronization",
    "openeventw": "synchronization",
    "ntopenevent": "synchronization",
    "waitforsingleobject": "synchronization",
    "waitformultipleobjects": "synchronization",
    "createsemaphorew": "synchronization",
    "releasesemaphore": "synchronization",
    "ntcreatesection": "synchronization",
    "opensection": "synchronization",
}

# Regex to scrub sensitive usernames from Windows file paths (C:\Users\username -> C:\Users\<USER>)
USER_PATH_REGEX = re.compile(r"(?i)(c:[\/\\]users[\/\\])([^[\/\\]+)", re.IGNORECASE)

# Known Persistence Registry / File keywords
PERSISTENCE_PATTERNS = [
    r"\\software\\microsoft\\windows\\currentversion\\run",
    r"\\software\\microsoft\\windows\\currentversion\\runonce",
    r"\\software\\microsoft\\windows\\currentversion\\winlogon",
    r"\\software\\microsoft\\windows\\currentversion\\explorer\\user shell folders",
    r"\\software\\microsoft\\windows\\currentversion\\explorer\\shell folders",
    r"\\system\\currentcontrolset\\services",
    r"\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
    r"\\start menu\\programs\\startup",
]


def normalize_api_category(api_name: str) -> str:
    """
    Map Win32/Native API name to a canonical behavior category.
    """
    clean_name = api_name.lower().strip()
    if clean_name in API_CATEGORY_MAP:
        return API_CATEGORY_MAP[clean_name]

    # Keyword heuristics
    if any(k in clean_name for k in ["mutex", "event", "semaphore", "waitfor", "section"]):
        return "synchronization"
    if "process" in clean_name or "exec" in clean_name:
        return "process"
    if "reg" in clean_name or "key" in clean_name:
        return "registry"
    if "file" in clean_name or "write" in clean_name or "read" in clean_name:
        return "file"
    if "net" in clean_name or "socket" in clean_name or "http" in clean_name or "connect" in clean_name or "wsa" in clean_name:
        return "network"
    if "service" in clean_name:
        return "service"
    if "mem" in clean_name or "alloc" in clean_name or "thread" in clean_name:
        return "memory"

    return "other"


def sanitize_path_string(text: str) -> str:
    """
    Scrub raw sensitive usernames from Windows paths (e.g. C:\\Users\\analyst -> C:\\Users\\<USER>).
    """
    if not isinstance(text, str):
        return str(text)
    return USER_PATH_REGEX.sub(r"\1<USER>", text)


def categorize_path(path_str: str) -> str:
    """
    Normalize path strings into standard safe categories.
    Categories: system_directory, user_directory, temporary_directory, application_data, startup_location, unknown
    """
    if not path_str or not isinstance(path_str, str):
        return "unknown"

    lower_p = path_str.lower().replace("/", "\\")

    if "startup" in lower_p or "\\run" in lower_p or "\\runonce" in lower_p:
        return "startup_location"
    if "\\temp" in lower_p or "%temp%" in lower_p or "%tmp%" in lower_p or "c:\\windows\\temp" in lower_p:
        return "temporary_directory"
    if "\\appdata\\" in lower_p or "c:\\programdata" in lower_p:
        return "application_data"
    if "c:\\windows" in lower_p or "%systemroot%" in lower_p:
        return "system_directory"
    if "c:\\users\\" in lower_p:
        return "user_directory"

    return "unknown"


def normalize_registry_hive(reg_key: str) -> str:
    """
    Normalize registry hive short names to full names (e.g. HKCU -> HKEY_CURRENT_USER).
    """
    if not reg_key or not isinstance(reg_key, str):
        return reg_key

    replacements = {
        "HKLM\\": "HKEY_LOCAL_MACHINE\\",
        "HKCU\\": "HKEY_CURRENT_USER\\",
        "HKU\\": "HKEY_USERS\\",
        "HKCR\\": "HKEY_CLASSES_ROOT\\",
        "HKCC\\": "HKEY_CURRENT_CONFIG\\",
    }
    normalized = reg_key
    for short_hive, long_hive in replacements.items():
        if normalized.upper().startswith(short_hive):
            normalized = long_hive + normalized[len(short_hive):]
            break
    return normalized


def check_is_persistence(path_or_reg: str) -> bool:
    """
    Check if a registry key or path touches known Windows persistence locations.
    """
    if not path_or_reg or not isinstance(path_or_reg, str):
        return False
    lower_val = path_or_reg.lower().replace("/", "\\")
    return any(re.search(pat, lower_val) for pat in PERSISTENCE_PATTERNS)


def categorize_network_destination(dest: str) -> str:
    """
    Categorize network destination into loopback, private, public, domain-like, or unknown without live lookups.
    """
    if not dest or not isinstance(dest, str):
        return "unknown"

    clean_dest = dest.strip().lower().split(":")[0].strip()

    if clean_dest in ("127.0.0.1", "::1", "localhost"):
        return "loopback"

    # Try IP address parsing
    try:
        ip = ipaddress.ip_address(clean_dest)
        if ip.is_loopback:
            return "loopback"
        if ip.is_private or ip.is_link_local:
            return "private"
        return "public"
    except ValueError:
        pass

    # Domain name heuristic check
    if "." in clean_dest and not clean_dest.startswith("."):
        parts = clean_dest.split(".")
        if len(parts) >= 2 and all(p.isalnum() or "-" in p for p in parts):
            return "domain-like"

    return "unknown"


def sanitize_arguments(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize raw arguments, scrub sensitive usernames, normalize registry keys & paths.
    """
    safe_args: Dict[str, Any] = {}
    for key, value in args.items():
        clean_key = str(key).strip().lower()

        if isinstance(value, str):
            clean_val = value.replace("\x00", "").strip()

            # Normalize registry hive if applicable
            if "registry" in clean_key or "key" in clean_key or clean_val.upper().startswith(("HKLM", "HKCU", "HKEY_")):
                clean_val = normalize_registry_hive(clean_val)

            # Scrub sensitive username
            clean_val = sanitize_path_string(clean_val)

            # Trim extremely long argument strings
            if len(clean_val) > 500:
                clean_val = clean_val[:500] + "... [truncated]"

            safe_args[clean_key] = clean_val

        elif isinstance(value, (int, float, bool)):
            safe_args[clean_key] = value
        elif isinstance(value, list):
            safe_args[clean_key] = [sanitize_path_string(str(v))[:100] for v in value[:10]]
        elif isinstance(value, dict):
            safe_args[clean_key] = {str(k): sanitize_path_string(str(v))[:100] for k, v in value.items()}
        else:
            safe_args[clean_key] = sanitize_path_string(str(value))

    return safe_args


def extract_argument_metadata(safe_args: Dict[str, Any]) -> Tuple[Optional[str], bool, Optional[str]]:
    """
    Extract path_category, is_persistence, and network_category from safe_arguments.
    """
    path_cat: Optional[str] = None
    is_pers = False
    net_cat: Optional[str] = None

    for clean_key, clean_val in safe_args.items():
        if isinstance(clean_val, str):
            if check_is_persistence(clean_val):
                is_pers = True

            if any(pk in clean_key for pk in ["path", "image", "target", "file", "folder", "dir", "command_line", "value_data"]):
                cat = categorize_path(clean_val)
                if cat != "unknown" and path_cat is None:
                    path_cat = cat

            if any(nk in clean_key for nk in ["ip", "host", "destination", "url", "domain"]):
                cat = categorize_network_destination(clean_val)
                if cat != "unknown" and net_cat is None:
                    net_cat = cat

    return path_cat, is_pers, net_cat


def generate_deterministic_event_id(sample_id: str, order: int, pid: int, api: str, ts: Optional[str], safe_args: Dict[str, Any]) -> Tuple[str, str]:
    """
    Generate deterministic event ID and SHA-256 hash.
    """
    arg_str = json.dumps(safe_args, sort_keys=True)
    raw_sig = f"{sample_id}:{order}:{pid}:{api}:{ts or ''}:{arg_str}".encode("utf-8")
    sha256_hash = hashlib.sha256(raw_sig).hexdigest()
    event_id = f"evt_{sha256_hash[:12]}"
    return event_id, sha256_hash


def normalize_event(raw_event: RawEvent) -> NormalizedEvent:
    """
    Convert a RawEvent into a NormalizedEvent with canonical category and privacy sanitization.
    """
    category = normalize_api_category(raw_event.api_name)
    safe_args = sanitize_arguments(raw_event.arguments)
    path_cat, is_pers, net_cat = extract_argument_metadata(safe_args)

    det_event_id, det_hash = generate_deterministic_event_id(
        sample_id=raw_event.sample_id,
        order=raw_event.event_order,
        pid=raw_event.process_id,
        api=raw_event.api_name,
        ts=raw_event.timestamp,
        safe_args=safe_args
    )

    # Use original event_id if provided and not generic
    final_event_id = raw_event.event_id if (raw_event.event_id and not raw_event.event_id.startswith("evt_0000")) else det_event_id

    return NormalizedEvent(
        sample_id=raw_event.sample_id,
        event_id=final_event_id,
        event_order=raw_event.event_order,
        process_id=raw_event.process_id,
        parent_process_id=raw_event.parent_process_id,
        timestamp=raw_event.timestamp,
        api_name=raw_event.api_name,
        category=category,
        safe_arguments=safe_args,
        source_file=raw_event.source_file,
        schema_version="1.0.0",
        repeat_count=1,
        first_order=raw_event.event_order,
        last_order=raw_event.event_order,
        first_timestamp=raw_event.timestamp,
        last_timestamp=raw_event.timestamp,
        path_category=path_cat,
        is_persistence=is_pers,
        network_category=net_cat,
        deterministic_hash=det_hash
    )


def collapse_consecutive_duplicates(events: List[NormalizedEvent]) -> List[NormalizedEvent]:
    """
    Collapse consecutive exact duplicate events for the SAME process ID.
    Retains repeat_count, first_order, last_order, first_timestamp, and last_timestamp.
    Does NOT collapse events across different processes or when arguments differ.
    """
    if not events:
        return []

    collapsed: List[NormalizedEvent] = []
    current: Optional[NormalizedEvent] = None

    for evt in events:
        if current is None:
            current = evt.model_copy()
            continue

        # Exact match criteria: same process_id, api_name, category, safe_arguments
        if (
            evt.process_id == current.process_id
            and evt.api_name == current.api_name
            and evt.category == current.category
            and evt.safe_arguments == current.safe_arguments
        ):
            current.repeat_count += 1
            current.last_order = evt.event_order
            current.last_timestamp = evt.timestamp
        else:
            collapsed.append(current)
            current = evt.model_copy()

    if current is not None:
        collapsed.append(current)

    return collapsed


def normalize_trace_events(raw_events: List[RawEvent], collapse_duplicates: bool = True) -> List[NormalizedEvent]:
    """
    Normalize a list of raw events and optionally collapse consecutive duplicates.
    """
    normalized = [normalize_event(evt) for evt in raw_events]
    if collapse_duplicates:
        return collapse_consecutive_duplicates(normalized)
    return normalized
