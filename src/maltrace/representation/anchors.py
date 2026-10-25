"""
Security anchor rules engine.
Identifies high-value security evidence and attaches transparent rule names.
Anchors are preserved with mandatory priority in context budget selection.
"""

from typing import List, Set
from maltrace.contracts.schemas import NormalizedEvent

ANCHOR_COMMAND_INTERPRETERS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "powershell", "cmd"}

def evaluate_security_anchors(event: NormalizedEvent) -> List[str]:
    """
    Evaluate transparent anchor rules on a normalized event.
    Returns list of triggered rule names.
    """
    rules: List[str] = []
    args_str = str(event.safe_arguments).lower()
    api_lower = event.api_name.lower()

    # Rule 1: AutorunRegistryWrite
    if event.is_persistence or (event.category == "registry" and any(k in args_str for k in ["run", "runonce", "startup", "winlogon"])):
        rules.append("AutorunRegistryWrite")

    # Rule 2: CommandShellLaunch
    if event.category == "process" or any(p in args_str for p in ANCHOR_COMMAND_INTERPRETERS) or any(p in api_lower for p in ANCHOR_COMMAND_INTERPRETERS):
        if any(p in args_str or p in api_lower for p in ANCHOR_COMMAND_INTERPRETERS):
            rules.append("CommandShellLaunch")

    # Rule 3: UnusualServiceCreation
    if event.category == "service" or "service" in api_lower or "createservice" in api_lower:
        rules.append("UnusualServiceCreation")

    # Rule 4: PublicOutboundConnection
    if event.category == "network" and (event.network_category in ("public", "domain-like") or any(k in args_str for k in ["http", "tcp", "connect"])):
        rules.append("PublicOutboundConnection")

    # Rule 5: InjectionIndicator
    if event.category == "memory" or any(k in api_lower for k in ["virtualalloc", "writeprocessmemory", "createremotethread", "unmapview"]):
        rules.append("InjectionIndicator")

    # Rule 6: DefenseImpairment
    if ("vssadmin" in args_str and "delete" in args_str) or any(k in args_str for k in ["bcdedit", "disableantispyware", "net stop", "sc stop"]):
        rules.append("DefenseImpairment")

    return list(dict.fromkeys(rules))  # Unique preserve order
