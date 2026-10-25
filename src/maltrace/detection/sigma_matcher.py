"""
Behavioral Sigma / Detection Rule Matching Engine.
Matches behavioral detection rules against normalized Windows execution traces.
Supports field lookups, wildcard / fnmatch matching, multiple selection blocks, and MITRE ATT&CK tags.
"""

import json
import fnmatch
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Set
from pydantic import BaseModel, Field

from maltrace.contracts.schemas import NormalizedEvent


class SigmaRule(BaseModel):
    id: str
    title: str
    description: str = ""
    level: str = "medium"  # low, medium, high, critical
    tags: List[str] = Field(default_factory=list)
    detection: Dict[str, Any] = Field(default_factory=dict)
    author: Optional[str] = None


class SigmaMatchResult(BaseModel):
    rule_id: str
    rule_title: str
    level: str
    tags: List[str]
    matched_event_ids: List[str]
    matched_events_count: int
    description: str = ""


def _match_field_condition(event_val: Any, pattern_val: Any) -> bool:
    """
    Check if a single event field value satisfies the pattern criteria.
    """
    if pattern_val is None:
        return True

    if event_val is None:
        return False

    event_str = str(event_val).lower()

    if isinstance(pattern_val, list):
        return any(_match_field_condition(event_val, p) for p in pattern_val)

    pat_str = str(pattern_val).lower()

    if "*" in pat_str or "?" in pat_str:
        return fnmatch.fnmatch(event_str, pat_str)
    else:
        return pat_str in event_str or event_str == pat_str


def _match_event_against_selection(event: NormalizedEvent, selection_dict: Dict[str, Any]) -> bool:
    """
    Check if a NormalizedEvent matches all field conditions within a selection dict.
    """
    event_dict = event.model_dump()
    safe_args = event.safe_arguments or {}

    for field_key, expected_val in selection_dict.items():
        field_lower = field_key.lower()

        # Check top-level event fields
        if field_lower in event_dict:
            actual_val = event_dict[field_lower]
        elif field_lower in ("api", "api_name"):
            actual_val = event.api_name
        elif field_lower in ("category", "event_category"):
            actual_val = event.category
        elif field_lower in ("image", "image_name", "process_name"):
            actual_val = safe_args.get("image_name", safe_args.get("process_name", ""))
        elif field_lower in ("command_line", "commandline", "cmdline"):
            actual_val = safe_args.get("command_line", "")
        elif field_lower in ("target_path", "filepath", "path"):
            actual_val = safe_args.get("target_path", "")
        elif field_lower in ("remote_address", "destination_ip", "ip"):
            actual_val = safe_args.get("remote_address", "")
        elif field_lower in safe_args:
            actual_val = safe_args[field_lower]
        else:
            # Fallback check raw string representation of arguments
            actual_val = json.dumps(safe_args)

        if not _match_field_condition(actual_val, expected_val):
            return False

    return True


class BehavioralSigmaEngine:
    """
    In-memory engine for loading and evaluating behavioral Sigma rules against trace events.
    """

    def __init__(self, rules: Optional[List[SigmaRule]] = None):
        self.rules: List[SigmaRule] = rules or []
        if not self.rules:
            self._load_builtin_rules()

    def _load_builtin_rules(self):
        """
        Load built-in behavioral detection rules covering ransomware, stealers, wipers, and evasion.
        """
        builtin = [
            SigmaRule(
                id="SIGMA-001",
                title="Shadow Copies Deletion via Vssadmin",
                description="Detects execution of vssadmin deleting volume shadow copies.",
                level="critical",
                tags=["attack.impact", "attack.t1490", "attack.t1486"],
                detection={
                    "selection": {
                        "category": "process",
                        "command_line": ["*vssadmin*delete*shadows*", "*delete shadows*"]
                    },
                    "condition": "selection"
                }
            ),
            SigmaRule(
                id="SIGMA-002",
                title="Windows Recovery Prevention via Bcdedit",
                description="Detects modification of boot configuration to disable recovery.",
                level="high",
                tags=["attack.impact", "attack.t1490"],
                detection={
                    "selection": {
                        "command_line": ["*bcdedit*recoveryenabled*no*", "*recoveryenabled no*"]
                    },
                    "condition": "selection"
                }
            ),
            SigmaRule(
                id="SIGMA-003",
                title="Raw Disk Access or MBR Overwrite",
                description="Detects direct opening of physical drive objects for wiper activity.",
                level="critical",
                tags=["attack.impact", "attack.t1485"],
                detection={
                    "selection": {
                        "target_path": ["*\\\\.\\PhysicalDrive*", "*PhysicalDrive0*"]
                    },
                    "condition": "selection"
                }
            ),
            SigmaRule(
                id="SIGMA-004",
                title="Browser Credential Store Access",
                description="Detects processes querying Chrome, Edge, or Firefox Login Data credential files.",
                level="high",
                tags=["attack.credential_access", "attack.t1555"],
                detection={
                    "selection": {
                        "target_path": ["*\\Login Data*", "*\\cookies*", "*\\passwords.txt*"]
                    },
                    "condition": "selection"
                }
            ),
            SigmaRule(
                id="SIGMA-005",
                title="Remote Process Memory Injection",
                description="Detects allocation and thread creation across process boundaries.",
                level="high",
                tags=["attack.defense_evasion", "attack.t1055"],
                detection={
                    "selection": {
                        "api_name": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
                    },
                    "condition": "selection"
                }
            )
        ]
        self.rules.extend(builtin)

    def add_rule(self, rule: SigmaRule):
        self.rules.append(rule)

    def load_rules_from_file(self, rule_file: Union[str, Path]):
        p = Path(rule_file)
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for item in data:
                self.rules.append(SigmaRule(**item))
        elif isinstance(data, dict):
            self.rules.append(SigmaRule(**data))

    def evaluate_trace(self, events: List[NormalizedEvent]) -> List[SigmaMatchResult]:
        """
        Evaluate all loaded Sigma rules against normalized trace events.
        """
        results: List[SigmaMatchResult] = []

        for rule in self.rules:
            det = rule.detection
            if not det:
                continue

            selection = det.get("selection", {})
            matched_eids: Set[str] = set()

            for event in events:
                if _match_event_against_selection(event, selection):
                    matched_eids.add(event.event_id)

            if matched_eids:
                results.append(SigmaMatchResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    tags=rule.tags,
                    matched_event_ids=sorted(list(matched_eids)),
                    matched_events_count=len(matched_eids),
                    description=rule.description
                ))

        return results
