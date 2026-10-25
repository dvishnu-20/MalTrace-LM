"""
In-memory evidence index for execution trace events.
Indexes event ID to normalized event, controlled phrase, process context, and source provenance.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from maltrace.contracts.schemas import NormalizedEvent, ProcessSummary


@dataclass
class ProcessContext:
    process_id: int
    parent_process_id: int
    process_name: str
    readable_path: str
    path_category: Optional[str] = None


@dataclass
class SourceProvenance:
    sample_id: str
    source_file: str
    schema_version: str
    event_order: int
    timestamp: Optional[str] = None


@dataclass
class EvidenceEntry:
    event_id: str
    event: NormalizedEvent
    controlled_phrase: str
    process_context: ProcessContext
    source_provenance: SourceProvenance


class EvidenceIndex:
    """
    In-memory index mapping event ID to normalized event, controlled phrase,
    process context, and source provenance.
    """
    def __init__(
        self,
        events: List[NormalizedEvent],
        process_summaries: Optional[List[ProcessSummary]] = None
    ):
        self._index: Dict[str, EvidenceEntry] = {}
        self.sample_id: str = events[0].sample_id if events else "unknown"

        proc_map: Dict[int, ProcessSummary] = {}
        if process_summaries:
            for p in process_summaries:
                proc_map[p.process_id] = p

        for evt in events:
            proc_sum = proc_map.get(evt.process_id)
            proc_name = proc_sum.process_name if proc_sum else f"pid_{evt.process_id}"
            readable_path = proc_sum.readable_path if (proc_sum and proc_sum.readable_path) else proc_name

            proc_ctx = ProcessContext(
                process_id=evt.process_id,
                parent_process_id=evt.parent_process_id,
                process_name=proc_name,
                readable_path=readable_path,
                path_category=evt.path_category
            )

            prov = SourceProvenance(
                sample_id=evt.sample_id,
                source_file=evt.source_file,
                schema_version=evt.schema_version,
                event_order=evt.event_order,
                timestamp=evt.timestamp
            )

            args_str = str(evt.safe_arguments)
            if len(args_str) > 100:
                args_str = args_str[:100] + "..."
            phrase = f"PID {evt.process_id} ({proc_name}) executed API '{evt.api_name}' [{evt.category}] with args: {args_str}"

            entry = EvidenceEntry(
                event_id=evt.event_id,
                event=evt,
                controlled_phrase=phrase,
                process_context=proc_ctx,
                source_provenance=prov
            )
            self._index[evt.event_id] = entry

    def get(self, event_id: str) -> Optional[EvidenceEntry]:
        return self._index.get(event_id)

    def contains(self, event_id: str) -> bool:
        return event_id in self._index

    def validate_reference(self, event_id: str, target_sample_id: Optional[str] = None) -> str:
        """
        Validates event citation reference against index.
        Returns: 'VALID', 'MISSING', or 'CROSS_SAMPLE'.
        """
        if event_id not in self._index:
            return "MISSING"
        entry = self._index[event_id]
        expected = target_sample_id or self.sample_id
        if entry.source_provenance.sample_id != expected:
            return "CROSS_SAMPLE"
        return "VALID"

    def __len__(self) -> int:
        return len(self._index)

    def __iter__(self):
        return iter(self._index.values())
