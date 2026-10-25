from pathlib import Path
from typing import Union
import orjson

from maltrace.contracts.schemas import RawTrace
from maltrace.ingestion.adapters import ReportAdapter


def load_trace_file(file_path: Union[str, Path]) -> RawTrace:
    """
    Load and parse a JSON trace file into a RawTrace object.
    Supports WinMET trace structure, Cuckoo/CAPE behavior reports, or generic event list JSON files.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Trace file not found: {path}")

    try:
        with open(path, "rb") as f:
            data = orjson.loads(f.read())
    except Exception as e:
        raise ValueError(f"Invalid JSON in trace file {path}: {str(e)}")

    sample_id, _, raw_events, _ = ReportAdapter.extract(data, source_file=path.name)

    return RawTrace(
        sample_id=str(sample_id),
        events=raw_events,
        schema_version="1.0.0"
    )
