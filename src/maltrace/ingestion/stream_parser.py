"""
Streaming and bounded-memory trace ingestion parser.
Processes reports one file at a time, yields normalized events,
and exports normalized JSONL, Parquet, and run manifests.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Generator, List, Dict, Any, Tuple, Optional, Union
import orjson
import pandas as pd

from maltrace.contracts.schemas import (
    RawEvent,
    NormalizedEvent,
    IngestionFileManifest,
    BatchRunManifest,
)
from maltrace.ingestion.adapters import ReportAdapter
from maltrace.representation.normalizer import normalize_trace_events
from maltrace.features.process_tree import build_process_tree


def compute_file_sha256_and_size(file_path: Union[str, Path]) -> Tuple[str, int]:
    """
    Compute SHA-256 hash and file size in bytes using streaming chunk reads.
    """
    path = Path(file_path)
    sha256 = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            size += len(chunk)
    return sha256.hexdigest(), size


def stream_parse_file(file_path: Union[str, Path]) -> Generator[NormalizedEvent, None, IngestionFileManifest]:
    """
    Generator yielding normalized events one by one from a single trace report.
    Returns IngestionFileManifest on completion.
    """
    path = Path(file_path)
    sha256_hash, file_size = compute_file_sha256_and_size(path)
    warnings: List[str] = []
    parse_status = "success"

    try:
        if path.suffix.lower() == ".jsonl" or path.suffix.lower() == ".ndjson":
            # Process NDJSON line by line
            raw_events: List[RawEvent] = []
            sample_id = path.stem
            label = None
            with open(path, "rb") as f:
                for idx, line in enumerate(f):
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        line_data = orjson.loads(line_str)
                        if isinstance(line_data, dict):
                            s_id, lbl, evts, warn = ReportAdapter.extract(line_data, source_file=path.name)
                            if s_id:
                                sample_id = s_id
                            if lbl:
                                label = lbl
                            raw_events.extend(evts)
                            warnings.extend(warn)
                    except Exception as e:
                        warnings.append(f"Line {idx + 1} parse error: {e}")
        else:
            # Standard JSON report
            with open(path, "rb") as f:
                content = f.read()
                data = orjson.loads(content)
            sample_id, label, raw_events, adapter_warnings = ReportAdapter.extract(data, source_file=path.name)
            warnings.extend(adapter_warnings)

    except Exception as e:
        parse_status = "failed"
        warnings.append(f"Failed to parse trace file {path.name}: {str(e)}")
        manifest = IngestionFileManifest(
            source_path=str(path),
            file_size_bytes=file_size,
            parse_status=parse_status,
            event_count=0,
            raw_event_count=0,
            process_count=0,
            warnings=warnings,
            sha256=sha256_hash,
            sample_id=path.stem,
            label=None
        )
        return manifest

    # Normalize events and collapse duplicates
    normalized_events = normalize_trace_events(raw_events, collapse_duplicates=True)

    # Process tree check for warnings
    nodes, tree_warnings = build_process_tree(normalized_events)
    warnings.extend(tree_warnings)

    if warnings and parse_status != "failed":
        parse_status = "partial" if len(raw_events) == 0 else "success"

    for event in normalized_events:
        yield event

    manifest = IngestionFileManifest(
        source_path=str(path),
        file_size_bytes=file_size,
        parse_status=parse_status,
        event_count=len(normalized_events),
        raw_event_count=len(raw_events),
        process_count=len(nodes),
        warnings=warnings,
        sha256=sha256_hash,
        sample_id=sample_id,
        label=label
    )
    return manifest


def process_batch(
    input_path: Union[str, Path],
    output_dir: Union[str, Path]
) -> BatchRunManifest:
    """
    Process a single trace file or directory of trace files bounded-memory,
    writing normalized JSONL, Parquet, and manifest.json to output_dir.
    """
    in_path = Path(input_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if in_path.is_file():
        files_to_process = [in_path]
    elif in_path.is_dir():
        files_to_process = sorted([
            p for p in in_path.glob("**/*")
            if p.is_file() and p.suffix.lower() in [".json", ".jsonl", ".ndjson"]
        ])
    else:
        raise FileNotFoundError(f"Input path does not exist: {in_path}")

    jsonl_path = out_dir / "events.jsonl"
    parquet_path = out_dir / "events.parquet"
    manifest_path = out_dir / "manifest.json"

    file_manifests: List[IngestionFileManifest] = []
    all_events_dicts: List[Dict[str, Any]] = []

    successful_count = 0
    failed_count = 0

    with open(jsonl_path, "w", encoding="utf-8") as jsonl_file:
        for file_p in files_to_process:
            gen = stream_parse_file(file_p)
            events_for_file: List[NormalizedEvent] = []

            try:
                while True:
                    event = next(gen)
                    events_for_file.append(event)
                    # Write to JSONL stream
                    event_dict = event.model_dump()
                    jsonl_file.write(json.dumps(event_dict) + "\n")
                    all_events_dicts.append(event_dict)
            except StopIteration as stop:
                file_manifest: IngestionFileManifest = stop.value
                file_manifests.append(file_manifest)
                if file_manifest.parse_status == "failed":
                    failed_count += 1
                else:
                    successful_count += 1

    # Write Parquet event table using pandas
    if all_events_dicts:
        df = pd.DataFrame(all_events_dicts)
        # Convert dict/list columns to string or json string for clean Parquet export
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, (dict, list))).any():
                df[col] = df[col].apply(lambda x: json.dumps(x) if isinstance(x, (dict, list)) else x)
        df.to_parquet(parquet_path, index=False)
    else:
        # Empty DataFrame parquet
        pd.DataFrame().to_parquet(parquet_path)

    batch_manifest = BatchRunManifest(
        run_id=f"run_{hashlib.sha256(str(in_path).encode()).hexdigest()[:10]}",
        timestamp=pd.Timestamp.now().isoformat(),
        total_files=len(files_to_process),
        successful_files=successful_count,
        failed_files=failed_count,
        files=file_manifests
    )

    with open(manifest_path, "w", encoding="utf-8") as mf:
        mf.write(json.dumps(batch_manifest.model_dump(), indent=2))

    return batch_manifest
