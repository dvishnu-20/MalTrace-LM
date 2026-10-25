"""
Dataset audit module.
Analyzes input trace files or manifest metadata to report data quality,
parse failures, missing labels, category distributions, trace-length metrics, hash collisions, and family frequencies.
"""

from pathlib import Path
from typing import Dict, Any, List, Union, Optional
from collections import defaultdict
import numpy as np

from maltrace.ingestion.stream_parser import stream_parse_file


def audit_dataset(input_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Perform a complete quality audit across trace files in input_path (file or directory).
    Returns structured audit metrics dictionary.
    """
    in_path = Path(input_path)

    if in_path.is_file() and in_path.suffix.lower() == ".json" and in_path.name == "manifest.json":
        # Manifest audit mode could be implemented, but direct trace scanning guarantees event-level metrics
        pass

    if in_path.is_file():
        files_to_audit = [in_path]
    elif in_path.is_dir():
        files_to_audit = sorted([
            p for p in in_path.glob("**/*")
            if p.is_file() and p.suffix.lower() in [".json", ".jsonl", ".ndjson"] and p.name != "manifest.json"
        ])
    else:
        raise FileNotFoundError(f"Path does not exist: {in_path}")

    total_files = len(files_to_audit)
    parse_failures = 0
    failure_details: List[Dict[str, Any]] = []

    missing_labels_count = 0
    hash_to_files: Dict[str, List[str]] = defaultdict(list)
    category_counts: Dict[str, int] = defaultdict(int)
    family_counts: Dict[str, int] = defaultdict(int)
    trace_lengths: List[int] = []

    for file_p in files_to_audit:
        gen = stream_parse_file(file_p)
        events = []

        try:
            while True:
                evt = next(gen)
                events.append(evt)
                category_counts[evt.category] += 1
        except StopIteration as stop:
            manifest = stop.value
            hash_to_files[manifest.sha256].append(str(file_p.name))

            if manifest.parse_status == "failed":
                parse_failures += 1
                failure_details.append({
                    "file": str(file_p.name),
                    "warnings": manifest.warnings
                })

            if not manifest.label or manifest.label.lower() in ("unknown", "none"):
                missing_labels_count += 1
            else:
                family_counts[manifest.label] += 1

            trace_lengths.append(len(events))

    # Calculate trace-length statistics
    if trace_lengths:
        lengths_arr = np.array(trace_lengths)
        length_stats = {
            "min": int(np.min(lengths_arr)),
            "max": int(np.max(lengths_arr)),
            "mean": float(np.mean(lengths_arr)),
            "median": float(np.median(lengths_arr)),
            "p95": float(np.percentile(lengths_arr, 95))
        }
    else:
        length_stats = {"min": 0, "max": 0, "mean": 0.0, "median": 0.0, "p95": 0.0}

    # Find duplicated file SHA-256 hashes
    duplicated_hashes = {
        h: file_list for h, file_list in hash_to_files.items() if len(file_list) > 1
    }

    audit_report = {
        "total_files": total_files,
        "successful_files": total_files - parse_failures,
        "parse_failures": parse_failures,
        "failure_details": failure_details,
        "missing_labels_count": missing_labels_count,
        "category_distribution": dict(sorted(category_counts.items(), key=lambda item: item[1], reverse=True)),
        "family_frequencies": dict(sorted(family_counts.items(), key=lambda item: item[1], reverse=True)),
        "trace_length_stats": length_stats,
        "duplicated_hashes": duplicated_hashes,
        "duplicate_hash_count": len(duplicated_hashes)
    }

    return audit_report
