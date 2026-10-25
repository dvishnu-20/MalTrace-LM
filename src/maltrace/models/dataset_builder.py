"""
Training dataset builder module.
Loads execution traces, extracts ground-truth family labels, excludes unknown labels,
and performs deterministic hash-grouped stratified splits to prevent data leakage.
"""

import hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Union
from collections import defaultdict
import numpy as np

from maltrace.contracts.schemas import NormalizedEvent, BehaviorStatement
from maltrace.ingestion.stream_parser import stream_parse_file, compute_file_sha256_and_size
from maltrace.representation.renderer import render_trace_statements


class TraceSampleRecord:
    """
    Representation of a single trace sample with events, rendered text, label, and file hash.
    """

    def __init__(
        self,
        sample_id: str,
        source_path: str,
        sha256: str,
        label: Optional[str],
        events: List[NormalizedEvent],
        statements: List[BehaviorStatement]
    ):
        self.sample_id = sample_id
        self.source_path = source_path
        self.sha256 = sha256
        self.label = label
        self.events = events
        self.statements = statements
        self.behavior_text = " ".join([s.rendered_phrase for s in statements])


def load_dataset_records(input_path: Union[str, Path]) -> Tuple[List[TraceSampleRecord], int]:
    """
    Scan trace files from input_path, extract events, labels, rendered statements, and SHA-256 hashes.
    Excludes samples with missing or unknown labels.
    Returns (labeled_records, excluded_count).
    """
    in_path = Path(input_path)

    if in_path.is_file():
        files = [in_path]
    elif in_path.is_dir():
        files = sorted([
            p for p in in_path.glob("**/*")
            if p.is_file() and p.suffix.lower() in [".json", ".jsonl", ".ndjson"] and p.name != "manifest.json"
        ])
    else:
        raise FileNotFoundError(f"Input path does not exist: {in_path}")

    records: List[TraceSampleRecord] = []
    excluded_count = 0

    for file_p in files:
        gen = stream_parse_file(file_p)
        events: List[NormalizedEvent] = []

        try:
            while True:
                events.append(next(gen))
        except StopIteration as stop:
            manifest = stop.value
            sha256_hash = manifest.sha256
            sample_id = manifest.sample_id or file_p.stem
            label = manifest.label

            if not label or str(label).strip().lower() in ("unknown", "none", "null"):
                excluded_count += 1
                continue

            statements = render_trace_statements(events)

            rec = TraceSampleRecord(
                sample_id=sample_id,
                source_path=str(file_p),
                sha256=sha256_hash,
                label=str(label).strip(),
                events=events,
                statements=statements
            )
            records.append(rec)

    return records, excluded_count


def split_dataset_hash_grouped(
    records: List[TraceSampleRecord],
    test_ratio: float = 0.2,
    seed: int = 42,
    balanced_subset: bool = False
) -> Tuple[List[TraceSampleRecord], List[TraceSampleRecord], str]:
    """
    Perform deterministic hash-grouped split so identical file SHA-256 hashes never cross splits.
    Returns (train_records, test_records, split_hash).
    """
    if not records:
        return [], [], "empty_split"

    if balanced_subset:
        # Group by label and pick equal numbers per label
        label_map: Dict[str, List[TraceSampleRecord]] = defaultdict(list)
        for r in records:
            label_map[r.label].append(r)
        
        min_count = min(len(v) for v in label_map.values()) if label_map else 0
        min_count = max(1, min_count)
        
        subset_records: List[TraceSampleRecord] = []
        for lbl, item_list in sorted(label_map.items()):
            # Sort deterministically
            sorted_items = sorted(item_list, key=lambda x: (x.sha256, x.sample_id))
            subset_records.extend(sorted_items[:min_count])
        records = subset_records

    # Group records by unique SHA-256 hash
    hash_groups: Dict[str, List[TraceSampleRecord]] = defaultdict(list)
    for r in records:
        hash_groups[r.sha256].append(r)

    unique_hashes = sorted(list(hash_groups.keys()))

    # Deterministic hash ranking for train/test assignment
    train_hashes: List[str] = []
    test_hashes: List[str] = []

    for h in unique_hashes:
        # Pseudo-random hash score using seed
        score_input = f"{h}:{seed}".encode("utf-8")
        score = int(hashlib.sha256(score_input).hexdigest(), 16) % 100000 / 100000.0
        if score < test_ratio and len(unique_hashes) > 1:
            test_hashes.append(h)
        else:
            train_hashes.append(h)

    # Fallback if test_hashes empty but multiple unique hashes exist
    if not test_hashes and len(unique_hashes) > 1:
        test_hashes = [unique_hashes[-1]]
        train_hashes = unique_hashes[:-1]

    train_records = [r for h in train_hashes for r in hash_groups[h]]
    test_records = [r for h in test_hashes for r in hash_groups[h]]

    split_signature = f"seed={seed}:train_hashes={sorted(train_hashes)}:test_hashes={sorted(test_hashes)}"
    split_hash = hashlib.sha256(split_signature.encode("utf-8")).hexdigest()[:12]

    return train_records, test_records, split_hash
