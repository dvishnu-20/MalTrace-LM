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


def load_dataset_records(
    input_path: Union[str, Path],
    benchmark_mode: bool = True
) -> Tuple[List[TraceSampleRecord], int]:
    """
    Scan trace files from input_path, extract events, labels, rendered statements, and SHA-256 hashes.
    Excludes samples with missing or unknown labels.
    In benchmark_mode=True, ground truth labels are strictly extracted from report metadata.
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
        gen = stream_parse_file(file_p, benchmark_mode=benchmark_mode)
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
    scored_hashes = sorted(
        unique_hashes,
        key=lambda h: hashlib.sha256(f"{h}:{seed}".encode("utf-8")).hexdigest()
    )
    n_total = len(scored_hashes)
    n_test = max(1, int(round(n_total * test_ratio))) if n_total > 1 else 0
    n_train = max(1, n_total - n_test)
    if n_train + n_test > n_total:
        n_test = max(1, n_total - n_train)

    train_hashes = scored_hashes[:n_train]
    test_hashes = scored_hashes[n_train:]

    train_records = [r for h in train_hashes for r in hash_groups[h]]
    test_records = [r for h in test_hashes for r in hash_groups[h]]

    split_signature = f"seed={seed}:train_hashes={sorted(train_hashes)}:test_hashes={sorted(test_hashes)}"
    split_hash = hashlib.sha256(split_signature.encode("utf-8")).hexdigest()[:12]

    return train_records, test_records, split_hash


def split_dataset_hash_grouped_3way(
    records: List[TraceSampleRecord],
    test_ratio: float = 0.20,
    val_ratio: float = 0.20,
    seed: int = 42,
    balanced_subset: bool = False
) -> Tuple[List[TraceSampleRecord], List[TraceSampleRecord], List[TraceSampleRecord], str]:
    """
    Perform deterministic 3-way hash-grouped split into Train, Validation (Calibration), and Test sets.
    Guarantees no identical SHA-256 hash or sample crosses splits.
    Returns (train_records, val_records, test_records, split_hash).
    """
    if not records:
        return [], [], [], "empty_split"

    if balanced_subset:
        label_map: Dict[str, List[TraceSampleRecord]] = defaultdict(list)
        for r in records:
            label_map[r.label].append(r)

        min_count = max(1, min(len(v) for v in label_map.values())) if label_map else 0
        subset_records: List[TraceSampleRecord] = []
        for lbl, item_list in sorted(label_map.items()):
            sorted_items = sorted(item_list, key=lambda x: (x.sha256, x.sample_id))
            subset_records.extend(sorted_items[:min_count])
        records = subset_records

    hash_groups: Dict[str, List[TraceSampleRecord]] = defaultdict(list)
    for r in records:
        hash_groups[r.sha256].append(r)

    unique_hashes = sorted(list(hash_groups.keys()))
    scored_hashes = sorted(
        unique_hashes,
        key=lambda h: hashlib.sha256(f"{h}:{seed}".encode("utf-8")).hexdigest()
    )
    n_total = len(scored_hashes)

    if n_total < 3:
        n_test = 1 if n_total >= 2 else 0
        n_val = 0
        n_train = max(1, n_total - n_test)
    else:
        n_test = max(1, int(round(n_total * test_ratio)))
        n_val = max(1, int(round(n_total * val_ratio)))
        n_train = max(1, n_total - n_test - n_val)
        while n_train + n_val + n_test > n_total:
            if n_val > 1:
                n_val -= 1
            elif n_test > 1:
                n_test -= 1
            else:
                break

    train_hashes = scored_hashes[:n_train]
    val_hashes = scored_hashes[n_train:n_train + n_val]
    test_hashes = scored_hashes[n_train + n_val:]

    train_records = [r for h in train_hashes for r in hash_groups[h]]
    val_records = [r for h in val_hashes for r in hash_groups[h]]
    test_records = [r for h in test_hashes for r in hash_groups[h]]

    split_signature = f"seed={seed}:train={sorted(train_hashes)}:val={sorted(val_hashes)}:test={sorted(test_hashes)}"
    split_hash = hashlib.sha256(split_signature.encode("utf-8")).hexdigest()[:12]

    return train_records, val_records, test_records, split_hash
