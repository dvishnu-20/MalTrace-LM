"""
Process tree construction engine.
Detects missing parents, resolves process cycles, identifies roots,
and produces human-readable process execution lineage paths.
"""

from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
import logging

from maltrace.contracts.schemas import NormalizedEvent, ProcessTreeNode, ProcessSummary

logger = logging.getLogger(__name__)


def build_process_tree(events: List[NormalizedEvent]) -> Tuple[Dict[int, ProcessTreeNode], List[str]]:
    """
    Construct process tree nodes from normalized events, detecting cycles and missing parents.
    Returns (nodes_by_pid, warnings).
    """
    warnings: List[str] = []

    # Map PID to node data
    nodes: Dict[int, ProcessTreeNode] = {}
    proc_ppids: Dict[int, int] = {}
    proc_names: Dict[int, str] = {}
    proc_paths: Dict[int, Optional[str]] = {}
    proc_cmdlines: Dict[int, Optional[str]] = {}

    for evt in events:
        pid = evt.process_id
        ppid = evt.parent_process_id

        if pid not in proc_ppids:
            proc_ppids[pid] = ppid
        elif ppid != 0 and proc_ppids[pid] == 0:
            proc_ppids[pid] = ppid

        # Extract process name, path, command line
        if pid not in proc_names:
            img = evt.safe_arguments.get("image_name") or evt.safe_arguments.get("process_name") or evt.safe_arguments.get("path") or evt.safe_arguments.get("target_path")
            cmd = evt.safe_arguments.get("command_line")

            if img:
                img_str = str(img)
                proc_paths[pid] = img_str
                name = img_str.replace("/", "\\").split("\\")[-1]
                proc_names[pid] = name if name else f"proc_{pid}.exe"
            else:
                proc_names[pid] = f"proc_{pid}.exe"

            if cmd:
                proc_cmdlines[pid] = str(cmd)

    pids = set(proc_ppids.keys())

    # Cycle Detection using DFS
    visited: Set[int] = set()
    rec_stack: Set[int] = set()
    cycles_detected: Set[int] = set()

    def detect_cycle_dfs(curr: int) -> bool:
        visited.add(curr)
        rec_stack.add(curr)

        parent = proc_ppids.get(curr, 0)
        if parent in pids and parent != 0:
            if parent in rec_stack:
                # Cycle found!
                cycles_detected.add(curr)
                cycles_detected.add(parent)
                warnings.append(f"Process cycle detected between PID {curr} and parent PID {parent}")
                # Break cycle by severing parent link
                proc_ppids[curr] = 0
            elif parent not in visited:
                detect_cycle_dfs(parent)

        rec_stack.remove(curr)
        return False

    for pid in sorted(list(pids)):
        if pid not in visited:
            detect_cycle_dfs(pid)

    # Populate children & identify root / orphan status
    child_map: Dict[int, Set[int]] = defaultdict(set)
    for pid, ppid in proc_ppids.items():
        if ppid != 0 and ppid in pids:
            child_map[ppid].add(pid)

    for pid in sorted(list(pids)):
        ppid = proc_ppids.get(pid, 0)
        is_orphan = (ppid != 0 and ppid not in pids)
        is_root = (ppid == 0 or is_orphan)
        has_cycle = pid in cycles_detected

        if is_orphan:
            warnings.append(f"Missing parent process PID {ppid} for process {proc_names.get(pid)} (PID {pid})")

        nodes[pid] = ProcessTreeNode(
            process_id=pid,
            parent_process_id=ppid if not is_orphan else 0,
            process_name=proc_names.get(pid, f"proc_{pid}.exe"),
            image_path=proc_paths.get(pid),
            command_line=proc_cmdlines.get(pid),
            child_pids=sorted(list(child_map.get(pid, set()))),
            is_root=is_root,
            is_orphan=is_orphan,
            has_cycle=has_cycle,
            readable_path=""
        )

    # Generate readable process lineage paths
    for pid, node in nodes.items():
        lineage: List[str] = [f"{node.process_name} ({node.process_id})"]
        curr_p = node.parent_process_id
        seen: Set[int] = {pid}

        while curr_p in nodes and curr_p not in seen and curr_p != 0:
            seen.add(curr_p)
            parent_node = nodes[curr_p]
            lineage.append(f"{parent_node.process_name} ({parent_node.process_id})")
            curr_p = parent_node.parent_process_id

        lineage.reverse()
        node.readable_path = " -> ".join(lineage)

    return nodes, warnings


def build_enhanced_process_summaries(events: List[NormalizedEvent]) -> Tuple[List[ProcessSummary], List[str]]:
    """
    Aggregate events into enriched ProcessSummary objects with readable process lineage paths.
    """
    tree_nodes, warnings = build_process_tree(events)

    proc_events: Dict[int, List[NormalizedEvent]] = defaultdict(list)
    for evt in events:
        proc_events[evt.process_id].append(evt)

    summaries: List[ProcessSummary] = []
    for pid in sorted(tree_nodes.keys()):
        node = tree_nodes[pid]
        p_evts = proc_events.get(pid, [])

        evt_ids = [e.event_id for e in p_evts]
        cats = sorted(list(set(e.category for e in p_evts)))

        summaries.append(
            ProcessSummary(
                process_id=pid,
                process_name=node.process_name,
                parent_process_id=node.parent_process_id,
                event_ids=evt_ids,
                categories_observed=cats,
                child_process_ids=node.child_pids,
                readable_path=node.readable_path,
                is_root=node.is_root,
                is_orphan=node.is_orphan,
                has_cycle=node.has_cycle
            )
        )

    return summaries, warnings
