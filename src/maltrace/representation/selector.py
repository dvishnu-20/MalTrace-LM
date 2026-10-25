"""
Context budget selector engine.
Selects behavior statements to fit within configurable token/character budgets while strictly preserving mandatory security anchors.
Provides DefaultBudgetSelector, FrontTruncationSelector, and CategoryFrequencySelector implementations.
"""

from typing import List, Dict, Set, Tuple
from collections import defaultdict
from maltrace.contracts.schemas import BehaviorStatement, ProcessBehaviorSummary

SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}


class DefaultBudgetSelector:
    """
    Primary budget selector.
    Retains 100% of security anchors and process representation, then fills remaining budget with highest-priority statements.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        selected_ids: Set[str] = set()
        selected_statements: List[BehaviorStatement] = []
        current_chars = 0

        # Step 1: MANDATORY ANCHORS - Must never be pruned
        for s in statements:
            if s.anchor_rules:
                if s.statement_id not in selected_ids:
                    selected_ids.add(s.statement_id)
                    selected_statements.append(s)
                    current_chars += len(s.rendered_phrase)

        # Step 2: PROCESS REPRESENTATION - Ensure at least 1 statement per PID if budget allows
        pids_represented = set(s.process_id for s in selected_statements)
        for s in statements:
            if s.process_id not in pids_represented:
                if s.statement_id not in selected_ids:
                    if current_chars + len(s.rendered_phrase) <= max_budget_chars:
                        selected_ids.add(s.statement_id)
                        selected_statements.append(s)
                        current_chars += len(s.rendered_phrase)
                        pids_represented.add(s.process_id)

        # Step 3: PRIORITY FILLING - Fill remaining budget by severity & order
        remaining_candidates = [s for s in statements if s.statement_id not in selected_ids]
        remaining_candidates.sort(
            key=lambda s: (SEVERITY_WEIGHTS.get(s.severity, 0), -s.event_order),
            reverse=True
        )

        for s in remaining_candidates:
            phrase_len = len(s.rendered_phrase)
            if current_chars + phrase_len <= max_budget_chars:
                selected_ids.add(s.statement_id)
                selected_statements.append(s)
                current_chars += phrase_len

        # Re-sort in original event execution order
        selected_statements.sort(key=lambda s: s.event_order)
        return selected_statements


class FrontTruncationSelector:
    """
    Alternative selector: Retains all anchors, then fills remaining budget chronologically from the front.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        selected_ids: Set[str] = set()
        selected_statements: List[BehaviorStatement] = []
        current_chars = 0

        # Step 1: Retain mandatory anchors
        for s in statements:
            if s.anchor_rules:
                selected_ids.add(s.statement_id)
                selected_statements.append(s)
                current_chars += len(s.rendered_phrase)

        # Step 2: Chronological front truncation
        for s in sorted(statements, key=lambda x: x.event_order):
            if s.statement_id not in selected_ids:
                if current_chars + len(s.rendered_phrase) <= max_budget_chars:
                    selected_ids.add(s.statement_id)
                    selected_statements.append(s)
                    current_chars += len(s.rendered_phrase)

        selected_statements.sort(key=lambda s: s.event_order)
        return selected_statements


class CategoryFrequencySelector:
    """
    Alternative selector: Retains all anchors, then selects statements proportionally across observed categories.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        selected_ids: Set[str] = set()
        selected_statements: List[BehaviorStatement] = []
        current_chars = 0

        # Step 1: Retain mandatory anchors
        for s in statements:
            if s.anchor_rules:
                selected_ids.add(s.statement_id)
                selected_statements.append(s)
                current_chars += len(s.rendered_phrase)

        # Step 2: Group unselected by category
        cat_map: Dict[str, List[BehaviorStatement]] = defaultdict(list)
        for s in statements:
            if s.statement_id not in selected_ids:
                cat_map[s.category].append(s)

        # Round-robin category pick
        categories = list(cat_map.keys())
        added_any = True

        while added_any and current_chars < max_budget_chars:
            added_any = False
            for cat in categories:
                if cat_map[cat]:
                    candidate = cat_map[cat].pop(0)
                    if current_chars + len(candidate.rendered_phrase) <= max_budget_chars:
                        selected_ids.add(candidate.statement_id)
                        selected_statements.append(candidate)
                        current_chars += len(candidate.rendered_phrase)
                        added_any = True

        selected_statements.sort(key=lambda s: s.event_order)
        return selected_statements
