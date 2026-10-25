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
    Primary anchor-aware budget selector.
    Prioritizes high-severity security anchors. In default mode (strict_budget=False),
    all security anchors are strictly preserved, and remaining budget is filled.
    In strict_budget=True mode, a hard character ceiling is enforced.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000,
        strict_budget: bool = False
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        selected_ids: Set[str] = set()
        selected_statements: List[BehaviorStatement] = []
        current_chars = 0

        # Step 1: ANCHORS SORTED BY SEVERITY
        anchors = [s for s in statements if s.anchor_rules]
        anchors.sort(key=lambda s: (SEVERITY_WEIGHTS.get(s.severity, 0), -s.event_order), reverse=True)

        for s in anchors:
            phrase_len = len(s.rendered_phrase)
            if not strict_budget or (current_chars + phrase_len <= max_budget_chars):
                if s.statement_id not in selected_ids:
                    selected_ids.add(s.statement_id)
                    selected_statements.append(s)
                    current_chars += phrase_len

        # Step 2: PROCESS REPRESENTATION - At least 1 statement per PID if budget allows
        pids_represented = set(s.process_id for s in selected_statements)
        for s in statements:
            if s.process_id not in pids_represented:
                phrase_len = len(s.rendered_phrase)
                if current_chars + phrase_len <= max_budget_chars:
                    if s.statement_id not in selected_ids:
                        selected_ids.add(s.statement_id)
                        selected_statements.append(s)
                        current_chars += phrase_len
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

        selected_statements.sort(key=lambda s: s.event_order)
        return selected_statements


class NaiveFrontTruncationSelector:
    """
    Scientific Baseline 1: Genuine anchor-free front truncation.
    Chronologically selects statements from the beginning until budget is exhausted.
    Does NOT prioritize or protect security anchors.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        selected: List[BehaviorStatement] = []
        current_chars = 0

        for s in sorted(statements, key=lambda x: x.event_order):
            phrase_len = len(s.rendered_phrase)
            if current_chars + phrase_len <= max_budget_chars:
                selected.append(s)
                current_chars += phrase_len
            else:
                break

        return selected


class NaiveTailTruncationSelector:
    """
    Scientific Baseline 2: Genuine anchor-free tail truncation.
    Chronologically selects statements from the end backwards until budget is exhausted.
    Does NOT prioritize or protect security anchors.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        selected: List[BehaviorStatement] = []
        current_chars = 0

        for s in sorted(statements, key=lambda x: x.event_order, reverse=True):
            phrase_len = len(s.rendered_phrase)
            if current_chars + phrase_len <= max_budget_chars:
                selected.append(s)
                current_chars += phrase_len
            else:
                break

        selected.sort(key=lambda s: s.event_order)
        return selected


class RandomStatementSelector:
    """
    Scientific Baseline 3: Random statement sampling without anchor awareness.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000,
        seed: int = 42
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        import random
        rng = random.Random(seed)
        shuffled = list(statements)
        rng.shuffle(shuffled)

        selected: List[BehaviorStatement] = []
        current_chars = 0

        for s in shuffled:
            phrase_len = len(s.rendered_phrase)
            if current_chars + phrase_len <= max_budget_chars:
                selected.append(s)
                current_chars += phrase_len

        selected.sort(key=lambda s: s.event_order)
        return selected


class HardBudgetSelector:
    """
    Experimental hard-budget selector:
    Enforces a strict upper bound on characters (never exceeds max_budget_chars)
    even if lower-severity anchors must be omitted.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000
    ) -> List[BehaviorStatement]:
        return DefaultBudgetSelector.select(statements, max_budget_chars=max_budget_chars, strict_budget=True)


class FrontTruncationSelector:
    """
    Anchor-Preserving Front Selector: Retains anchors, then fills chronologically from front.
    Supports strict_budget mode.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000,
        strict_budget: bool = False
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        selected_ids: Set[str] = set()
        selected_statements: List[BehaviorStatement] = []
        current_chars = 0

        # Step 1: Retain anchors
        anchors = [s for s in statements if s.anchor_rules]
        anchors.sort(key=lambda s: (SEVERITY_WEIGHTS.get(s.severity, 0), -s.event_order), reverse=True)
        for s in anchors:
            phrase_len = len(s.rendered_phrase)
            if not strict_budget or (current_chars + phrase_len <= max_budget_chars):
                selected_ids.add(s.statement_id)
                selected_statements.append(s)
                current_chars += phrase_len

        # Step 2: Chronological front truncation
        for s in sorted(statements, key=lambda x: x.event_order):
            if s.statement_id not in selected_ids:
                phrase_len = len(s.rendered_phrase)
                if current_chars + phrase_len <= max_budget_chars:
                    selected_ids.add(s.statement_id)
                    selected_statements.append(s)
                    current_chars += phrase_len

        selected_statements.sort(key=lambda s: s.event_order)
        return selected_statements


class CategoryFrequencySelector:
    """
    Anchor-Preserving Category Selector: Retains anchors, then samples round-robin across categories.
    Supports strict_budget mode.
    """

    @staticmethod
    def select(
        statements: List[BehaviorStatement],
        max_budget_chars: int = 2000,
        strict_budget: bool = False
    ) -> List[BehaviorStatement]:
        if not statements:
            return []

        selected_ids: Set[str] = set()
        selected_statements: List[BehaviorStatement] = []
        current_chars = 0

        # Step 1: Retain anchors
        anchors = [s for s in statements if s.anchor_rules]
        anchors.sort(key=lambda s: (SEVERITY_WEIGHTS.get(s.severity, 0), -s.event_order), reverse=True)
        for s in anchors:
            phrase_len = len(s.rendered_phrase)
            if not strict_budget or (current_chars + phrase_len <= max_budget_chars):
                selected_ids.add(s.statement_id)
                selected_statements.append(s)
                current_chars += phrase_len

        # Step 2: Group unselected by category
        cat_map: Dict[str, List[BehaviorStatement]] = defaultdict(list)
        for s in statements:
            if s.statement_id not in selected_ids:
                cat_map[s.category].append(s)

        categories = list(cat_map.keys())
        added_any = True

        while added_any and current_chars < max_budget_chars:
            added_any = False
            for cat in categories:
                if cat_map[cat]:
                    candidate = cat_map[cat].pop(0)
                    phrase_len = len(candidate.rendered_phrase)
                    if current_chars + phrase_len <= max_budget_chars:
                        selected_ids.add(candidate.statement_id)
                        selected_statements.append(candidate)
                        current_chars += phrase_len
                        added_any = True

        selected_statements.sort(key=lambda s: s.event_order)
        return selected_statements
