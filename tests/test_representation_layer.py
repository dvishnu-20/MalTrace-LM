import tempfile
from pathlib import Path
import pytest

from maltrace.contracts.schemas import NormalizedEvent, BehaviorStatement
from maltrace.representation.renderer import render_event_statement, render_trace_statements, get_vocabulary
from maltrace.representation.anchors import evaluate_security_anchors
from maltrace.representation.grouping import build_process_behavior_summaries, build_trace_behavior_summary
from maltrace.representation.selector import DefaultBudgetSelector, FrontTruncationSelector, CategoryFrequencySelector
from maltrace.representation.exporter import export_behavior_jsonl, export_behavior_text
from maltrace.ingestion.stream_parser import stream_parse_file


def test_deterministic_rendering():
    evt = NormalizedEvent(
        sample_id="samp_10",
        event_id="evt_1001",
        event_order=1,
        process_id=1234,
        parent_process_id=1000,
        timestamp="2026-07-28T10:00:00Z",
        api_name="CreateProcessInternalW",
        category="process",
        safe_arguments={"image_name": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c dir"},
        source_file="sample.json"
    )

    stmt1 = render_event_statement(evt)
    stmt2 = render_event_statement(evt)

    assert stmt1.rendered_phrase == stmt2.rendered_phrase
    assert stmt1.statement_id == stmt2.statement_id
    assert stmt1.evidence_metadata == stmt2.evidence_metadata


def test_missing_fields_neutral_phrases():
    evt = NormalizedEvent(
        sample_id="samp_11",
        event_id="evt_1002",
        event_order=1,
        process_id=1234,
        parent_process_id=0,
        timestamp=None,
        api_name="WriteFile",
        category="file",
        safe_arguments={},  # Empty arguments - missing path and bytes
        source_file="sample.json"
    )

    stmt = render_event_statement(evt)
    assert "<unspecified path>" in stmt.rendered_phrase
    assert "proc_1234.exe" in stmt.rendered_phrase
    assert stmt.event_id == "evt_1002"


def test_security_anchors_detection():
    # Autorun registry write
    evt_reg = NormalizedEvent(
        sample_id="s", event_id="e1", event_order=1, process_id=100, parent_process_id=0,
        api_name="RegSetValueExW", category="registry", is_persistence=True,
        safe_arguments={"key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, source_file="f"
    )
    # Powershell launch
    evt_ps = NormalizedEvent(
        sample_id="s", event_id="e2", event_order=2, process_id=100, parent_process_id=0,
        api_name="CreateProcessInternalW", category="process",
        safe_arguments={"command_line": "powershell.exe -nop -w hidden"}, source_file="f"
    )
    # Defense impairment
    evt_vss = NormalizedEvent(
        sample_id="s", event_id="e3", event_order=3, process_id=100, parent_process_id=0,
        api_name="CreateProcessInternalW", category="process",
        safe_arguments={"command_line": "vssadmin.exe delete shadows /all"}, source_file="f"
    )

    stmt_reg = render_event_statement(evt_reg)
    stmt_ps = render_event_statement(evt_ps)
    stmt_vss = render_event_statement(evt_vss)

    assert "AutorunRegistryWrite" in stmt_reg.anchor_rules
    assert "CommandShellLaunch" in stmt_ps.anchor_rules
    assert "DefenseImpairment" in stmt_vss.anchor_rules


def test_anchor_retention_under_small_context_budget():
    evts = [
        # Non-anchor event
        NormalizedEvent(sample_id="s", event_id="e1", event_order=1, process_id=100, parent_process_id=0, api_name="NtCreateFile", category="file", safe_arguments={"path": "C:\\temp\\1.txt"}, source_file="f"),
        NormalizedEvent(sample_id="s", event_id="e2", event_order=2, process_id=100, parent_process_id=0, api_name="NtCreateFile", category="file", safe_arguments={"path": "C:\\temp\\2.txt"}, source_file="f"),
        # Anchor event (vssadmin delete shadows)
        NormalizedEvent(sample_id="s", event_id="e3", event_order=3, process_id=100, parent_process_id=0, api_name="CreateProcessInternalW", category="process", safe_arguments={"command_line": "vssadmin delete shadows /all"}, source_file="f"),
    ]

    stmts = render_trace_statements(evts)
    # Set a tiny budget (e.g. 100 chars) that cannot fit all 3 statements
    selected = DefaultBudgetSelector.select(stmts, max_budget_chars=100)

    # Anchor statement (e3) MUST be retained regardless of tight budget!
    selected_eids = [s.event_id for s in selected]
    assert "e3" in selected_eids


def test_alternative_budget_selectors():
    evts = [
        NormalizedEvent(sample_id="s", event_id=f"e{i}", event_order=i, process_id=100, parent_process_id=0, api_name="WriteFile", category="file", safe_arguments={"target_path": f"file_{i}.txt"}, source_file="f")
        for i in range(1, 10)
    ]
    stmts = render_trace_statements(evts)

    front_sel = FrontTruncationSelector.select(stmts, max_budget_chars=200)
    cat_sel = CategoryFrequencySelector.select(stmts, max_budget_chars=200)

    assert len(front_sel) > 0
    assert len(cat_sel) > 0
    assert front_sel[0].event_order == 1


def test_acceptance_gate_all_samples():
    samples_dir = Path("data/samples")
    assert samples_dir.exists()

    sample_files = sorted(list(samples_dir.glob("*.json")))
    assert len(sample_files) >= 6

    for sample_file in sample_files:
        gen = stream_parse_file(sample_file)
        events = list(gen)
        assert len(events) > 0

        stmts = render_trace_statements(events)
        assert len(stmts) == len(events)

        # Verify event ID traceability
        valid_eids = set(e.event_id for e in events)
        for s in stmts:
            assert s.event_id in valid_eids
            assert s.evidence_metadata["event_id"] in valid_eids

        # Test process and trace summaries
        proc_summaries = build_process_behavior_summaries(events, stmts)
        trace_summary = build_trace_behavior_summary(events, stmts)

        assert len(proc_summaries) > 0
        assert trace_summary.sample_id == events[0].sample_id

        # Verify small budget retention
        budget_selected = DefaultBudgetSelector.select(stmts, max_budget_chars=150)
        anchor_eids = set(s.event_id for s in stmts if s.anchor_rules)
        selected_eids = set(s.event_id for s in budget_selected)

        # Every mandatory anchor must remain present under small budget
        for a_eid in anchor_eids:
            assert a_eid in selected_eids, f"Anchor {a_eid} missing under small budget in {sample_file.name}"


def test_exporter():
    evts = [
        NormalizedEvent(sample_id="ex_1", event_id="e1", event_order=1, process_id=100, parent_process_id=0, api_name="NtCreateFile", category="file", safe_arguments={"target_path": "C:\\test.txt"}, source_file="f")
    ]
    stmts = render_trace_statements(evts)
    trace_sum = build_trace_behavior_summary(evts, stmts)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = Path(tmp)
        j_file = tmp_p / "out.jsonl"
        t_file = tmp_p / "out.txt"

        export_behavior_jsonl(stmts, j_file)
        export_behavior_text(trace_sum, t_file)

        assert j_file.exists()
        assert t_file.exists()

        content = j_file.read_text(encoding="utf-8")
        assert "e1" in content
        assert "NtCreateFile" in content
