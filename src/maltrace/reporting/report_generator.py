"""
Deterministic analyst report generator.
Generates comprehensive analyst reports (Executive Summary, Family & Confidence, Observed Categories,
ATT&CK Techniques, Process Tree Overview, Evidence Table, Uncertainty & Limitations)
completely deterministically without external LLM dependencies, exporting JSON, Markdown, and HTML.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Union, Optional

from maltrace.contracts.schemas import AnalysisResult, AnalystReport, EvidenceReference, TechniquePrediction


def generate_deterministic_analyst_report(result: AnalysisResult) -> AnalystReport:
    """
    Generate an AnalystReport strictly using predefined templates populated with validated fields.
    """
    fam = result.family_prediction
    proc_count = len(result.process_summaries)
    cats = sorted(result.trace_summary.get("categories_found", []))
    cats_str = ", ".join(cats) if cats else "none"

    exec_summary = (
        f"Executive Summary: Execution trace sample '{result.sample_id}' exhibits behavior "
        f"classified under family '{fam.family_name}' with {fam.confidence_label} confidence ({fam.confidence:.2f}). "
        f"The trace contains {proc_count} processes interacting across behavioral categories [{cats_str}]. "
        f"Primary classification signal: '{fam.rule_triggered}'."
    )

    # Process tree overview
    tree_overview = []
    for proc in result.process_summaries:
        tree_overview.append({
            "process_id": proc.process_id,
            "process_name": proc.process_name,
            "parent_process_id": proc.parent_process_id,
            "lineage_path": proc.readable_path or proc.process_name,
            "is_root": proc.is_root,
            "categories_observed": proc.categories_observed
        })

    # Defensive recommendations
    recommendations = [
        "Isolate affected host endpoint from local network subnets.",
        "Terminate processes associated with suspicious command execution lineage.",
        "Block outbound remote IP destinations identified in network event citations.",
        "Audit autostart registry keys and scheduled tasks for unauthorized persistence entries."
    ]

    uncertainty_text = (
        "Uncertainty & Limitations: Analysis is strictly grounded in observed trace events. "
        "Unexecuted code branches, dynamic evasion delays, and kernel driver interactions not present in the "
        "input trace log are outside the scope of this report. Categorical assertions reflect deterministic evidence linkage."
    )

    return AnalystReport(
        sample_id=result.sample_id,
        generation_mode="deterministic",
        executive_summary=exec_summary,
        predicted_family=fam.family_name,
        confidence=fam.confidence,
        confidence_label=fam.confidence_label,
        signal_triggered=fam.rule_triggered,
        observed_categories=cats,
        attack_techniques=result.technique_predictions,
        process_tree_overview=tree_overview,
        key_evidence_table=result.cited_evidence,
        uncertainty_and_limitations=uncertainty_text,
        analyst_recommendations=recommendations,
        verification_summary=result.verification_summary,
        manifest=result.manifest,
        schema_version="1.0.0"
    )


def render_report_json(report: AnalystReport) -> str:
    """
    Export AnalystReport as formatted JSON string.
    """
    return json.dumps(report.model_dump(), indent=2)


def render_report_markdown(report: AnalystReport) -> str:
    """
    Export AnalystReport as Markdown document.
    """
    md = []
    md.append(f"# MalTrace-LM Defensive Analyst Report: {report.sample_id}")
    md.append(f"**Generation Mode**: `{report.generation_mode.upper()}` | **Schema Version**: `{report.schema_version}`\n")
    md.append("---")
    md.append("## Executive Summary")
    md.append(f"> {report.executive_summary}\n")

    md.append("## Classification & Primary Signal")
    md.append(f"- **Predicted Family**: `{report.predicted_family}`")
    md.append(f"- **Confidence**: `{report.confidence:.2f}` ({report.confidence_label})")
    md.append(f"- **Signal / Rule Triggered**: `{report.signal_triggered}`")
    md.append(f"- **Observed Categories**: {', '.join([f'`{c}`' for c in report.observed_categories])}\n")

    if report.verification_summary:
        v = report.verification_summary
        md.append("## Evidence Verification Audit Summary")
        md.append(f"- **Claims Analyzed**: `{v.total_claims}` (Supported: `{v.supported_claims}`, Partially Supported: `{v.partially_supported_claims}`, Rejected: `{v.rejected_claims}`)")
        md.append(f"- **Citation Completeness**: `{v.citation_completeness * 100:.1f}%`")
        if v.family_abstained:
            md.append(f"- **Family Prediction Status**: `ABSTAINED` ({v.abstention_reason})")
        else:
            md.append("- **Family Prediction Status**: `VALIDATED`")
        md.append("")

    md.append("## Mapped MITRE ATT&CK Techniques")
    if report.attack_techniques:
        for t in report.attack_techniques:
            review_flag = " **[NEEDS REVIEW]**" if t.needs_review else ""
            md.append(f"### [{t.technique_id}] {t.technique_name}{review_flag}")
            md.append(f"- **Tactic**: `{t.tactic}` | **Confidence**: `{t.confidence:.2f}` ({t.confidence_label})")
            md.append(f"- **Matched Rules**: `{', '.join(t.matched_rules)}`")
            md.append(f"- **Supporting Evidence Event IDs**: `{', '.join(t.supporting_evidence_ids)}`")
            md.append(f"- **Explanation**: {t.explanation}\n")
    else:
        md.append("_No specific MITRE ATT&CK techniques mapped._\n")

    md.append("## Process Tree Overview")
    for p in report.process_tree_overview:
        root_tag = " [ROOT]" if p["is_root"] else ""
        md.append(f"- **PID {p['process_id']}**: `{p['process_name']}`{root_tag} (Parent PID: {p['parent_process_id']})")
        md.append(f"  - Lineage: `{p['lineage_path']}`")
        md.append(f"  - Categories: {', '.join(p['categories_observed'])}\n")

    md.append("## Key Evidence Table")
    md.append("| Event ID | Order | Category | API Name | Snippet |")
    md.append("|---|---|---|---|---|")
    for ev in report.key_evidence_table:
        md.append(f"| `{ev.event_id}` | {ev.event_order} | `{ev.category}` | `{ev.api_name}` | {ev.snippet} |")
    md.append("")

    md.append("## Defensive Recommendations")
    for r in report.analyst_recommendations:
        md.append(f"- {r}")
    md.append("")

    md.append("## Uncertainty & Limitations")
    md.append(f"_{report.uncertainty_and_limitations}_\n")

    return "\n".join(md)


def render_report_html(report: AnalystReport) -> str:
    """
    Export AnalystReport as a styled, printable HTML document.
    """
    tech_rows = ""
    for t in report.attack_techniques:
        badge = "<span style='color: #d97706; font-weight: bold;'>[NEEDS REVIEW]</span>" if t.needs_review else ""
        tech_rows += f"""
        <div style="border: 1px solid #e5e7eb; padding: 12px; border-radius: 6px; margin-bottom: 12px;">
            <h4 style="margin: 0 0 6px 0;"><code>{t.technique_id}</code> - {t.technique_name} {badge}</h4>
            <p style="margin: 4px 0; color: #4b5563;"><b>Tactic:</b> {t.tactic} | <b>Confidence:</b> {t.confidence:.2f} ({t.confidence_label})</p>
            <p style="margin: 4px 0; color: #4b5563;"><b>Matched Rules:</b> <code>{', '.join(t.matched_rules)}</code></p>
            <p style="margin: 4px 0; color: #4b5563;"><b>Evidence IDs:</b> <code>{', '.join(t.supporting_evidence_ids)}</code></p>
            <p style="margin: 4px 0;"><i>{t.explanation}</i></p>
        </div>
        """

    evidence_rows = ""
    for ev in report.key_evidence_table:
        evidence_rows += f"""
        <tr>
            <td><code>{ev.event_id}</code></td>
            <td>{ev.event_order}</td>
            <td><code>{ev.category}</code></td>
            <td><code>{ev.api_name}</code></td>
            <td>{ev.snippet}</td>
        </tr>
        """

    proc_rows = ""
    for p in report.process_tree_overview:
        proc_rows += f"<li><b>PID {p['process_id']}</b>: <code>{p['process_name']}</code> - <i>{p['lineage_path']}</i></li>"

    recs_list = "".join([f"<li>{r}</li>" for r in report.analyst_recommendations])

    verifier_html = ""
    if report.verification_summary:
        v = report.verification_summary
        status_text = f"<span style='color: #dc2626; font-weight: bold;'>ABSTAINED</span> ({v.abstention_reason})" if v.family_abstained else "<span style='color: #16a34a; font-weight: bold;'>PASSED</span>"
        verifier_html = f"""
        <div style="background-color: #f8fafc; border: 1px solid #cbd5e1; border-left: 4px solid #64748b; padding: 16px; margin: 16px 0; border-radius: 0 6px 6px 0;">
            <h3 style="margin-top: 0; color: #334155;">🔍 Evidence Verification Audit Summary</h3>
            <p style="margin: 4px 0;"><b>Total Claims:</b> {v.total_claims} | <b>Supported:</b> {v.supported_claims} | <b>Partially Supported:</b> {v.partially_supported_claims} | <b>Rejected:</b> {v.rejected_claims}</p>
            <p style="margin: 4px 0;"><b>Citation Completeness:</b> {v.citation_completeness * 100:.1f}%</p>
            <p style="margin: 4px 0;"><b>Verification Status:</b> {status_text}</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MalTrace-LM Analyst Report - {report.sample_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.5; color: #1f2937; max-width: 900px; margin: 40px auto; padding: 0 20px; }}
        h1 {{ color: #1e3a8a; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }}
        h2 {{ color: #1e40af; margin-top: 24px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; background: #eff6ff; color: #1d4ed8; font-weight: 600; font-size: 0.85em; }}
        .summary-box {{ background-color: #f8fafc; border-left: 4px solid #3b82f6; padding: 16px; margin: 16px 0; border-radius: 0 6px 6px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.9em; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background-color: #f3f4f6; color: #374151; }}
        code {{ background-color: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; color: #0f172a; }}
    </style>
</head>
<body>
    <h1>🛡️ MalTrace-LM Defensive Analyst Report</h1>
    <p><b>Sample ID:</b> <code>{report.sample_id}</code> | <span class="badge">Mode: {report.generation_mode.upper()}</span></p>
    
    <div class="summary-box">
        <h3 style="margin-top: 0;">Executive Summary</h3>
        <p>{report.executive_summary}</p>
    </div>

    {verifier_html}

    <h2>Malware Family Prediction</h2>
    <p><b>Predicted Family:</b> <code>{report.predicted_family}</code> (Confidence: <b>{report.confidence:.2f}</b> - {report.confidence_label})</p>
    <p><b>Primary Triggered Signal:</b> <code>{report.signal_triggered}</code></p>
    <p><b>Observed Categories:</b> <code>{', '.join(report.observed_categories)}</code></p>

    <h2>Mapped MITRE ATT&CK Techniques</h2>
    {tech_rows if tech_rows else "<p>No specific ATT&CK techniques mapped.</p>"}

    <h2>Process Tree Overview</h2>
    <ul>{proc_rows}</ul>

    <h2>Key Cited Evidence Table</h2>
    <table>
        <thead>
            <tr>
                <th>Event ID</th>
                <th>Order</th>
                <th>Category</th>
                <th>API Name</th>
                <th>Snippet</th>
            </tr>
        </thead>
        <tbody>
            {evidence_rows}
        </tbody>
    </table>

    <h2>Defensive Recommendations</h2>
    <ul>{recs_list}</ul>

    <h2>Uncertainty & Limitations</h2>
    <p><i>{report.uncertainty_and_limitations}</i></p>
</body>
</html>
"""
    return html

