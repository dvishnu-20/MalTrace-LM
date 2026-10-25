"""
MalTrace-LM Streamlit Analyst Dashboard Application.
Multi-page service-backed analyst workflow interacting with the MalTrace-LM FastAPI REST service.
Includes Analyze, Results, Diff Studio, Sigma Rules & IDS, Anomaly Detection, Evidence Inspector, and History pages.
"""

import os
from pathlib import Path
import json
from typing import Dict, Any, List, Optional, Union
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

from maltrace.dashboard.api_client import MalTraceAPIClient, APIError, APIConnectionError
from maltrace.features.trace_diff import compute_trace_diff
from maltrace.detection.sigma_matcher import BehavioralSigmaEngine
from maltrace.detection.ids_generator import generate_suricata_rules, generate_snort_rules, extract_network_indicators
from maltrace.models.anomaly import BehavioralAnomalyDetector
from maltrace.ingestion.loader import load_trace_file
from maltrace.representation.normalizer import normalize_trace_events
from maltrace.reporting.report_generator import generate_deterministic_analyst_report, render_report_html, render_report_markdown
from maltrace.contracts.schemas import AnalysisResult, ProcessSummary
from maltrace.visualization.process_graph import generate_process_tree_html
from maltrace.visualization.timeline import generate_event_timeline_html

# Page Config & Layout
st.set_page_config(
    page_title="MalTrace-LM Analyst Portal",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cybersecurity Styling
st.markdown("""
<style>
    .main-header { font-size: 2.2rem; font-weight: 700; color: #1e3a8a; margin-bottom: 0.2rem; }
    .sub-header { font-size: 1.0rem; color: #475569; margin-bottom: 1.5rem; }
    .status-badge-ok { background-color: #dcfce7; color: #166534; padding: 4px 10px; border-radius: 12px; font-weight: 600; font-size: 0.85rem; }
    .status-badge-err { background-color: #fee2e2; color: #991b1b; padding: 4px 10px; border-radius: 12px; font-weight: 600; font-size: 0.85rem; }
    .card-box { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .scorecard-metric { font-size: 1.5rem; font-weight: 700; color: #0f172a; }
</style>
""", unsafe_allow_html=True)


def get_clean_analysis_result(data: Any) -> Dict[str, Any]:
    """Helper to safely extract result dictionary whether raw AnalysisResult dict or wrapped API response."""
    if isinstance(data, dict):
        if "result" in data and isinstance(data["result"], dict):
            return data["result"]
        return data
    return {}


# Initialize API Client & Session State
api_url_input = os.environ.get("MALTRACE_API_URL", "http://127.0.0.1:8000")

if "active_analysis_id" not in st.session_state:
    st.session_state.active_analysis_id = None
if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None
if "active_trace_path" not in st.session_state:
    st.session_state.active_trace_path = "data/samples/ransomware_lockbit.json"

# Sidebar Configuration & Navigation
st.sidebar.markdown("## MalTrace-LM Portal")
st.sidebar.caption("Defensive Behavioral Trace Analysis System")

api_url = st.sidebar.text_input("API Service Endpoint", value=api_url_input)
client = MalTraceAPIClient(base_url=api_url)

# Health Check & Status Badge
try:
    health = client.check_health()
    st.sidebar.markdown('<span class="status-badge-ok">[ONLINE] API Service Connected</span>', unsafe_allow_html=True)
except APIConnectionError:
    st.sidebar.markdown('<span class="status-badge-err">[OFFLINE] API Server Disconnected</span>', unsafe_allow_html=True)
    st.sidebar.error("FastAPI server is offline. Run `maltrace serve` in terminal.")
except Exception as err:
    st.sidebar.warning(f"API Health Warning: {err}")

st.sidebar.markdown("---")

navigation_page = st.sidebar.radio(
    "Analyst Workflow Navigation",
    [
        "Analyze Trace",
        "Analysis Results",
        "Diff Studio",
        "Sigma Rules & IDS",
        "Anomaly & Novelty",
        "Evidence Inspector",
        "Persisted History"
    ],
    index=0
)

st.sidebar.markdown("---")
st.sidebar.info("Tip: Select a sample preset or upload a JSON trace on the Analyze Trace page to begin.")


# ==============================================================================
# PAGE 1: ANALYZE TRACE
# ==============================================================================
if navigation_page == "Analyze Trace":
    st.markdown('<div class="main-header">Analyze Execution Trace</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Upload a Windows API execution trace JSON log for evidence verification and ATT&CK mapping.</div>', unsafe_allow_html=True)

    st.warning("""
    **Defensive Safety Boundary Notice**: MalTrace-LM operates strictly on offline, structured JSON execution logs.
    It contains **no** binary payload execution, active network scanning, or offensive exploit routines.
    """)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("1. File Upload")
        uploaded_file = st.file_uploader(
            "Select Windows Execution Trace (.json) - Max size 10MB",
            type=["json"],
            help="Upload structured WinMET or JSON execution trace log."
        )

    with col2:
        st.subheader("2. Sample Presets")
        sample_choice = st.selectbox(
            "Or Choose Built-in Fixture:",
            [
                "[Select Preset]",
                "ransomware_lockbit.json",
                "ransomware_wannacry.json",
                "infostealer_agenttesla.json",
                "infostealer_redline.json",
                "wiper_hermetic.json",
                "loader_qakbot.json",
                "trojan_asyncrat.json",
                "dropper_emotet.json",
                "coinminer_xmrig.json",
                "benign_notepad.json"
            ]
        )

    st.markdown("---")

    file_bytes = None
    filename = None

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        filename = uploaded_file.name
        scratch_p = Path("data/scratch") / f"active_{uploaded_file.name}"
        scratch_p.parent.mkdir(parents=True, exist_ok=True)
        scratch_p.write_bytes(file_bytes)
        st.session_state.active_trace_path = str(scratch_p)
        st.session_state.active_trace_name = filename
    elif sample_choice != "[Select Preset]":
        preset_path = Path("data/samples") / sample_choice
        if preset_path.exists():
            file_bytes = preset_path.read_bytes()
            filename = sample_choice
            st.session_state.active_trace_path = str(preset_path)
            st.session_state.active_trace_name = filename


    if file_bytes and filename:
        st.info(f"Selected Trace File: **{filename}** ({len(file_bytes)} bytes)")
        if st.button("Run Defensive Analysis Pipeline", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()

            try:
                status_text.text("Uploading trace file to FastAPI service...")
                progress_bar.progress(30)

                resp = client.analyze_file(file_bytes=file_bytes, filename=str(filename))
                progress_bar.progress(70)

                status_text.text("Retrieving verified analysis results...")
                aid = resp["analysis_id"]


                full_data = client.get_analysis(aid)
                progress_bar.progress(100)

                st.session_state.active_analysis_id = aid
                # Extract clean result dictionary directly
                st.session_state.analysis_data = get_clean_analysis_result(full_data)

                try:
                    if st.session_state.get("active_trace_path"):
                        raw_trace_obj = load_trace_file(Path(st.session_state.active_trace_path))
                        st.session_state.active_normalized_events = normalize_trace_events(raw_trace_obj.events)
                except Exception:
                    pass

                status_text.empty()
                progress_bar.empty()

                st.success(f"Analysis successfully completed! Generated Analysis ID: `{aid}`")
                st.markdown("**Navigate to the 'Analysis Results' tab in sidebar to view findings.**")

            except APIError as e:
                progress_bar.empty()
                status_text.empty()
                st.error(f"Analysis Error: {e}")
            except Exception as e:
                progress_bar.empty()
                status_text.empty()
                st.error(f"Execution Error: {e}")


# ==============================================================================
# PAGE 2: ANALYSIS RESULTS
# ==============================================================================
elif navigation_page == "Analysis Results":
    st.markdown('<div class="main-header">Analysis Findings & ATT&CK Mapping</div>', unsafe_allow_html=True)

    if not st.session_state.analysis_data:
        st.info("No active analysis in session. Please run an analysis on the **'Analyze Trace'** page first.")
    else:
        res = get_clean_analysis_result(st.session_state.analysis_data)
        fam = res.get("family_prediction") or {}
        techniques = res.get("technique_predictions") or []
        evidence = res.get("cited_evidence") or []
        claims = res.get("behavior_claims") or []

        # Scorecard Row
        sc1, sc2, sc3, sc4 = st.columns(4)
        with sc1:
            st.metric("Malware Family", fam.get("family_name", "Unknown"))
        with sc2:
            conf_val = fam.get("confidence", 0.0)
            st.metric("Confidence Score", f"{conf_val * 100:.1f}%", fam.get("confidence_label", "Unknown"))
        with sc3:
            st.metric("ATT&CK Techniques", len(techniques))
        with sc4:
            st.metric("Cited Evidence Events", len(evidence))

        st.markdown("---")

        # Executive Summary Box
        st.subheader("Executive Behavioral Summary")
        summary_text = res.get("behavior_summary") or res.get("summary")
        if not summary_text:
            fam_name = fam.get("family_name", "Unclassified")
            conf_pct = f"{fam.get('confidence', 0.0) * 100:.1f}%"
            tech_count = len(techniques)
            ev_count = len(evidence)
            claims_count = len(claims)
            summary_text = (
                f"Automated behavioral analysis identified high-confidence indicators corresponding to {fam_name} "
                f"({conf_pct} confidence). The execution trace exhibits {claims_count} verified behavioral claim(s) "
                f"and maps directly to {tech_count} MITRE ATT&CK technique(s) supported by {ev_count} cited forensic evidence event(s)."
            )
        st.info(summary_text)

        # Tabbed Findings View
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "MITRE ATT&CK Matrix",
            "Behavior Statements",
            "Process Execution Graph",
            "Chronological Timeline",
            "Download Reports"
        ])

        with tab1:
            st.subheader("Mapped MITRE ATT&CK Techniques")
            if techniques:
                t_data = []
                for t in techniques:
                    t_data.append({
                        "Technique ID": t.get("technique_id"),
                        "Technique Name": t.get("technique_name"),
                        "Tactic": t.get("tactic"),
                        "Confidence": f"{t.get('confidence', 0.0)*100:.0f}%",
                        "Matched Rules": ", ".join(t.get("matched_rules", [])),
                        "Evidence IDs": ", ".join(t.get("supporting_evidence_ids", []))
                    })
                df_tech = pd.DataFrame(t_data)
                st.dataframe(df_tech, use_container_width=True)
            else:
                st.warning("No high-confidence threat techniques mapped.")

        with tab2:
            st.subheader("Verified Behavior Statements")
            if claims:
                for c in claims:
                    cat = c.get("category") or c.get("claim_category", "Behavior")
                    stmt = c.get("description") or c.get("statement", "Observed trace execution behavior")
                    ev_ids = c.get("evidence_event_ids") or []
                    ev_str = f" *(Cited Evidence: `{', '.join(ev_ids)}`)*" if ev_ids else ""
                    conf = float(c.get("confidence", 1.0))
                    ver_status = "[SUPPORTED]" if (c.get("support_status") == "supported" or conf >= 0.7 or len(ev_ids) > 0) else "[NEEDS REVIEW]"
                    st.markdown(f"- **{ver_status}** — **[{cat}]**: {stmt}{ev_str}")
            else:
                st.info("No behavior claims recorded.")

        with tab3:
            st.subheader("Process Execution Hierarchy & Graph")
            procs = res.get("process_summaries", [])
            if procs:
                try:
                    proc_objs = [ProcessSummary(**p) for p in procs]
                    p_html = generate_process_tree_html(proc_objs, title=f"Process Tree for {res.get('sample_id', 'Trace')}")
                    components.html(p_html, height=450, scrolling=True)
                except Exception:
                    pass

                with st.expander("View Raw Process Lineage Paths", expanded=False):
                    for p in procs:
                        st.code(f"PID {p.get('process_id')}: {p.get('process_name')} | Lineage: {p.get('readable_path')}")
            else:
                st.info("No process execution trees recorded.")

        with tab4:
            st.subheader("Interactive Event Timeline")
            norm_evs = st.session_state.get("active_normalized_events")
            if not norm_evs and st.session_state.get("active_trace_path"):
                try:
                    r_t = load_trace_file(Path(st.session_state.active_trace_path))
                    norm_evs = normalize_trace_events(r_t.events)
                    st.session_state.active_normalized_events = norm_evs
                except Exception:
                    pass

            if norm_evs:
                t_html = generate_event_timeline_html(norm_evs, title=f"Event Timeline for {res.get('sample_id', 'Trace')}")
                components.html(t_html, height=450, scrolling=True)
            else:
                st.info("Upload or select a trace fixture to display chronological event execution timeline.")

        with tab5:
            st.subheader("Export Analyst Artifacts & Reports")
            aid = st.session_state.active_analysis_id
            sample_name = res.get('sample_id', 'analysis')

            # Fetch or generate HTML and Markdown reports
            html_report_str = None
            md_report_str = None

            if aid:
                try:
                    html_report_str = client.get_report(aid, format="html")
                except Exception:
                    pass
                try:
                    md_report_str = client.get_report(aid, format="markdown")
                except Exception:
                    pass

            if not html_report_str or not md_report_str:
                try:
                    analysis_obj = AnalysisResult(**res)
                    analyst_rep = generate_deterministic_analyst_report(analysis_obj)
                    if not html_report_str:
                        html_report_str = render_report_html(analyst_rep)
                    if not md_report_str:
                        md_report_str = render_report_markdown(analyst_rep)
                except Exception:
                    pass

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                if html_report_str:
                    st.download_button(
                        "Download HTML Report",
                        data=str(html_report_str),
                        file_name=f"{sample_name}_report.html",
                        mime="text/html",
                        type="primary"
                    )
            with c2:
                if md_report_str:
                    st.download_button(
                        "Download Markdown Report",
                        data=str(md_report_str),
                        file_name=f"{sample_name}_report.md",
                        mime="text/markdown"
                    )
            with c3:
                st.download_button(
                    "Download JSON Analysis",
                    data=json.dumps(res, indent=2),
                    file_name=f"{sample_name}_result.json",
                    mime="application/json"
                )
            with c4:
                try:
                    nav_data = client.get_navigator_layer(aid) if aid else None
                    if nav_data:
                        st.download_button(
                            "Download ATT&CK Navigator",
                            data=json.dumps(nav_data, indent=2),
                            file_name=f"{sample_name}_navigator_layer.json",
                            mime="application/json"
                        )
                except Exception:
                    pass

            st.markdown("---")
            st.subheader("Interactive Incident Report Preview")
            if html_report_str:
                with st.expander("View Rendered HTML Incident Report", expanded=True):
                    components.html(str(html_report_str), height=600, scrolling=True)
            elif md_report_str:
                with st.expander("View Markdown Incident Report", expanded=True):
                    st.markdown(md_report_str)



# ==============================================================================
# PAGE 3: DIFF STUDIO
# ==============================================================================
elif navigation_page == "Diff Studio":
    st.markdown('<div class="main-header">Multi-Trace Differential Analysis Studio</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Compare two execution traces side-by-side to detect behavioral shifts, mutated processes, and shared C2.</div>', unsafe_allow_html=True)

    active_p_str = st.session_state.get("active_trace_path")
    active_name = st.session_state.get("active_trace_name", "active_trace.json")
    has_active = bool(active_p_str and Path(active_p_str).exists())

    if has_active:
        st.success(f"**[ACTIVE] Baseline Trace A Loaded:** `{active_name}` (automatically defaulted as Baseline Trace A)")

    diff_modes = ["Use Active Trace as Baseline (A)", "Upload Custom JSON Files"] if has_active else ["Upload Custom JSON Files"]
    input_mode = st.radio("Source Mode:", diff_modes, horizontal=True, index=0)

    p_a = None
    p_b = None
    temp_dir = Path("data/scratch")
    temp_dir.mkdir(parents=True, exist_ok=True)

    if input_mode == "Use Active Trace as Baseline (A)":
        p_a = Path(str(active_p_str)) if (has_active and active_p_str) else None
        col_b1, col_b2 = st.columns(2)
        with col_b1:
            st.subheader(f"Baseline Trace (A): `{active_name if has_active else 'None'}`")
            st.info("Using your currently analyzed trace as Baseline (A).")
        with col_b2:
            st.subheader("Select Comparison Variant (B)")
            var_mode = st.radio("Variant B Source:", ["Built-in Preset", "Upload Custom File"], horizontal=True, key="diff_b_mode")
            if var_mode == "Built-in Preset":
                samples = [f.name for f in Path("data/samples").glob("*.json")]
                trace_b_name = st.selectbox("Select Variant Trace (B):", samples, index=1 if len(samples) > 1 else 0, key="diff_b_preset")
                p_b = Path("data/samples") / trace_b_name
            else:
                file_b = st.file_uploader("Upload Variant Trace B (.json):", type=["json"], key="diff_b_upload")
                if file_b:
                    p_b = temp_dir / f"diff_b_{file_b.name}"
                    p_b.write_bytes(file_b.getvalue())
                else:
                    st.info("Please upload Variant Trace B to compare against Active Baseline (A).")


    elif input_mode == "Upload Custom JSON Files":
        col_u1, col_u2 = st.columns(2)
        with col_u1:
            st.subheader("Baseline Trace (A)")
            file_a = st.file_uploader("Upload Trace A (.json):", type=["json"], key="diff_file_a")
        with col_u2:
            st.subheader("Variant Trace (B)")
            file_b = st.file_uploader("Upload Trace B (.json):", type=["json"], key="diff_file_b")

        if file_a and file_b:
            p_a = temp_dir / f"diff_a_{file_a.name}"
            p_b = temp_dir / f"diff_b_{file_b.name}"
            p_a.write_bytes(file_a.getvalue())
            p_b.write_bytes(file_b.getvalue())
            st.success(f"Ready to compare `{file_a.name}` vs `{file_b.name}`")
        else:
            st.info("Please upload both JSON trace files to perform differential comparison.")

    if p_a and p_b and st.button("Run Differential Comparison", type="primary"):
        diff_res = compute_trace_diff(p_a, p_b)

        st.subheader(f"Behavioral Similarity: **{diff_res.behavioral_similarity_score * 100:.1f}%**")
        st.info(diff_res.summary)

        dc1, dc2 = st.columns(2)
        with dc1:
            st.markdown(f"#### Trace A Highlights (`{diff_res.sample_a_id}`)")
            st.write(f"- **Total Events:** {diff_res.total_events_a}")
            st.write(f"- **Unique Techniques:** `{', '.join(diff_res.unique_techniques_a) or 'None'}`")
            st.write(f"- **Unique Processes:** `{', '.join(diff_res.unique_processes_a) or 'None'}`")
            if diff_res.unique_network_destinations_a:
                st.write(f"- **Unique Network IOCs:** `{', '.join(diff_res.unique_network_destinations_a)}`")
        with dc2:
            st.markdown(f"#### Trace B Highlights (`{diff_res.sample_b_id}`)")
            st.write(f"- **Total Events:** {diff_res.total_events_b}")
            st.write(f"- **Unique Techniques:** `{', '.join(diff_res.unique_techniques_b) or 'None'}`")
            st.write(f"- **Unique Processes:** `{', '.join(diff_res.unique_processes_b) or 'None'}`")
            if diff_res.unique_network_destinations_b:
                st.write(f"- **Unique Network IOCs:** `{', '.join(diff_res.unique_network_destinations_b)}`")

        st.markdown("#### Shared Threat Infrastructure")
        st.success(f"**Shared ATT&CK Techniques:** `{', '.join(diff_res.shared_attack_techniques) or 'None'}`")
        st.success(f"**Shared Processes:** `{', '.join(diff_res.shared_processes) or 'None'}`")


# ==============================================================================
# PAGE 4: SIGMA RULES & IDS GENERATOR
# ==============================================================================
elif navigation_page == "Sigma Rules & IDS":
    st.markdown('<div class="main-header">Behavioral Sigma Rules & IDS Generator</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Evaluate behavioral detection rules and generate ready-to-deploy Suricata / Snort network signatures.</div>', unsafe_allow_html=True)

    active_p_str = st.session_state.get("active_trace_path")
    active_name = st.session_state.get("active_trace_name", "active_trace.json")
    has_active = bool(active_p_str and Path(active_p_str).exists())

    sig_options = [f"Active Trace ({active_name})", "Upload Custom JSON File"] if has_active else ["Upload Custom JSON File"]
    sig_mode = st.radio("Select Input Trace:", sig_options, horizontal=True, key="sig_mode", index=0)

    sample_p = None
    if sig_mode.startswith("Active Trace") and active_p_str:
        sample_p = Path(str(active_p_str))
    elif sig_mode == "Upload Custom JSON File":
        up_sig = st.file_uploader("Upload Execution Trace (.json):", type=["json"], key="up_sig_file")
        if up_sig:
            temp_p = Path("data/scratch") / f"sig_{up_sig.name}"
            temp_p.parent.mkdir(parents=True, exist_ok=True)
            temp_p.write_bytes(up_sig.getvalue())
            sample_p = temp_p
        else:
            st.info("Please upload a JSON trace file to evaluate behavioral Sigma rules.")

    if sample_p and sample_p.exists():
        raw_t = load_trace_file(sample_p)
        norm_t = normalize_trace_events(raw_t.events)

        tab_sig, tab_ids = st.tabs(["Behavioral Sigma Matching", "Network IDS Rules (Suricata/Snort)"])

        with tab_sig:
            st.subheader(f"Evaluated Sigma Rules on `{sample_p.name}`")
            engine = BehavioralSigmaEngine()
            matches = engine.evaluate_trace(norm_t)

            if matches:
                st.success(f"**{len(matches)} Behavioral Detection Rules Matched** on `{sample_p.name}`:")
                for m in matches:
                    st.markdown(f"- **[{m.level.upper()}] {m.rule_id}**: {m.rule_title}")
                    st.caption(f"Description: {m.description} | Matched Events: {m.matched_event_ids} | Tags: {m.tags}")
            else:
                st.info("No built-in behavioral Sigma rules matched this trace.")

        with tab_ids:
            st.subheader(f"Auto-Generated Intrusion Detection Signatures for `{sample_p.name}`")
            inds = extract_network_indicators(norm_t, sample_id=raw_t.sample_id, predicted_family=raw_t.sample_id)
            if inds:
                suricata_text = generate_suricata_rules(inds)
                snort_text = generate_snort_rules(inds)

                st.code(suricata_text, language="text")
                st.download_button(
                    "Download Suricata .rules File",
                    data=suricata_text,
                    file_name=f"{raw_t.sample_id}_suricata.rules",
                    mime="text/plain"
                )
            else:
                st.info("No outbound network connections observed in this trace fixture.")


# ==============================================================================
# PAGE 5: ANOMALY & NOVELTY
# ==============================================================================
elif navigation_page == "Anomaly & Novelty":
    st.markdown('<div class="main-header">Behavioral Anomaly & Zero-Day Detection</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Measure behavioral statistical divergence from baseline activity using Isolation Forests.</div>', unsafe_allow_html=True)

    active_p_str = st.session_state.get("active_trace_path")
    active_name = st.session_state.get("active_trace_name", "active_trace.json")
    has_active = bool(active_p_str and Path(active_p_str).exists())

    anom_options = [f"Active Trace ({active_name})", "Upload Custom JSON File"] if has_active else ["Upload Custom JSON File"]
    anom_mode = st.radio("Select Input Trace:", anom_options, horizontal=True, key="anom_mode", index=0)

    sample_p = None
    if anom_mode.startswith("Active Trace") and active_p_str:
        sample_p = Path(str(active_p_str))
    elif anom_mode == "Upload Custom JSON File":
        up_anom = st.file_uploader("Upload Execution Trace (.json):", type=["json"], key="up_anom_file")
        if up_anom:
            temp_p = Path("data/scratch") / f"anom_{up_anom.name}"
            temp_p.parent.mkdir(parents=True, exist_ok=True)
            temp_p.write_bytes(up_anom.getvalue())
            sample_p = temp_p
        else:
            st.info("Please upload a JSON trace file to evaluate behavioral anomalies.")



    if sample_p and sample_p.exists():
        raw_t = load_trace_file(sample_p)
        norm_t = normalize_trace_events(raw_t.events)

        detector = BehavioralAnomalyDetector()
        res_anom = detector.evaluate_trace(norm_t)

        a_col1, a_col2 = st.columns(2)
        with a_col1:
            st.metric("Anomaly Score", f"{res_anom['anomaly_score']:.3f}", res_anom["confidence_label"])
        with a_col2:
            status_text = "HIGH DIVERGENCE (ZERO-DAY PROFILE)" if res_anom["is_anomaly"] else "NORMAL EXECUTION PATTERN"

            st.markdown(f"### Status: **{status_text}**")

        st.markdown("---")
        st.subheader("Divergence Factor Analysis")
        if res_anom["divergence_factors"]:
            for dfactor in res_anom["divergence_factors"]:
                st.warning(f"[DIVERGENCE FACTOR] {dfactor}")
        else:
            st.success("No abnormal behavioral spikes detected.")


# ==============================================================================
# PAGE 6: EVIDENCE INSPECTOR
# ==============================================================================
elif navigation_page == "Evidence Inspector":
    st.markdown('<div class="main-header">Evidence Inspector & Raw Trace Lookup</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Perform granular auditing on individual event IDs and verify arguments.</div>', unsafe_allow_html=True)

    if not st.session_state.analysis_data:
        st.info("No active analysis in session. Please run an analysis on the **'Analyze Trace'** page first.")
    else:
        res = get_clean_analysis_result(st.session_state.analysis_data)
        tab_ev1, tab_ev2, tab_ev3 = st.tabs(["Lookup by Event ID", "Cited Evidence Table", "Full JSON Document"])

        with tab_ev1:
            st.subheader("Individual Event Audit")
            cited_ev_ids = [ev.get("event_id") for ev in res.get("cited_evidence", []) if ev.get("event_id")]

            col_in1, col_in2 = st.columns([1, 2])
            with col_in1:
                if cited_ev_ids:
                    selected_ev = st.selectbox("Quick-Select Cited Event:", ["-- Custom Entry --"] + cited_ev_ids)
                else:
                    selected_ev = "-- Custom Entry --"
            with col_in2:
                default_val = selected_ev if selected_ev != "-- Custom Entry --" else ""
                ev_input = st.text_input("Enter Event ID (e.g. evt_0001, evt_1001, sysmon_0001):", value=default_val)

            target_id = ev_input.strip() if ev_input else (selected_ev if selected_ev != "-- Custom Entry --" else None)

            if st.button("Inspect Event", type="primary") or target_id:
                if target_id:
                    aid = st.session_state.active_analysis_id
                    ev_data = None
                    try:
                        if aid:
                            ev_data = client.get_evidence_event(aid, target_id)
                    except Exception:
                        # Fallback to local cited_evidence lookup if API is offline or not found via HTTP
                        for c_ev in res.get("cited_evidence", []):
                            if c_ev.get("event_id") == target_id:
                                ev_data = {"event_id": target_id, "status": "cited_in_report", "evidence_reference": c_ev}
                                break

                    if ev_data:
                        st.success(f"Evidence event `{target_id}` retrieved:")
                        st.json(ev_data)
                    else:
                        st.warning(f"Event ID `{target_id}` not found in active analysis.")

        with tab_ev2:
            st.subheader("Cited Key Evidence Table")
            cited_list = res.get("cited_evidence", [])
            if cited_list:
                df_ev = pd.DataFrame(cited_list)
                st.dataframe(df_ev, use_container_width=True)
            else:
                st.info("No cited evidence records available.")

        with tab_ev3:
            st.subheader("Complete Analysis JSON Document")
            st.json(res)


# ==============================================================================
# PAGE 7: PERSISTED HISTORY
# ==============================================================================
elif navigation_page == "Persisted History":
    st.markdown('<div class="main-header">Historical Analysis Database</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Browse locally persisted trace analyses from SQLite database with status and family filters.</div>', unsafe_allow_html=True)

    try:
        analyses_list = client.list_analyses(limit=100)

        if not analyses_list:
            st.info("No historical analyses found in SQLite database.")
        else:
            df = pd.DataFrame(analyses_list)

            # Filter Controls
            col_f1, col_f2 = st.columns(2)
            status_filter = col_f1.selectbox("Filter by Status:", ["All", "completed", "failed"])
            fam_filter = col_f2.selectbox("Filter by Family:", ["All"] + sorted(list(set(df["predicted_family"].dropna().tolist()))))

            filtered_df = df.copy()
            if status_filter != "All":
                filtered_df = filtered_df[filtered_df["status"] == status_filter]
            if fam_filter != "All":
                filtered_df = filtered_df[filtered_df["predicted_family"] == fam_filter]

            st.write(f"Displaying **{len(filtered_df)}** of **{len(df)}** analysis records:")
            st.dataframe(
                filtered_df[[
                    "analysis_id", "sample_id", "created_at", "status",
                    "predicted_family", "confidence", "confidence_label", "event_count", "file_size_bytes"
                ]],
                use_container_width=True
            )

            st.markdown("---")
            st.subheader("Load Analysis into Portal")

            aid_to_load = st.selectbox("Select Analysis ID to inspect:", filtered_df["analysis_id"].tolist())
            if st.button("Load Selected Analysis", type="primary") and aid_to_load:
                try:
                    loaded_data = client.get_analysis(str(aid_to_load))
                    st.session_state.active_analysis_id = str(aid_to_load)
                    st.session_state.analysis_data = get_clean_analysis_result(loaded_data)
                    st.success(f"Loaded Analysis ID `{aid_to_load}` into dashboard session!")
                    st.markdown("**Navigate to the 'Analysis Results' tab in sidebar to view findings.**")
                except Exception as err:
                    st.error(f"Failed to load analysis `{aid_to_load}`: {err}")

    except APIConnectionError:
        st.error("[OFFLINE] Unable to load history: MalTrace FastAPI server is offline.")
    except Exception as err:
        st.error(f"Error retrieving analysis history: {err}")

