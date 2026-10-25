import time

from pathlib import Path
from typing import Union, Dict, Any, List, Optional
import orjson

from maltrace.contracts.schemas import (
    AnalysisResult,
    EvidenceReference,
    RunManifest
)
from maltrace.ingestion.loader import load_trace_file
from maltrace.representation.normalizer import normalize_trace_events
from maltrace.features.summarizer import build_process_summaries, extract_behavior_claims
from maltrace.models.family_classifier import classify_malware_family
from maltrace.attack_mapping.mapper import map_behavior_to_attack
from maltrace.verification.validator import EvidenceVerifier, verify_evidence_references
from maltrace.utils.seed import set_seed


def analyze_trace(
    input_file: Union[str, Path],
    output_file: Union[str, Path, None] = None,
    seed: int = 42,
    model_dir: Optional[Union[str, Path]] = None
) -> AnalysisResult:
    """
    Run complete end-to-end trace analysis pipeline.
    """
    start_time = time.time()
    set_seed(seed)
    in_path = Path(input_file)

    # 1. Ingestion
    raw_trace = load_trace_file(in_path)

    # 2. Normalization
    norm_events = normalize_trace_events(raw_trace.events)
    events_by_id = {e.event_id: e for e in norm_events}

    # 3. Process Summarization & Behavior Extraction
    proc_summaries = build_process_summaries(norm_events)
    behavior_claims = extract_behavior_claims(norm_events)

    # 4. Family Classification & ATT&CK Mapping
    family_prediction = classify_malware_family(norm_events, behavior_claims, model_dir=model_dir)
    technique_predictions = map_behavior_to_attack(norm_events, behavior_claims)

    # 5. Evidence Verification Gate
    verifier = EvidenceVerifier()
    behavior_claims, family_prediction, technique_predictions, verification_summary = verifier.verify(
        events=norm_events,
        claims=behavior_claims,
        family_pred=family_prediction,
        technique_preds=technique_predictions,
        process_summaries=proc_summaries
    )

    # 6. Extract Cited Evidence References
    cited_ids = set()
    for c in behavior_claims:
        cited_ids.update(c.evidence_event_ids)
    cited_ids.update(family_prediction.supporting_evidence_ids)
    for t in technique_predictions:
        cited_ids.update(t.supporting_evidence_ids)

    cited_references: List[EvidenceReference] = []
    for eid in sorted(list(cited_ids)):
        if eid in events_by_id:
            e = events_by_id[eid]
            args_snippet = str(e.safe_arguments)
            if len(args_snippet) > 120:
                args_snippet = args_snippet[:120] + "..."
            cited_references.append(
                EvidenceReference(
                    event_id=e.event_id,
                    event_order=e.event_order,
                    api_name=e.api_name,
                    category=e.category,
                    snippet=f"PID {e.process_id} | {e.api_name} | {args_snippet}"
                )
            )

    elapsed_ms = (time.time() - start_time) * 1000.0

    manifest = RunManifest(
        run_id=f"run_{int(time.time())}",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        maltrace_version="0.1.0",
        input_file=str(in_path),
        output_file=str(output_file) if output_file else None,
        execution_time_ms=round(elapsed_ms, 2),
        seed=seed
    )

    result = AnalysisResult(
        sample_id=raw_trace.sample_id,
        trace_summary={
            "total_raw_events": len(raw_trace.events),
            "total_normalized_events": len(norm_events),
            "total_processes": len(proc_summaries),
            "categories_found": sorted(list(set(e.category for e in norm_events)))
        },
        process_summaries=proc_summaries,
        behavior_claims=behavior_claims,
        family_prediction=family_prediction,
        technique_predictions=technique_predictions,
        cited_evidence=cited_references,
        verification_summary=verification_summary,
        manifest=manifest,
        schema_version="1.0.0"
    )

    # Output writing if output_file specified
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(orjson.dumps(result.model_dump(), option=orjson.OPT_INDENT_2))

    return result
