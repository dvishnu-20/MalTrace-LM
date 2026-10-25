"""
Production-style FastAPI Web Service for MalTrace-LM Execution Trace Analysis.
Single-machine architecture with SQLite persistence, filesystem report storage,
strict upload validation, evidence event lookup, ATT&CK Navigator export, and differential analysis.
"""

import os
import time
import uuid
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

import orjson
from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Request, Response, status, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from maltrace.contracts.schemas import AnalysisResult
from maltrace.reporting.generator import analyze_trace
from maltrace.reporting.report_generator import generate_deterministic_analyst_report, render_report_html, render_report_markdown
from maltrace.api.database import init_db, save_analysis_record, get_analysis_record, get_storage_dir
from maltrace.api.security import verify_api_security, InMemoryRateLimiter
from maltrace.attack_mapping.navigator import generate_navigator_layer
from maltrace.features.trace_diff import compute_trace_diff
from maltrace.detection.ids_generator import export_ids_rules_from_result
from maltrace.reporting.siem_exporter import export_siem_format
from maltrace.features.clustering import cluster_trace_samples


MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB limit
BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".elf", ".bat", ".ps1", ".vbs", ".js",
    ".py", ".sh", ".zip", ".tar", ".gz", ".7z", ".rar", ".iso", ".img"
}

rate_limiter = InMemoryRateLimiter(max_requests=200, window_seconds=60)
ANALYSIS_JOBS: Dict[str, Dict[str, Any]] = {}


def execute_background_trace_analysis(
    job_id: str,
    analysis_id: str,
    raw_file_path: Path,
    result_json_path: Path,
    report_html_path: Path,
    sample_hash: str,
    content_len: int,
    raw_json_data: Any
):
    """
    Executes trace analysis pipeline in background worker task.
    """
    ANALYSIS_JOBS[job_id]["status"] = "processing"
    try:
        result = analyze_trace(raw_file_path)
        with open(result_json_path, "wb") as f:
            f.write(orjson.dumps(result.model_dump(), option=orjson.OPT_INDENT_2))

        analyst_report = generate_deterministic_analyst_report(result)
        html_content = render_report_html(analyst_report)
        with open(report_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        fam = result.family_prediction
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record = {
            "analysis_id": analysis_id,
            "sample_id": result.sample_id,
            "sample_hash": sample_hash,
            "pipeline_version": "0.2.0",
            "model_artifact_version": "0.2.0",
            "vocabulary_version": "1.0.0",
            "technique_catalog_version": "1.1.0",
            "created_at": created_at,
            "status": "completed",
            "predicted_family": fam.family_name,
            "family_confidence": fam.confidence,
            "family_confidence_label": fam.confidence_label,
            "event_count": result.trace_summary.get("total_normalized_events", 0),
            "process_count": len(result.process_summaries),
            "technique_count": len(result.technique_predictions),
            "warnings": getattr(result.verification_summary, "rejected_claim_details", []) if result.verification_summary else [],
            "failure_reason": None,
            "raw_file_path": str(raw_file_path),
            "result_json_path": str(result_json_path),
            "report_html_path": str(report_html_path),
            "file_size_bytes": content_len
        }
        save_analysis_record(record)

        ANALYSIS_JOBS[job_id].update({
            "status": "completed",
            "analysis_id": analysis_id,
            "sample_id": result.sample_id,
            "predicted_family": fam.family_name,
            "confidence": fam.confidence,
            "confidence_label": fam.confidence_label,
            "total_events": result.trace_summary.get("total_normalized_events", 0),
            "links": {
                "result": f"/analyses/{analysis_id}",
                "report_html": f"/analyses/{analysis_id}/report?format=html",
                "report_json": f"/analyses/{analysis_id}/report?format=json",
                "report_markdown": f"/analyses/{analysis_id}/report?format=markdown",
                "navigator": f"/analyses/{analysis_id}/navigator"
            }
        })
    except Exception as err:
        ANALYSIS_JOBS[job_id]["status"] = "failed"
        ANALYSIS_JOBS[job_id]["error"] = str(err)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager initializing database and storage on startup.
    """
    init_db()
    get_storage_dir().mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="MalTrace-LM Analysis Engine API",
    description=(
        "Defensive Windows Execution Trace Analysis & Behavioral Mapping REST API. "
        "Provides single-machine trace ingestion, evidence verification, ATT&CK mapping, "
        "SQLite persistence, ATT&CK Navigator export, differential comparison, and rendered analyst reports."
    ),
    version="0.2.0",
    lifespan=lifespan
)


@app.middleware("http")
async def security_and_logging_middleware(request: Request, call_next):
    """
    Middleware applying in-memory rate limiting and request duration logging.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    rate_limiter.check_rate_limit(client_ip)

    start_time = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000.0
    print(f"[API LOG] {request.method} {request.url.path} -> Status: {response.status_code} ({duration_ms:.2f}ms)")
    return response


@app.get("/health", summary="Health Check Endpoint", tags=["System"])
def health_check():
    """
    Return basic service health status.
    """
    return {
        "status": "ok",
        "service": "maltrace-api",
        "version": "0.1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


@app.get("/version", summary="Version & Vocabulary Manifest", tags=["System"])
def version_manifest():
    """
    Return pipeline version, vocabulary schema version, technique catalog version, and baseline model version.
    """
    return {
        "service": "MalTrace-LM API",
        "maltrace_version": "0.1.0",
        "schema_version": "1.0.0",
        "vocabulary_version": "1.0.0",
        "technique_catalog_version": "1.0.0",
        "model_version": "0.1.0"
    }



@app.post("/analyze", summary="Analyze Windows Trace JSON", status_code=status.HTTP_201_CREATED, tags=["Analysis"])
async def analyze_file(
    file: UploadFile = File(...),
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Upload a single Windows trace JSON file for defensive behavioral analysis.
    Validates file size (max 10MB), checks content safety, executes analysis pipeline,
    persists result in SQLite and filesystem storage, and returns analysis summary with artifact links.
    """
    filename = file.filename or "uploaded_trace.json"

    # 1. Path traversal & filename safety checks
    if any(seq in filename for seq in ["..", "/", "\\", "\0"]):
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal sequences prohibited.")

    ext = Path(filename).suffix.lower()
    if ext in BLOCKED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsafe file extension '{ext}' is blocked.")

    if ext != ".json":
        raise HTTPException(status_code=400, detail="Only JSON execution trace files (.json) are supported.")

    # 2. Read content and enforce strict size limit
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file size ({len(content)} bytes) exceeds maximum limit of {MAX_UPLOAD_BYTES} bytes (10MB)."
        )

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded trace file is empty.")

    # 3. Validate JSON syntax
    try:
        raw_json_data = orjson.loads(content)
    except Exception:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid JSON content.")

    sample_hash = hashlib.sha256(content).hexdigest()

    # 4. Generate unique analysis ID and setup storage paths
    analysis_id = f"ana_{uuid.uuid4().hex[:12]}"
    storage_dir = get_storage_dir()
    analysis_dir = storage_dir / "analyses" / analysis_id
    analysis_dir.mkdir(parents=True, exist_ok=True)

    raw_file_path = analysis_dir / "raw_trace.json"
    result_json_path = analysis_dir / "result.json"
    report_html_path = analysis_dir / "report.html"

    # Write raw trace upload
    with open(raw_file_path, "wb") as f:
        f.write(content)

    # 5. Run local analysis pipeline
    try:
        result: AnalysisResult = analyze_trace(input_file=raw_file_path, output_file=result_json_path)

        # Generate & save HTML report
        report_obj = generate_deterministic_analyst_report(result)
        html_content = render_report_html(report_obj)
        with open(report_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        fam = result.family_prediction
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # 6. Save metadata record to SQLite
        record = {
            "analysis_id": analysis_id,
            "sample_id": result.sample_id,
            "sample_hash": sample_hash,
            "pipeline_version": "0.2.0",
            "model_artifact_version": "0.2.0",
            "vocabulary_version": "1.0.0",
            "technique_catalog_version": "1.1.0",
            "created_at": created_at,
            "status": "completed",
            "predicted_family": fam.family_name,
            "confidence": fam.confidence,
            "confidence_label": fam.confidence_label,
            "event_count": result.trace_summary.get("total_normalized_events", 0),
            "process_count": len(result.process_summaries),
            "technique_count": len(result.technique_predictions),
            "warnings": getattr(result.verification_summary, "rejected_claim_details", []) if result.verification_summary else [],
            "failure_reason": None,
            "raw_file_path": str(raw_file_path),
            "result_json_path": str(result_json_path),
            "report_html_path": str(report_html_path),
            "file_size_bytes": len(content)
        }
        save_analysis_record(record)

        return {
            "analysis_id": analysis_id,
            "status": "completed",
            "sample_id": result.sample_id,
            "sample_hash": sample_hash,
            "predicted_family": fam.family_name,
            "confidence": fam.confidence,
            "confidence_label": fam.confidence_label,
            "total_events": result.trace_summary.get("total_normalized_events", 0),
            "total_processes": len(result.process_summaries),
            "mapped_techniques_count": len(result.technique_predictions),
            "links": {
                "result": f"/analyses/{analysis_id}",
                "report_html": f"/analyses/{analysis_id}/report?format=html",
                "report_json": f"/analyses/{analysis_id}/report?format=json",
                "report_markdown": f"/analyses/{analysis_id}/report?format=markdown",
                "navigator": f"/analyses/{analysis_id}/navigator"
            }
        }

    except Exception as err:
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        failure_record = {
            "analysis_id": analysis_id,
            "sample_id": raw_json_data.get("sample_id", "unknown") if isinstance(raw_json_data, dict) else "unknown",
            "sample_hash": sample_hash,
            "pipeline_version": "0.2.0",
            "model_artifact_version": "0.2.0",
            "vocabulary_version": "1.0.0",
            "technique_catalog_version": "1.1.0",
            "created_at": created_at,
            "status": "failed",
            "failure_reason": str(err),
            "raw_file_path": str(raw_file_path),
            "file_size_bytes": len(content)
        }
        save_analysis_record(failure_record)
        raise HTTPException(status_code=500, detail=f"Trace analysis pipeline execution failed: {str(err)}")


@app.post("/analyze/async", summary="Queue Trace for Asynchronous Background Analysis", status_code=status.HTTP_202_ACCEPTED, tags=["Analysis"])
async def analyze_file_async(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Queue a Windows execution trace JSON for non-blocking asynchronous background execution.
    Returns immediately with a job ID and status checking endpoint.
    """
    filename = file.filename or "uploaded_trace.json"

    if any(seq in filename for seq in ["..", "/", "\\", "\0"]):
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal sequences prohibited.")

    ext = Path(filename).suffix.lower()
    if ext in BLOCKED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsafe file extension '{ext}' is blocked.")

    if ext != ".json":
        raise HTTPException(status_code=400, detail="Only JSON execution trace files (.json) are supported.")

    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file size ({len(content)} bytes) exceeds maximum limit of {MAX_UPLOAD_BYTES} bytes (10MB)."
        )

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded trace file is empty.")

    try:
        raw_json_data = json.loads(content.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {str(e)}")

    analysis_id = str(uuid.uuid4())
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    sample_hash = hashlib.sha256(content).hexdigest()

    storage_dir = get_storage_dir()
    analysis_dir = storage_dir / "analyses" / analysis_id
    analysis_dir.mkdir(parents=True, exist_ok=True)

    raw_file_path = analysis_dir / "raw_trace.json"
    result_json_path = analysis_dir / "result.json"
    report_html_path = analysis_dir / "report.html"

    with open(raw_file_path, "wb") as f:
        f.write(content)

    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ANALYSIS_JOBS[job_id] = {
        "job_id": job_id,
        "analysis_id": analysis_id,
        "status": "queued",
        "filename": filename,
        "sample_hash": sample_hash,
        "created_at": created_at,
        "check_status_url": f"/analyses/jobs/{job_id}"
    }

    background_tasks.add_task(
        execute_background_trace_analysis,
        job_id=job_id,
        analysis_id=analysis_id,
        raw_file_path=raw_file_path,
        result_json_path=result_json_path,
        report_html_path=report_html_path,
        sample_hash=sample_hash,
        content_len=len(content),
        raw_json_data=raw_json_data
    )

    return {
        "job_id": job_id,
        "analysis_id": analysis_id,
        "status": "queued",
        "created_at": created_at,
        "check_status_url": f"/analyses/jobs/{job_id}"
    }


@app.get("/analyses/jobs/{job_id}", summary="Check Status of Background Analysis Job", tags=["Analysis"])
def get_job_status(
    job_id: str,
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Check the current status and results of an asynchronous background analysis job.
    """
    job = ANALYSIS_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job ID '{job_id}' not found.")
    return job


@app.get("/analyses", summary="List Stored Analysis History", tags=["Analysis"])
def list_analyses(
    limit: int = Query(100, ge=1, le=500),
    auth_passed: bool = Depends(verify_api_security)
):
    """
    List persisted analysis records ordered by creation timestamp descending.
    """
    from maltrace.api.database import list_analysis_records
    records = list_analysis_records(limit=limit)
    return {"total": len(records), "analyses": records}


@app.get("/analyses/{analysis_id}", summary="Get Analysis Metadata & Results", tags=["Analysis"])
def get_analysis(
    analysis_id: str,
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Retrieve stored analysis metadata and complete JSON result by analysis_id.
    """
    rec = get_analysis_record(analysis_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Analysis ID '{analysis_id}' not found.")

    result_json_path = rec.get("result_json_path")
    if not result_json_path or not Path(result_json_path).exists():
        return {
            "metadata": rec,
            "result": None,
            "message": "Analysis completed or failed, but result JSON artifact file is not available."
        }

    with open(result_json_path, "r", encoding="utf-8") as f:
        full_result = json.load(f)

    return {
        "metadata": rec,
        "result": full_result
    }


@app.get("/analyses/{analysis_id}/report", summary="Get Rendered Report", tags=["Analysis"])
def get_analysis_report(
    analysis_id: str,
    format: str = Query("html", description="Report format: html, markdown, or json"),
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Retrieve formatted analyst report for an analysis. Supports html, markdown, or json formats.
    """
    rec = get_analysis_record(analysis_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Analysis ID '{analysis_id}' not found.")

    fmt = format.lower()

    if fmt == "html":
        html_path = rec.get("report_html_path")
        if html_path and Path(html_path).exists():
            with open(html_path, "r", encoding="utf-8") as f:
                content = f.read()
            return HTMLResponse(content=content)
        else:
            raise HTTPException(status_code=404, detail="HTML report artifact not found for this analysis.")

    res_path = rec.get("result_json_path")
    if not res_path or not Path(res_path).exists():
        raise HTTPException(status_code=404, detail="Analysis result artifact not found.")

    with open(res_path, "r", encoding="utf-8") as f:
        result_dict = json.load(f)

    analysis_res = AnalysisResult.model_validate(result_dict)
    report_obj = generate_deterministic_analyst_report(analysis_res)

    if fmt == "markdown":
        md_text = render_report_markdown(report_obj)
        return PlainTextResponse(content=md_text, media_type="text/markdown")

    elif fmt == "json":
        return JSONResponse(content=report_obj.model_dump())

    else:
        raise HTTPException(status_code=400, detail="Invalid format requested. Supported formats: html, markdown, json.")


@app.get("/analyses/{analysis_id}/navigator", summary="Get ATT&CK Navigator Layer JSON", tags=["Analysis"])
def get_analysis_navigator(
    analysis_id: str,
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Export MITRE ATT&CK Navigator Layer v4.5 JSON for the analysis.
    """
    rec = get_analysis_record(analysis_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Analysis ID '{analysis_id}' not found.")

    res_path = rec.get("result_json_path")
    if not res_path or not Path(res_path).exists():
        raise HTTPException(status_code=404, detail="Analysis result artifact not found.")

    with open(res_path, "r", encoding="utf-8") as f:
        result_dict = json.load(f)

    analysis_res = AnalysisResult.model_validate(result_dict)
    layer = generate_navigator_layer(analysis_res)
    return JSONResponse(content=layer)


@app.post("/diff", summary="Differential Analysis Between Two Traces", tags=["Analysis"])
async def diff_traces(
    file_a: UploadFile = File(...),
    file_b: UploadFile = File(...),
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Upload two JSON execution traces and compute differential comparison metrics.
    """
    content_a = await file_a.read()
    content_b = await file_b.read()

    storage_dir = get_storage_dir()
    diff_dir = storage_dir / "diffs" / f"diff_{uuid.uuid4().hex[:8]}"
    diff_dir.mkdir(parents=True, exist_ok=True)

    path_a = diff_dir / "trace_a.json"
    path_b = diff_dir / "trace_b.json"

    with open(path_a, "wb") as f:
        f.write(content_a)
    with open(path_b, "wb") as f:
        f.write(content_b)

    try:
        diff_res = compute_trace_diff(path_a, path_b)
        return JSONResponse(content=diff_res.model_dump())
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"Diff computation failed: {str(err)}")


@app.get("/analyses/{analysis_id}/events/{event_id}", summary="Lookup Evidence Event by ID", tags=["Evidence"])
def get_evidence_event(
    analysis_id: str,
    event_id: str,
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Retrieve specific evidence event details by event_id for a given analysis_id.
    """
    rec = get_analysis_record(analysis_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Analysis ID '{analysis_id}' not found.")

    res_path = rec.get("result_json_path")
    if not res_path or not Path(res_path).exists():
        raise HTTPException(status_code=404, detail="Analysis result artifact not found.")

    with open(res_path, "r", encoding="utf-8") as f:
        result_dict = json.load(f)

    cited = [ev for ev in result_dict.get("cited_evidence", []) if ev.get("event_id") == event_id]
    if cited:
        return {
            "analysis_id": analysis_id,
            "event_id": event_id,
            "status": "cited_in_report",
            "evidence_reference": cited[0]
        }

    raw_path = rec.get("raw_file_path")
    if raw_path and Path(raw_path).exists():
        with open(raw_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        raw_events = raw_data.get("events", [])
        for ev in raw_events:
            if ev.get("event_id") == event_id:
                return {
                    "analysis_id": analysis_id,
                    "event_id": event_id,
                    "status": "found_in_raw_trace",
                    "event": ev
                }

    raise HTTPException(status_code=404, detail=f"Event ID '{event_id}' not found in analysis '{analysis_id}'.")


@app.get("/analyses/{analysis_id}/ids", summary="Export Network IDS / IPS Rules", tags=["Detection"])
def export_analysis_ids_rules(
    analysis_id: str,
    format: str = Query("suricata", description="IDS rule format: 'suricata', 'snort', or 'zeek'"),
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Generate and export network intrusion detection rules (Suricata / Snort / Zeek) from an analysis.
    """
    rec = get_analysis_record(analysis_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Analysis ID '{analysis_id}' not found.")

    res_path = rec.get("result_json_path")
    if not res_path or not Path(res_path).exists():
        raise HTTPException(status_code=404, detail="Analysis result artifact not found.")

    with open(res_path, "r", encoding="utf-8") as f:
        result_dict = json.load(f)

    result_obj = AnalysisResult(**result_dict)
    try:
        rules_text = export_ids_rules_from_result(result_obj, format_type=format)
        return PlainTextResponse(content=rules_text, media_type="text/plain")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/analyses/{analysis_id}/siem", summary="Export Analysis in SIEM / TIP Format", tags=["Integrations"])
def export_analysis_siem(
    analysis_id: str,
    format: str = Query("splunk", description="SIEM/TIP format: 'splunk', 'ecs', 'misp', or 'stix'"),
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Export structured threat intelligence object for Splunk HEC, Elastic ECS, MISP, or STIX 2.1.
    """
    rec = get_analysis_record(analysis_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Analysis ID '{analysis_id}' not found.")

    res_path = rec.get("result_json_path")
    if not res_path or not Path(res_path).exists():
        raise HTTPException(status_code=404, detail="Analysis result artifact not found.")

    with open(res_path, "r", encoding="utf-8") as f:
        result_dict = json.load(f)

    result_obj = AnalysisResult(**result_dict)
    try:
        siem_data = export_siem_format(result_obj, format_type=format)
        return JSONResponse(content=siem_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/cluster", summary="Cluster Multiple Traces into Threat Campaigns", tags=["Threat Hunting"])
async def cluster_multiple_traces(
    files: List[UploadFile] = File(..., description="List of trace JSON files to cluster"),
    distance_threshold: float = Query(0.55, description="Distance threshold for Agglomerative Clustering"),
    auth_passed: bool = Depends(verify_api_security)
):
    """
    Upload multiple trace JSON files and cluster them into adversary campaigns based on behavioral similarity.
    """
    if not files or len(files) < 2:
        raise HTTPException(status_code=400, detail="Please upload at least 2 trace JSON files to perform campaign clustering.")

    storage_dir = get_storage_dir()
    temp_dir = storage_dir / f"cluster_{uuid.uuid4().hex[:8]}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    saved_paths = []

    try:
        for idx, file in enumerate(files):
            contents = await file.read()
            if not contents or not contents.strip().startswith(b"{"):
                continue
            path = temp_dir / f"sample_{idx}_{file.filename}"
            with open(path, "wb") as f:
                f.write(contents)
            saved_paths.append(path)

        if len(saved_paths) < 2:
            raise HTTPException(status_code=400, detail="At least 2 valid JSON trace files are required.")

        result = cluster_trace_samples(saved_paths, distance_threshold=distance_threshold)
        return JSONResponse(content=result.model_dump())
    finally:
        # Cleanup temp cluster files
        for p in saved_paths:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            temp_dir.rmdir()
        except Exception:
            pass

