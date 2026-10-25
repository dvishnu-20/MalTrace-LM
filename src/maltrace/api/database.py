"""
SQLite database and storage manager for MalTrace-LM FastAPI service.
Persists analysis metadata, versions, status, and file paths dynamically.
"""

import os
import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, List, Optional


def get_db_path() -> Path:
    return Path(os.environ.get("MALTRACE_DB_PATH", "data/maltrace.db"))


def get_storage_dir() -> Path:
    return Path(os.environ.get("MALTRACE_STORAGE_DIR", "data/storage"))


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target_db = db_path or get_db_path()
    target_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_db))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """
    Initialize SQLite database schema.
    """
    conn = get_db_connection(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                sample_hash TEXT NOT NULL,
                pipeline_version TEXT NOT NULL,
                model_artifact_version TEXT NOT NULL,
                vocabulary_version TEXT NOT NULL,
                technique_catalog_version TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                predicted_family TEXT,
                confidence REAL,
                confidence_label TEXT,
                event_count INTEGER,
                process_count INTEGER,
                technique_count INTEGER,
                warnings_json TEXT,
                failure_reason TEXT,
                raw_file_path TEXT,
                result_json_path TEXT,
                report_html_path TEXT,
                file_size_bytes INTEGER
            );
        """)
    conn.close()


def save_analysis_record(record: Dict[str, Any], db_path: Optional[Path] = None) -> None:
    """
    Insert or update an analysis record in SQLite.
    """
    conn = get_db_connection(db_path)
    with conn:
        conn.execute("""
            INSERT OR REPLACE INTO analyses (
                analysis_id, sample_id, sample_hash, pipeline_version,
                model_artifact_version, vocabulary_version, technique_catalog_version,
                created_at, status, predicted_family, confidence, confidence_label,
                event_count, process_count, technique_count, warnings_json,
                failure_reason, raw_file_path, result_json_path, report_html_path, file_size_bytes
            ) VALUES (
                :analysis_id, :sample_id, :sample_hash, :pipeline_version,
                :model_artifact_version, :vocabulary_version, :technique_catalog_version,
                :created_at, :status, :predicted_family, :confidence, :confidence_label,
                :event_count, :process_count, :technique_count, :warnings_json,
                :failure_reason, :raw_file_path, :result_json_path, :report_html_path, :file_size_bytes
            );
        """, {
            "analysis_id": record["analysis_id"],
            "sample_id": record.get("sample_id", "unknown"),
            "sample_hash": record.get("sample_hash", ""),
            "pipeline_version": record.get("pipeline_version", "0.1.0"),
            "model_artifact_version": record.get("model_artifact_version", "0.1.0"),
            "vocabulary_version": record.get("vocabulary_version", "1.0.0"),
            "technique_catalog_version": record.get("technique_catalog_version", "1.0.0"),
            "created_at": record["created_at"],
            "status": record.get("status", "completed"),
            "predicted_family": record.get("predicted_family"),
            "confidence": record.get("confidence", 0.0),
            "confidence_label": record.get("confidence_label", "Low"),
            "event_count": record.get("event_count", 0),
            "process_count": record.get("process_count", 0),
            "technique_count": record.get("technique_count", 0),
            "warnings_json": json.dumps(record.get("warnings", [])),
            "failure_reason": record.get("failure_reason"),
            "raw_file_path": record.get("raw_file_path"),
            "result_json_path": record.get("result_json_path"),
            "report_html_path": record.get("report_html_path"),
            "file_size_bytes": record.get("file_size_bytes", 0)
        })
    conn.close()


def get_analysis_record(analysis_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve an analysis record by analysis_id.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    res = dict(row)
    if res.get("warnings_json"):
        try:
            res["warnings"] = json.loads(res["warnings_json"])
        except Exception:
            res["warnings"] = []
    else:
        res["warnings"] = []
    return res


def list_analysis_records(limit: int = 100, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    List recent analysis records.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    records = []
    for r in rows:
        d = dict(r)
        if d.get("warnings_json"):
            try:
                d["warnings"] = json.loads(d["warnings_json"])
            except Exception:
                d["warnings"] = []
        records.append(d)
    return records


def delete_analysis_record(analysis_id: str, db_path: Optional[Path] = None) -> bool:
    """
    Delete an analysis record from SQLite database.
    """
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
        deleted = cursor.rowcount > 0
    conn.close()
    return deleted
