"""
Retention policy and cleanup module for MalTrace-LM FastAPI service artifacts.
Removes old raw input files, reports, and database records older than configured max_age_days.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from maltrace.api.database import get_db_path, get_storage_dir, get_db_connection, delete_analysis_record


def cleanup_old_analyses(
    max_age_days: int = 30,
    db_path: Optional[Path] = None,
    storage_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Retention cleanup job: removes raw trace uploads, JSON results, HTML reports,
    and database records older than max_age_days.
    """
    target_db = db_path or get_db_path()
    target_storage = storage_dir or get_storage_dir()

    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_db_connection(target_db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses WHERE created_at < ?", (cutoff_iso,))
    stale_rows = cursor.fetchall()
    conn.close()

    deleted_count = 0
    deleted_bytes = 0

    for r in stale_rows:
        aid = r["analysis_id"]

        # Delete raw file
        if r["raw_file_path"] and Path(r["raw_file_path"]).exists():
            try:
                size = Path(r["raw_file_path"]).stat().st_size
                Path(r["raw_file_path"]).unlink(missing_ok=True)
                deleted_bytes += size
            except Exception:
                pass

        # Delete result json
        if r["result_json_path"] and Path(r["result_json_path"]).exists():
            try:
                size = Path(r["result_json_path"]).stat().st_size
                Path(r["result_json_path"]).unlink(missing_ok=True)
                deleted_bytes += size
            except Exception:
                pass

        # Delete report html
        if r["report_html_path"] and Path(r["report_html_path"]).exists():
            try:
                size = Path(r["report_html_path"]).stat().st_size
                Path(r["report_html_path"]).unlink(missing_ok=True)
                deleted_bytes += size
            except Exception:
                pass

        # Delete analysis storage folder if empty
        analysis_folder = target_storage / "analyses" / aid
        if analysis_folder.exists():
            try:
                for child in analysis_folder.glob("*"):
                    child.unlink(missing_ok=True)
                analysis_folder.rmdir()
            except Exception:
                pass

        # Remove from database
        delete_analysis_record(aid, db_path=target_db)
        deleted_count += 1

    return {
        "status": "success",
        "max_age_days": max_age_days,
        "cutoff_timestamp": cutoff_iso,
        "analyses_cleaned": deleted_count,
        "freed_bytes": deleted_bytes
    }
