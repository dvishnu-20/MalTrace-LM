"""
Global Pytest test configuration and fixtures.
Configures isolated temporary databases and storage directories for all tests,
preventing cross-test pollution and ensuring test repeatability on CI runners.
"""

from pathlib import Path
import pytest


@pytest.fixture(autouse=True)
def configure_isolated_test_environment(tmp_path: Path, monkeypatch):
    """
    Ensure all tests run with isolated SQLite database and storage paths.
    """
    test_db = tmp_path / "test_maltrace.db"
    test_storage = tmp_path / "test_storage"
    test_storage.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("MALTRACE_DB_PATH", str(test_db))
    monkeypatch.setenv("MALTRACE_STORAGE_DIR", str(test_storage))
