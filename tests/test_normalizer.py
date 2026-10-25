from maltrace.contracts.schemas import RawEvent
from maltrace.representation.normalizer import normalize_event, normalize_api_category, sanitize_arguments


def test_normalize_api_category():
    assert normalize_api_category("CreateProcessInternalW") == "process"
    assert normalize_api_category("RegSetValueExW") == "registry"
    assert normalize_api_category("NtCreateFile") == "file"
    assert normalize_api_category("WSAConnect") == "network"
    assert normalize_api_category("CreateServiceW") == "service"
    assert normalize_api_category("VirtualAllocEx") == "memory"
    assert normalize_api_category("UnknownCustomApi") == "other"


def test_sanitize_arguments():
    raw_args = {
        "path": "C:\\test.txt\x00",
        "long_val": "A" * 600,
        "count": 42
    }
    clean = sanitize_arguments(raw_args)
    assert clean["path"] == "C:\\test.txt"
    assert clean["long_val"].endswith("... [truncated]")
    assert clean["count"] == 42


def test_normalize_event():
    raw = RawEvent(
        sample_id="samp_01",
        event_id="evt_01",
        event_order=1,
        process_id=1234,
        parent_process_id=1000,
        api_name="RegSetValueExW",
        arguments={"key": "HKCU\\Run", "value": "test.exe"},
        source_file="trace.json"
    )
    norm = normalize_event(raw)
    assert norm.category == "registry"
    assert norm.process_id == 1234
    assert norm.safe_arguments["key"] == "HKEY_CURRENT_USER\\Run"
