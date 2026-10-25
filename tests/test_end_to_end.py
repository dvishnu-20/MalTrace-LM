from pathlib import Path
import pytest
from maltrace.reporting.generator import analyze_trace


@pytest.mark.parametrize("sample_filename,expected_family", [
    ("benign_notepad.json", "Benign.Activity"),
    ("ransomware_wannacry.json", "Ransomware.WannaCry"),
    ("infostealer_redline.json", "Stealer.RedLine"),
    ("trojan_asyncrat.json", "Trojan.AsyncRAT"),
    ("dropper_emotet.json", "Dropper.Emotet"),
    ("coinminer_xmrig.json", "Coinminer.XMRig"),
])
def test_end_to_end_samples(sample_filename: str, expected_family: str):
    sample_path = Path("data/samples") / sample_filename
    assert sample_path.exists(), f"Sample fixture missing: {sample_filename}"

    result = analyze_trace(input_file=sample_path, seed=42)

    assert result.family_prediction.family_name == expected_family
    assert result.family_prediction.confidence > 0.5
    assert len(result.behavior_claims) >= 1
    if expected_family == "Benign.Activity":
        assert len(result.technique_predictions) == 0
    else:
        assert len(result.technique_predictions) >= 1
    assert len(result.cited_evidence) >= 1


def test_deterministic_output():
    sample_path = Path("data/samples/ransomware_wannacry.json")
    res1 = analyze_trace(input_file=sample_path, seed=42)
    res2 = analyze_trace(input_file=sample_path, seed=42)

    d1 = res1.model_dump()
    d2 = res2.model_dump()
    d1.pop("manifest")
    d2.pop("manifest")
    assert d1 == d2
