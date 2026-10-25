"""
MITRE ATT&CK Navigator Layer Generator.
Exports analysis results into official ATT&CK Navigator v4.5 JSON layers
for visualization on https://mitre-attack.github.io/attack-navigator/
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from maltrace.contracts.schemas import AnalysisResult, TechniquePrediction


def generate_navigator_layer(
    result: AnalysisResult,
    layer_name: Optional[str] = None,
    domain: str = "enterprise-attack"
) -> Dict[str, Any]:
    """
    Generate an official ATT&CK Navigator v4.5 layer JSON dictionary from AnalysisResult.
    """
    sample_id = result.sample_id
    fam = result.family_prediction.family_name if result.family_prediction else "Unknown"
    title = layer_name or f"MalTrace-LM: {sample_id} ({fam})"

    techniques_list: List[Dict[str, Any]] = []

    for t in result.technique_predictions:
        # Score 0-100 based on confidence
        score_val = int(round(t.confidence * 100))

        # Color based on confidence
        if t.needs_review or score_val < 50:
            color_hex = "#fef08a"  # yellow
        elif score_val >= 80:
            color_hex = "#ef4444"  # red
        else:
            color_hex = "#f97316"  # orange

        evidence_str = ", ".join(t.supporting_evidence_ids[:5])
        rules_str = ", ".join(t.matched_rules[:3])
        comment_text = (
            f"Confidence: {t.confidence:.2f} ({t.confidence_label}) | "
            f"Rules: [{rules_str}] | Evidence IDs: [{evidence_str}]"
        )

        tactic_slug = t.tactic.lower().replace(" ", "-") if t.tactic else "execution"

        techniques_list.append({
            "techniqueID": t.technique_id,
            "tactic": tactic_slug,
            "score": score_val,
            "color": color_hex,
            "comment": comment_text,
            "enabled": True,
            "metadata": [
                {"name": "Confidence Label", "value": t.confidence_label},
                {"name": "Matched Rules Count", "value": str(len(t.matched_rules))},
                {"name": "Supporting Evidence Count", "value": str(len(t.supporting_evidence_ids))}
            ]
        })

    layer_dict: Dict[str, Any] = {
        "name": title,
        "versions": {
            "attack": "14",
            "navigator": "4.5",
            "layer": "4.5"
        },
        "domain": domain,
        "description": f"Automated MalTrace-LM behavioral mapping for trace sample '{sample_id}'. Predicted family: {fam}.",
        "techniques": techniques_list,
        "gradient": {
            "colors": ["#fef08a", "#f97316", "#ef4444"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "High Confidence (>= 80%)", "color": "#ef4444"},
            {"label": "Medium Confidence (50% - 79%)", "color": "#f97316"},
            {"label": "Needs Review / Low (< 50%)", "color": "#fef08a"}
        ]
    }

    return layer_dict


def export_navigator_layer_file(
    result: AnalysisResult,
    output_path: Union[str, Path],
    layer_name: Optional[str] = None
) -> Path:
    """
    Export Navigator layer dictionary to a JSON file.
    """
    layer = generate_navigator_layer(result, layer_name=layer_name)
    out_p = Path(output_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    return out_p
