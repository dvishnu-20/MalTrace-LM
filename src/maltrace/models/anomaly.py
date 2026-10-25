"""
Behavioral Anomaly & Novelty Detection Engine.
Identifies zero-day behavioral deviations and abnormal execution profiles
using statistical vector scoring and Isolation Forest ensemble models.
"""

from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.ensemble import IsolationForest

from maltrace.contracts.schemas import NormalizedEvent
from maltrace.models.feature_extractor import extract_single_structured_vector, FEATURE_NAMES


class BehavioralAnomalyDetector:
    """
    Evaluates execution trace behavioral divergence against standard baseline distributions.
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        forest_cls: Any = IsolationForest
        self.model = forest_cls(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state
        )
        self.is_fitted = False
        self._init_default_baseline()

    def _init_default_baseline(self):
        """
        Fit baseline on synthetic benchmark vector distributions (benign and standard malware distributions).
        """
        # Synthetic baseline vectors matching 12-D FEATURE_NAMES:
        # ["file", "process", "registry", "network", "service", "memory", "sync", "other", pids, net, pers, anchors]
        normal_samples = [
            [5, 2, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0],   # Benign Notepad
            [8, 3, 2, 1, 0, 0, 0, 2, 1, 1, 0, 0],   # Normal Office
            [10, 5, 2, 0, 0, 0, 0, 5, 2, 0, 0, 0],  # Normal Dev Build
            [3, 1, 0, 2, 0, 0, 0, 1, 1, 2, 0, 0],   # Web Browser
            [6, 4, 1, 1, 1, 0, 0, 2, 2, 1, 0, 0],   # System Utility
        ]
        X = np.array(normal_samples, dtype=np.float64)
        self.model.fit(X)
        self.is_fitted = True

    def extract_features(self, events: List[NormalizedEvent]) -> np.ndarray:
        """
        Extract fixed-length 12-D numerical feature representation from trace events.
        """
        return extract_single_structured_vector(events)

    def evaluate_trace(self, events: List[NormalizedEvent]) -> Dict[str, Any]:
        """
        Score a trace and return anomaly metrics and explanation.
        """
        if not events:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence_label": "Normal",
                "divergence_factors": ["Empty trace"]
            }

        vec = self.extract_features(events).reshape(1, -1)

        # Raw decision score (negative indicates anomaly in sklearn IsolationForest)
        raw_score = float(self.model.decision_function(vec)[0])

        # Base statistical score
        base_anomaly = 0.5 - raw_score

        divergence_factors = []
        anchor_weight = 0.0
        injection_weight = 0.0
        persistence_weight = 0.0

        if vec[0, 5] > 0:  # memory category
            divergence_factors.append("Cross-process memory injection activity observed")
            injection_weight = 0.30 * min(float(vec[0, 5]), 2.0)
        if vec[0, 3] > 3:  # high network outbound
            divergence_factors.append("Unusual volume of remote network egress endpoints")
        if vec[0, 10] > 0:  # persistence
            divergence_factors.append("Autostart / registry persistence hooks registered")
            persistence_weight = 0.15 * min(float(vec[0, 10]), 2.0)
        if vec[0, 11] > 0:  # anchors
            divergence_factors.append("High-severity persistence or security anchor triggers")
            anchor_weight = 0.25 * min(float(vec[0, 11]), 2.0)
        if len(events) > 50:
            divergence_factors.append("High event velocity / rapid API burst")

        total_score = base_anomaly + anchor_weight + injection_weight + persistence_weight
        normalized_anomaly = float(np.clip(total_score, 0.0, 1.0))
        is_anomaly = normalized_anomaly >= 0.50 or len(divergence_factors) > 0

        if not divergence_factors and is_anomaly:
            divergence_factors.append("Statistical feature distribution divergence from benign baseline")

        conf_label = "High" if normalized_anomaly >= 0.7 else ("Medium" if normalized_anomaly >= 0.5 else "Low")

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(normalized_anomaly, 3),
            "confidence_label": conf_label,
            "divergence_factors": divergence_factors
        }
