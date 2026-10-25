"""
Model baselines module.
Implements MajorityClassBaseline, TfidfBehaviorClassifier, and StructuredCountClassifier
with probability calibration and Scikit-Learn pipeline integration.
"""

from typing import List, Dict, Any, Tuple, Optional
import numpy as np
from collections import Counter

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.calibration import CalibratedClassifierCV


class MajorityClassBaseline:
    """
    Baseline 1: Constant predictor predicting the majority class observed during training.
    """

    def __init__(self):
        self.majority_class: str = "Benign.Activity"
        self.majority_ratio: float = 1.0
        self.classes_: np.ndarray = np.array(["Benign.Activity"])

    def fit(self, X: Any, y: List[str]):
        counts = Counter(y)
        if counts:
            self.majority_class, maj_count = counts.most_common(1)[0]
            self.majority_ratio = float(maj_count) / max(1, len(y))
            self.classes_ = np.array(sorted(list(counts.keys())))
        return self

    def predict(self, X: Any) -> List[str]:
        n_samples = len(X) if hasattr(X, "__len__") else 1
        return [self.majority_class] * n_samples

    def predict_proba(self, X: Any) -> np.ndarray:
        n_samples = len(X) if hasattr(X, "__len__") else 1
        n_classes = len(self.classes_)
        probas = np.zeros((n_samples, n_classes), dtype=np.float64)
        maj_idx = np.where(self.classes_ == self.majority_class)[0][0] if self.majority_class in self.classes_ else 0
        probas[:, maj_idx] = 1.0
        return probas


class TfidfBehaviorClassifier:
    """
    Baseline 2: TF-IDF over controlled behavior text + Logistic Regression classifier.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=500, token_pattern=r"(?u)\b\w+\b")
        self.clf = LogisticRegression(C=1.0, random_state=seed, max_iter=500, solver="lbfgs")
        self.label_encoder = LabelEncoder()
        self.classes_: np.ndarray = np.array([])
        self.is_calibrated: bool = False

    def fit(self, texts: List[str], y: List[str], calib_texts: Optional[List[str]] = None, calib_y: Optional[List[str]] = None):
        y_encoded = self.label_encoder.fit_transform(y)
        self.classes_ = self.label_encoder.classes_

        X_tfidf = self.vectorizer.fit_transform(texts)

        if len(self.classes_) == 1:
            self.clf = MajorityClassBaseline()
            self.clf.fit(texts, y)
            return self

        if calib_texts and calib_y:
            known_classes = set(self.classes_)
            valid_idx = [i for i, lbl in enumerate(calib_y) if lbl in known_classes]
            if len(valid_idx) >= 2 and len(set(calib_y[i] for i in valid_idx)) > 1:
                base_clf = LogisticRegression(C=1.0, random_state=self.seed, max_iter=500, solver="lbfgs")
                base_clf.fit(X_tfidf, y_encoded)

                calib_t_filt = [calib_texts[i] for i in valid_idx]
                calib_y_filt = [calib_y[i] for i in valid_idx]

                X_calib = self.vectorizer.transform(calib_t_filt)
                y_calib_enc = self.label_encoder.transform(calib_y_filt)

                calibrated = CalibratedClassifierCV(estimator=base_clf, method="sigmoid", cv="prefit")
                calibrated.fit(X_calib, y_calib_enc)
                self.clf = calibrated
                self.is_calibrated = True
            else:
                self.clf.fit(X_tfidf, y_encoded)
        else:
            self.clf.fit(X_tfidf, y_encoded)

        return self

    def predict(self, texts: List[str]) -> List[str]:
        if isinstance(self.clf, MajorityClassBaseline):
            return self.clf.predict(texts)

        X_tfidf = self.vectorizer.transform(texts)
        preds_enc = self.clf.predict(X_tfidf)
        return list(self.label_encoder.inverse_transform(preds_enc))

    def predict_proba(self, texts: List[str]) -> np.ndarray:
        if isinstance(self.clf, MajorityClassBaseline):
            return self.clf.predict_proba(texts)

        X_tfidf = self.vectorizer.transform(texts)
        return self.clf.predict_proba(X_tfidf)


class StructuredCountClassifier:
    """
    Baseline 3: Structured numerical feature counts + Logistic Regression / Gradient Boosting classifier.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.scaler = StandardScaler()
        self.clf = LogisticRegression(C=1.0, random_state=seed, max_iter=500, solver="lbfgs")
        self.label_encoder = LabelEncoder()
        self.classes_: np.ndarray = np.array([])
        self.is_calibrated: bool = False

    def fit(self, X: np.ndarray, y: List[str], calib_X: Optional[np.ndarray] = None, calib_y: Optional[List[str]] = None):
        y_encoded = self.label_encoder.fit_transform(y)
        self.classes_ = self.label_encoder.classes_

        X_scaled = self.scaler.fit_transform(X)

        if len(self.classes_) == 1:
            self.clf = MajorityClassBaseline()
            self.clf.fit(X, y)
            return self

        if calib_X is not None and calib_y:
            known_classes = set(self.classes_)
            valid_idx = [i for i, lbl in enumerate(calib_y) if lbl in known_classes]
            if len(valid_idx) >= 2 and len(set(calib_y[i] for i in valid_idx)) > 1:
                base_clf = LogisticRegression(C=1.0, random_state=self.seed, max_iter=500, solver="lbfgs")
                base_clf.fit(X_scaled, y_encoded)

                calib_X_filt = calib_X[valid_idx]
                calib_y_filt = [calib_y[i] for i in valid_idx]

                X_calib_scaled = self.scaler.transform(calib_X_filt)
                y_calib_enc = self.label_encoder.transform(calib_y_filt)

                calibrated = CalibratedClassifierCV(estimator=base_clf, method="sigmoid", cv="prefit")
                calibrated.fit(X_calib_scaled, y_calib_enc)
                self.clf = calibrated
                self.is_calibrated = True
            else:
                self.clf.fit(X_scaled, y_encoded)
        else:
            self.clf.fit(X_scaled, y_encoded)

        return self

    def predict(self, X: np.ndarray) -> List[str]:
        if isinstance(self.clf, MajorityClassBaseline):
            return self.clf.predict(X)

        X_scaled = self.scaler.transform(X)
        preds_enc = self.clf.predict(X_scaled)
        return list(self.label_encoder.inverse_transform(preds_enc))

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if isinstance(self.clf, MajorityClassBaseline):
            return self.clf.predict_proba(X)

        X_scaled = self.scaler.transform(X)
        return self.clf.predict_proba(X_scaled)
