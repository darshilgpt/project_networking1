"""Inference and operational interfaces for trained ML models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


class AnomalyDecision(str, Enum):
    NORMAL = "NORMAL"
    ANOMALY = "ANOMALY"


@dataclass
class AnomalyInferenceResult:
    decision: AnomalyDecision
    anomaly_score: float  # Higher score = more anomalous
    is_anomaly: bool
    raw_prediction: int  # 1 (inlier) or -1 (outlier) from scikit-learn


@dataclass
class ClassificationInferenceResult:
    predicted_class: str
    confidence: float
    class_probabilities: Dict[str, float]
    all_classes: List[str]


class BaseMLModel(ABC):
    """Abstract base class for DPI ML models enforcing schema, version, and input validation."""

    def __init__(self, model_version: str = "1.0.0") -> None:
        self.model_version = model_version
        self.feature_names: List[str] = []
        self.expected_num_features: int = 0
        self.training_metadata: Dict[str, Any] = {}

    def validate_features(self, X: np.ndarray) -> np.ndarray:
        """Validates input feature dimensionality, non-emptiness, and finite values."""
        if not isinstance(X, np.ndarray):
            X = np.asarray(X, dtype=np.float32)

        if X.ndim == 1:
            X = X.reshape(1, -1)

        if X.ndim != 2:
            raise ValueError(f"Expected 2D array of features, got {X.ndim}D array.")

        if self.expected_num_features > 0 and X.shape[1] != self.expected_num_features:
            raise ValueError(
                f"Feature dimension mismatch: model expects {self.expected_num_features} features "
                f"({self.feature_names[:3]}...), but received {X.shape[1]} features."
            )

        if np.isnan(X).any() or np.isinf(X).any():
            # Conservative sanitization: replace non-finite with 0.0
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        return X

    @abstractmethod
    def predict(self, X: np.ndarray) -> Any:
        pass


class IsolationForestModel(BaseMLModel):
    """
    Wrapper for scikit-learn IsolationForest anomaly detection.
    Enforces training primarily on BENIGN baseline and outputs consistent NORMAL/ANOMALY decisions.
    """

    def __init__(
        self,
        estimator: Any,
        feature_names: List[str],
        contamination: float = 0.05,
        model_version: str = "1.0.0",
        training_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(model_version=model_version)
        self.estimator = estimator
        self.feature_names = list(feature_names)
        self.expected_num_features = len(self.feature_names)
        self.contamination = contamination
        self.training_metadata = training_metadata or {}

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Computes anomaly score where higher values indicate greater anomaly.
        scikit-learn decision_function returns positive for inliers and negative for outliers.
        We negate decision_function so higher = more anomalous.
        """
        X_val = self.validate_features(X)
        return -self.estimator.decision_function(X_val)

    def predict(self, X: np.ndarray) -> List[AnomalyInferenceResult]:
        """
        Predicts anomaly status for one or more feature vectors.
        Returns:
            List of AnomalyInferenceResult with NORMAL or ANOMALY decisions.
        """
        X_val = self.validate_features(X)
        raw_preds = self.estimator.predict(X_val)  # 1 for inlier, -1 for outlier
        scores = self.score_samples(X_val)

        results: List[AnomalyInferenceResult] = []
        for raw, score in zip(raw_preds, scores):
            is_anomaly = bool(raw == -1)
            decision = AnomalyDecision.ANOMALY if is_anomaly else AnomalyDecision.NORMAL
            results.append(
                AnomalyInferenceResult(
                    decision=decision,
                    anomaly_score=float(score),
                    is_anomaly=is_anomaly,
                    raw_prediction=int(raw),
                )
            )
        return results


class RandomForestModel(BaseMLModel):
    """
    Wrapper for scikit-learn RandomForestClassifier.
    Outputs normalized multiclass predictions, probabilities, and confidence scores.
    """

    def __init__(
        self,
        estimator: Any,
        feature_names: List[str],
        class_names: List[str],
        model_version: str = "1.0.0",
        training_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(model_version=model_version)
        self.estimator = estimator
        self.feature_names = list(feature_names)
        self.expected_num_features = len(self.feature_names)
        self.class_names = list(class_names)
        self.training_metadata = training_metadata or {}

    def predict(self, X: np.ndarray) -> List[ClassificationInferenceResult]:
        """
        Predicts attack category and class probabilities.
        """
        X_val = self.validate_features(X)
        raw_preds = self.estimator.predict(X_val)
        proba_matrix = self.estimator.predict_proba(X_val)

        results: List[ClassificationInferenceResult] = []
        for pred, proba in zip(raw_preds, proba_matrix):
            # Class mapping
            pred_class = str(pred)
            prob_dict = {cls: float(p) for cls, p in zip(self.class_names, proba)}
            max_conf = float(np.max(proba)) if len(proba) > 0 else 0.0

            results.append(
                ClassificationInferenceResult(
                    predicted_class=pred_class,
                    confidence=max_conf,
                    class_probabilities=prob_dict,
                    all_classes=self.class_names,
                )
            )
        return results

