"""Model evaluation metrics calculation and serialization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


@dataclass
class AnomalyEvaluationMetrics:
    """Metrics for unsupervised anomaly detection models (e.g. Isolation Forest)."""
    model_name: str
    total_samples: int
    normal_samples: int
    anomaly_samples: int
    contamination: float
    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    true_positive_rate: float
    roc_auc: Optional[float]
    pr_auc: Optional[float]
    confusion_matrix: List[List[int]]  # [[TN, FP], [FN, TP]]
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ClassMetric:
    """Per-class performance metrics for classification."""
    class_name: str
    support: int
    precision: float
    recall: float
    f1: float


@dataclass
class ClassificationEvaluationMetrics:
    """Metrics for supervised classification models (e.g. Random Forest)."""
    model_name: str
    total_samples: int
    num_classes: int
    classes: List[str]
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_precision: float
    weighted_recall: float
    weighted_f1: float
    per_class_metrics: Dict[str, Dict[str, float]]
    confusion_matrix: List[List[int]]
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def evaluate_anomaly_detector(
    y_true_binary: np.ndarray,  # 0 for NORMAL/BENIGN, 1 for ANOMALY/ATTACK
    y_pred_binary: np.ndarray,  # 0 for NORMAL, 1 for ANOMALY
    anomaly_scores: Optional[np.ndarray] = None,  # Higher = more anomalous
    model_name: str = "IsolationForest",
    contamination: float = 0.05,
    notes: str = "",
) -> AnomalyEvaluationMetrics:
    """Computes comprehensive anomaly detection evaluation metrics."""
    cm = confusion_matrix(y_true_binary, y_pred_binary, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    precision = float(precision_score(y_true_binary, y_pred_binary, zero_division=0))
    recall = float(recall_score(y_true_binary, y_pred_binary, zero_division=0))
    f1 = float(f1_score(y_true_binary, y_pred_binary, zero_division=0))
    acc = float(accuracy_score(y_true_binary, y_pred_binary))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    tpr = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0

    roc_auc_val: Optional[float] = None
    pr_auc_val: Optional[float] = None

    if anomaly_scores is not None and len(np.unique(y_true_binary)) > 1:
        try:
            roc_auc_val = float(roc_auc_score(y_true_binary, anomaly_scores))
        except Exception:
            roc_auc_val = None

        try:
            prec_vals, rec_vals, _ = precision_recall_curve(y_true_binary, anomaly_scores)
            pr_auc_val = float(auc(rec_vals, prec_vals))
        except Exception:
            pr_auc_val = None

    return AnomalyEvaluationMetrics(
        model_name=model_name,
        total_samples=int(len(y_true_binary)),
        normal_samples=int(np.sum(y_true_binary == 0)),
        anomaly_samples=int(np.sum(y_true_binary == 1)),
        contamination=contamination,
        accuracy=acc,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=fpr,
        true_positive_rate=tpr,
        roc_auc=roc_auc_val,
        pr_auc=pr_auc_val,
        confusion_matrix=cm.tolist(),
        notes=notes,
    )


def evaluate_multiclass_classifier(
    y_true: List[str] | np.ndarray,
    y_pred: List[str] | np.ndarray,
    labels: List[str],
    model_name: str = "RandomForest",
    notes: str = "",
) -> ClassificationEvaluationMetrics:
    """Computes comprehensive multiclass classification metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    macro_prec = float(precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))

    weighted_prec = float(precision_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0))
    weighted_rec = float(recall_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=labels)

    per_class: Dict[str, Dict[str, float]] = {}
    prec_per_class = precision_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    rec_per_class = recall_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    f1_per_class = f1_score(y_true, y_pred, labels=labels, average=None, zero_division=0)

    y_arr = np.array(y_true)
    for i, cls_name in enumerate(labels):
        support_cnt = int(np.sum(y_arr == cls_name))
        per_class[cls_name] = {
            "support": support_cnt,
            "precision": float(prec_per_class[i]),
            "recall": float(rec_per_class[i]),
            "f1": float(f1_per_class[i]),
        }

    return ClassificationEvaluationMetrics(
        model_name=model_name,
        total_samples=int(len(y_true)),
        num_classes=len(labels),
        classes=labels,
        accuracy=acc,
        macro_precision=macro_prec,
        macro_recall=macro_rec,
        macro_f1=macro_f1,
        weighted_precision=weighted_prec,
        weighted_recall=weighted_rec,
        weighted_f1=weighted_f1,
        per_class_metrics=per_class,
        confusion_matrix=cm.tolist(),
        notes=notes,
    )

