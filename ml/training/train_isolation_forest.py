"""Training pipeline for unsupervised Isolation Forest anomaly detection."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from ml.data.feature_mapping import AttackCategory
from ml.data.preprocessing import DataPreprocessor, PreprocessingArtifacts
from ml.evaluation.evaluation_report import save_evaluation_report
from ml.evaluation.metrics import AnomalyEvaluationMetrics, evaluate_anomaly_detector
from ml.features.feature_schema import FeatureSchema
from ml.models.model_interface import IsolationForestModel
from ml.models.model_loader import save_model_bundle

logger = logging.getLogger("dpi_ids_ips.ml.training.isolation_forest")


def train_isolation_forest(
    X_train: np.ndarray,
    y_train: List[str],
    X_test: np.ndarray,
    y_test: List[str],
    feature_names: List[str],
    n_estimators: int = 100,
    contamination: float = 0.05,
    max_samples: float | int = "auto",
    random_state: int = 42,
    output_dir: Optional[str] = None,
    preprocessing: Optional[PreprocessingArtifacts] = None,
) -> Tuple[IsolationForestModel, AnomalyEvaluationMetrics]:
    """
    Trains an unsupervised IsolationForest model strictly on BENIGN flows from X_train,
    and evaluates out-of-sample anomaly detection performance on (X_test, y_test).

    Requirements:
    - Train primarily on BENIGN traffic.
    - Exclude attack labels from model inputs during training.
    - Evaluate on test set with ground-truth binary labels (BENIGN = 0, ATTACK = 1).
    - Save trained estimator bundle with artifacts and reports.
    """
    logger.info("Initializing IsolationForest training pipeline...")
    start_time = time.time()

    # 1. Filter X_train to BENIGN traffic only for unsupervised normal baseline learning
    y_train_arr = np.array(y_train)
    benign_mask = (y_train_arr == AttackCategory.BENIGN)
    X_train_benign = X_train[benign_mask]

    if len(X_train_benign) == 0:
        logger.warning("No BENIGN traffic found in training partition; falling back to full training set.")
        X_train_benign = X_train

    logger.info(
        f"Fitting IsolationForest on {len(X_train_benign)} BENIGN flows "
        f"(total train rows: {len(X_train)}, features: {X_train.shape[1]})."
    )

    # 2. Fit IsolationForest estimator
    estimator = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples=max_samples,
        random_state=random_state,
        n_jobs=-1,
    )
    estimator.fit(X_train_benign)

    train_duration = time.time() - start_time
    logger.info(f"IsolationForest fit complete in {train_duration:.2f} seconds.")

    # 3. Wrap in model interface
    meta = {
        "n_estimators": n_estimators,
        "contamination": contamination,
        "max_samples": str(max_samples),
        "random_state": random_state,
        "train_rows_benign": len(X_train_benign),
        "train_rows_total": len(X_train),
        "train_duration_seconds": round(train_duration, 3),
        "feature_count": len(feature_names),
    }

    model = IsolationForestModel(
        estimator=estimator,
        feature_names=feature_names,
        contamination=contamination,
        model_version="1.0.0",
        training_metadata=meta,
    )

    # 4. Out-of-sample evaluation on held-out test data
    logger.info(f"Evaluating IsolationForest on {len(X_test)} test samples...")
    y_test_arr = np.array(y_test)
    y_true_binary = np.where(y_test_arr == AttackCategory.BENIGN, 0, 1)

    # Predict anomalies
    inferences = model.predict(X_test)
    y_pred_binary = np.array([1 if inf.is_anomaly else 0 for inf in inferences], dtype=int)
    anomaly_scores = np.array([inf.anomaly_score for inf in inferences], dtype=float)

    metrics = evaluate_anomaly_detector(
        y_true_binary=y_true_binary,
        y_pred_binary=y_pred_binary,
        anomaly_scores=anomaly_scores,
        model_name="IsolationForest",
        contamination=contamination,
        notes="Unsupervised baseline trained strictly on BENIGN flows.",
    )

    # 5. Persist artifacts if output_dir provided
    if output_dir:
        model_dir = os.path.join(output_dir, "isolation_forest")
        report_dir = os.path.join(output_dir, "reports")
        save_model_bundle(model, preprocessing, model_dir)

        json_rep = os.path.join(report_dir, "isolation_forest_evaluation.json")
        txt_rep = os.path.join(report_dir, "isolation_forest_evaluation.md")
        save_evaluation_report(metrics, json_rep, txt_rep, extra_metadata=meta)
        logger.info(f"Saved IsolationForest artifacts to {model_dir} and {json_rep}")

    return model, metrics

