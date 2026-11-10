"""Training pipeline for supervised multiclass Random Forest classification."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ml.data.feature_mapping import AttackCategory
from ml.data.preprocessing import PreprocessingArtifacts
from ml.evaluation.evaluation_report import save_evaluation_report
from ml.evaluation.metrics import ClassificationEvaluationMetrics, evaluate_multiclass_classifier
from ml.models.model_interface import RandomForestModel
from ml.models.model_loader import save_model_bundle

logger = logging.getLogger("dpi_ids_ips.ml.training.random_forest")


def train_random_forest(
    X_train: np.ndarray,
    y_train: List[str],
    X_test: np.ndarray,
    y_test: List[str],
    feature_names: List[str],
    n_estimators: int = 100,
    max_depth: Optional[int] = 20,
    class_weight: str | Dict[str, float] = "balanced",
    random_state: int = 42,
    output_dir: Optional[str] = None,
    preprocessing: Optional[PreprocessingArtifacts] = None,
) -> Tuple[RandomForestModel, ClassificationEvaluationMetrics]:
    """
    Trains a supervised multiclass RandomForestClassifier using normalized attack categories.

    Requirements:
    - Train on normalized attack categories (BENIGN, DoS, DDoS, PortScan, Bot, Brute Force, Web Attack, Infiltration, Heartbleed).
    - Exclude UNKNOWN unless explicitly justified.
    - Use class_weight='balanced' to handle severe class imbalances without synthetic oversampling of test data.
    - Evaluate out-of-sample on held-out test data.
    - Return predicted class, probabilities, per-class metrics, and confusion matrix.
    - Save trained estimator bundle with artifacts and reports.
    """
    logger.info("Initializing RandomForest training pipeline...")
    start_time = time.time()

    # 1. Filter out UNKNOWN labels if any from training partition
    y_train_clean: List[str] = []
    indices_keep: List[int] = []
    for i, label in enumerate(y_train):
        if label != AttackCategory.UNKNOWN:
            y_train_clean.append(label)
            indices_keep.append(i)

    X_train_filtered = X_train[indices_keep]

    # Distinct class labels present in training data (sorted for deterministic ordering)
    classes_present = sorted(list(set(y_train_clean)))
    logger.info(
        f"Fitting RandomForest on {len(X_train_filtered)} flows across {len(classes_present)} classes: "
        f"{classes_present}"
    )

    # 2. Fit RandomForestClassifier
    estimator = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight=class_weight,
        random_state=random_state,
        n_jobs=-1,
    )
    estimator.fit(X_train_filtered, y_train_clean)

    train_duration = time.time() - start_time
    logger.info(f"RandomForest fit complete in {train_duration:.2f} seconds.")

    # 3. Wrap in model interface
    meta = {
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "class_weight": str(class_weight),
        "random_state": random_state,
        "train_rows": len(X_train_filtered),
        "train_duration_seconds": round(train_duration, 3),
        "classes_trained": classes_present,
        "feature_count": len(feature_names),
    }

    model = RandomForestModel(
        estimator=estimator,
        feature_names=feature_names,
        class_names=classes_present,
        model_version="1.0.0",
        training_metadata=meta,
    )

    # 4. Out-of-sample evaluation on held-out test data
    logger.info(f"Evaluating RandomForest on {len(X_test)} test samples...")
    # Filter test samples to only classes known to the model
    y_test_clean: List[str] = []
    test_indices_keep: List[int] = []
    for i, label in enumerate(y_test):
        if label in classes_present:
            y_test_clean.append(label)
            test_indices_keep.append(i)
        else:
            logger.debug(f"Skipping test sample with class {label} not present in training data.")

    X_test_filtered = X_test[test_indices_keep]

    inferences = model.predict(X_test_filtered)
    y_pred = [inf.predicted_class for inf in inferences]

    metrics = evaluate_multiclass_classifier(
        y_true=y_test_clean,
        y_pred=y_pred,
        labels=classes_present,
        model_name="RandomForest",
        notes="Supervised multiclass classifier with balanced class weights.",
    )

    # 5. Persist artifacts if output_dir provided
    if output_dir:
        model_dir = os.path.join(output_dir, "random_forest")
        report_dir = os.path.join(output_dir, "reports")
        save_model_bundle(model, preprocessing, model_dir)

        json_rep = os.path.join(report_dir, "random_forest_evaluation.json")
        txt_rep = os.path.join(report_dir, "random_forest_evaluation.md")
        save_evaluation_report(metrics, json_rep, txt_rep, extra_metadata=meta)
        logger.info(f"Saved RandomForest artifacts to {model_dir} and {json_rep}")

    return model, metrics

