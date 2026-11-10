"""Orchestration pipeline for dataset loading, preprocessing, model training, and evaluation."""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from ml.data.dataset_loader import DatasetLoader
from ml.data.preprocessing import DataPreprocessor
from ml.evaluation.metrics import AnomalyEvaluationMetrics, ClassificationEvaluationMetrics
from ml.features.feature_schema import FeatureSchema
from ml.models.model_interface import IsolationForestModel, RandomForestModel
from ml.training.train_isolation_forest import train_isolation_forest
from ml.training.train_random_forest import train_random_forest

logger = logging.getLogger("dpi_ids_ips.ml.training.pipeline")


class ModelTrainingPipeline:
    """
    Coordinates end-to-end ML training for DPI:
    1. Loads dataset from CSV files with leakage prevention.
    2. Performs stratified train/val/test splitting before any fitting.
    3. Fits preprocessor strictly on training split.
    4. Trains Isolation Forest on BENIGN subset.
    5. Trains Random Forest on balanced multiclass labels.
    6. Generates out-of-sample evaluation metrics, confusion matrices, and serialized model bundles.
    """

    def __init__(
        self,
        schema: Optional[FeatureSchema] = None,
        output_dir: str = "ml/artifacts",
        scaler_type: str = "standard",
        random_state: int = 42,
    ) -> None:
        self.schema = schema or FeatureSchema(selected_only=True)
        self.output_dir = output_dir
        self.scaler_type = scaler_type
        self.random_state = random_state
        self.preprocessor = DataPreprocessor(schema=self.schema, scaler_type=self.scaler_type)

    def run_training_pipeline(
        self,
        dataset_path: str | List[str],
        max_benign_per_file: int = 5000,
        max_attack_per_class: int = 5000,
        if_estimators: int = 100,
        if_contamination: float = 0.05,
        rf_estimators: int = 100,
        rf_max_depth: Optional[int] = 20,
    ) -> Dict[str, Any]:
        """
        Executes complete training and evaluation workflow.
        """
        logger.info(f"Starting ML training pipeline with dataset: {dataset_path}")

        # 1. Load balanced dataset
        loader = DatasetLoader(schema=self.schema, drop_duplicates=True)
        X_raw, y_raw, _ = loader.load_balanced_dataset(
            dataset_dir_or_files=dataset_path,
            max_benign_per_file=max_benign_per_file,
            max_attack_per_class=max_attack_per_class,
            random_seed=self.random_state,
        )

        if len(X_raw) == 0:
            raise ValueError(f"No records loaded from dataset path: {dataset_path}")

        logger.info(f"Loaded {len(X_raw)} records across {len(set(y_raw))} classes.")

        # 2. Split dataset BEFORE fitting preprocessor
        X_train_raw, X_val_raw, X_test_raw, y_train, y_val, y_test = self.preprocessor.split_dataset(
            X=X_raw,
            y=y_raw,
            test_size=0.2,
            val_size=0.1,
            random_state=self.random_state,
            stratify=True,
        )

        # 3. Fit preprocessor strictly on X_train_raw
        self.preprocessor.fit(X_train_raw, y_train)
        preprocessing_artifacts = self.preprocessor.export_artifacts()

        # Transform splits
        X_train, _ = self.preprocessor.transform(X_train_raw)
        X_val, _ = self.preprocessor.transform(X_val_raw)
        X_test, _ = self.preprocessor.transform(X_test_raw)

        # 4. Train Isolation Forest
        if_model, if_metrics = train_isolation_forest(
            X_train=X_train,
            y_train=y_train,
            X_test=X_test,
            y_test=y_test,
            feature_names=self.schema.feature_names,
            n_estimators=if_estimators,
            contamination=if_contamination,
            random_state=self.random_state,
            output_dir=self.output_dir,
            preprocessing=preprocessing_artifacts,
        )

        # 5. Train Random Forest
        rf_model, rf_metrics = train_random_forest(
            X_train=X_train,
            y_train=y_train,
            X_test=X_test,
            y_test=y_test,
            feature_names=self.schema.feature_names,
            n_estimators=rf_estimators,
            max_depth=rf_max_depth,
            random_state=self.random_state,
            output_dir=self.output_dir,
            preprocessing=preprocessing_artifacts,
        )

        return {
            "dataset_rows_total": len(X_raw),
            "train_rows": len(X_train),
            "val_rows": len(X_val),
            "test_rows": len(X_test),
            "feature_count": self.schema.num_features,
            "feature_names": self.schema.feature_names,
            "class_distribution": dict(loader.stats.class_distribution),
            "isolation_forest_metrics": if_metrics.to_dict(),
            "random_forest_metrics": rf_metrics.to_dict(),
            "output_dir": self.output_dir,
        }
