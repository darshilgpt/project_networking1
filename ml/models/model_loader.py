"""Model serialization, loading, and persistence using joblib and JSON."""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional, Tuple
import joblib

from ml.data.preprocessing import PreprocessingArtifacts
from ml.models.model_interface import IsolationForestModel, RandomForestModel

logger = logging.getLogger("dpi_ids_ips.ml.models.loader")


def save_model_bundle(
    model: IsolationForestModel | RandomForestModel,
    preprocessing: Optional[PreprocessingArtifacts],
    model_dir: str,
    model_filename: str = "model.joblib",
    metadata_filename: str = "metadata.json",
    preprocessing_filename: str = "preprocessing.json",
) -> Dict[str, str]:
    """
    Saves a trained model estimator via joblib and its associated metadata/preprocessing artifacts.
    """
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, model_filename)
    meta_path = os.path.join(model_dir, metadata_filename)
    prep_path = os.path.join(model_dir, preprocessing_filename)

    # 1. Save scikit-learn estimator
    joblib.dump(model.estimator, model_path, compress=3)

    # 2. Save metadata JSON
    metadata = {
        "model_type": model.__class__.__name__,
        "model_version": model.model_version,
        "feature_names": model.feature_names,
        "expected_num_features": model.expected_num_features,
        "training_metadata": model.training_metadata,
    }
    if isinstance(model, IsolationForestModel):
        metadata["contamination"] = model.contamination
    elif isinstance(model, RandomForestModel):
        metadata["class_names"] = model.class_names

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # 3. Save preprocessing artifacts if present
    saved_paths = {
        "model_path": model_path,
        "metadata_path": meta_path,
    }
    if preprocessing:
        preprocessing.save_json(prep_path)
        saved_paths["preprocessing_path"] = prep_path

    return saved_paths


def load_isolation_forest_bundle(model_dir: str) -> Tuple[IsolationForestModel, Optional[PreprocessingArtifacts]]:
    """Loads an IsolationForest model bundle from a directory."""
    model_path = os.path.join(model_dir, "model.joblib")
    meta_path = os.path.join(model_dir, "metadata.json")
    prep_path = os.path.join(model_dir, "preprocessing.json")

    if not os.path.exists(model_path) or not os.path.exists(meta_path):
        raise FileNotFoundError(f"Model artifacts not found in {model_dir}")

    estimator = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    preprocessing = None
    if os.path.exists(prep_path):
        preprocessing = PreprocessingArtifacts.load_json(prep_path)

    model = IsolationForestModel(
        estimator=estimator,
        feature_names=meta["feature_names"],
        contamination=meta.get("contamination", 0.05),
        model_version=meta.get("model_version", "1.0.0"),
        training_metadata=meta.get("training_metadata", {}),
    )
    return model, preprocessing


def load_random_forest_bundle(model_dir: str) -> Tuple[RandomForestModel, Optional[PreprocessingArtifacts]]:
    """Loads a RandomForest model bundle from a directory."""
    model_path = os.path.join(model_dir, "model.joblib")
    meta_path = os.path.join(model_dir, "metadata.json")
    prep_path = os.path.join(model_dir, "preprocessing.json")

    if not os.path.exists(model_path) or not os.path.exists(meta_path):
        raise FileNotFoundError(f"Model artifacts not found in {model_dir}")

    estimator = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    preprocessing = None
    if os.path.exists(prep_path):
        preprocessing = PreprocessingArtifacts.load_json(prep_path)

    model = RandomForestModel(
        estimator=estimator,
        feature_names=meta["feature_names"],
        class_names=meta.get("class_names", []),
        model_version=meta.get("model_version", "1.0.0"),
        training_metadata=meta.get("training_metadata", {}),
    )
    return model, preprocessing

