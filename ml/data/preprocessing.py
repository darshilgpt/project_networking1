"""Data preprocessing, leakage prevention, label encoding, and dataset splitting pipeline."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, RobustScaler, StandardScaler

from ml.features.feature_schema import FeatureSchema

logger = logging.getLogger("dpi_ids_ips.ml.preprocessing")


@dataclass
class PreprocessingArtifacts:
    """Stores fitted preprocessing transformers and metadata to prevent data leakage."""
    scaler_type: str  # "standard", "robust", "none"
    feature_names: List[str]
    label_classes: List[str]
    scaler_mean: Optional[List[float]] = None
    scaler_scale: Optional[List[float]] = None
    imputer_medians: Optional[List[float]] = None

    def save_json(self, filepath: str) -> None:
        """Saves preprocessing metadata to JSON."""
        data = {
            "scaler_type": self.scaler_type,
            "feature_names": self.feature_names,
            "label_classes": self.label_classes,
            "scaler_mean": self.scaler_mean,
            "scaler_scale": self.scaler_scale,
            "imputer_medians": self.imputer_medians,
        }
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_json(cls, filepath: str) -> PreprocessingArtifacts:
        """Loads preprocessing metadata from JSON."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            scaler_type=data["scaler_type"],
            feature_names=data["feature_names"],
            label_classes=data["label_classes"],
            scaler_mean=data.get("scaler_mean"),
            scaler_scale=data.get("scaler_scale"),
            imputer_medians=data.get("imputer_medians"),
        )


class DataPreprocessor:
    """
    Robust data preprocessing pipeline strictly enforcing zero-data-leakage principles.
    Fits imputers and scalers ONLY on training data splits, applying fitted parameters
    identically to validation and test sets.
    """

    def __init__(
        self,
        schema: Optional[FeatureSchema] = None,
        scaler_type: str = "standard",  # "standard", "robust", "none"
    ) -> None:
        self.schema = schema or FeatureSchema(selected_only=True)
        self.scaler_type = scaler_type.lower()
        self.label_encoder = LabelEncoder()
        self.scaler: Optional[StandardScaler | RobustScaler] = None
        self.feature_medians: Optional[np.ndarray] = None
        self.is_fitted = False

    def split_dataset(
        self,
        X: np.ndarray,
        y: List[str],
        test_size: float = 0.2,
        val_size: float = 0.1,
        random_state: int = 42,
        stratify: bool = True,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str], List[str], List[str]]:
        """
        Splits data into train, validation, and test partitions BEFORE fitting any scaler or imputer.
        Guarantees zero data leakage from test/validation distributions into training parameters.

        Returns:
            Tuple of (X_train, X_val, X_test, y_train, y_val, y_test)
        """
        if len(X) == 0:
            empty = np.empty((0, self.schema.num_features), dtype=np.float32)
            return empty, empty, empty, [], [], []

        # Convert y to numpy array for indexed slicing
        y_arr = np.array(y)

        # Check stratification viability (at least 2 samples per class required)
        stratify_arr = y_arr if stratify else None
        if stratify:
            unique, counts = np.unique(y_arr, return_counts=True)
            if any(c < 2 for c in counts):
                logger.warning("Some classes have fewer than 2 samples; disabling stratification to prevent split failure.")
                stratify_arr = None

        # First split off test set
        X_temp, X_test, y_temp, y_test = train_test_split(
            X,
            y_arr,
            test_size=test_size,
            random_state=random_state,
            stratify=stratify_arr,
        )

        # Then split remaining into train and validation if val_size > 0
        if val_size > 0.0:
            rel_val_size = val_size / (1.0 - test_size)
            stratify_temp = y_temp if (stratify and stratify_arr is not None) else None
            if stratify_temp is not None:
                unique, counts = np.unique(y_temp, return_counts=True)
                if any(c < 2 for c in counts):
                    stratify_temp = None

            X_train, X_val, y_train, y_val = train_test_split(
                X_temp,
                y_temp,
                test_size=rel_val_size,
                random_state=random_state,
                stratify=stratify_temp,
            )
        else:
            X_train = X_temp
            y_train = y_temp
            X_val = np.empty((0, self.schema.num_features), dtype=np.float32)
            y_val = np.array([], dtype=y_temp.dtype)

        return (
            X_train,
            X_val,
            X_test,
            list(y_train),
            list(y_val),
            list(y_test),
        )

    def fit(self, X_train: np.ndarray, y_train: List[str]) -> DataPreprocessor:
        """
        Fits imputer medians, scaler parameters, and label encoder strictly on training data.
        """
        if len(X_train) == 0:
            raise ValueError("Cannot fit preprocessor on empty training data.")

        # 1. Compute feature medians on training data for missing-value imputation
        self.feature_medians = np.nanmedian(X_train, axis=0)
        # Fallback for completely nan columns
        self.feature_medians = np.nan_to_num(self.feature_medians, nan=0.0)

        # Impute training array
        X_imputed = self._impute(X_train)

        # 2. Fit scaler on training data
        if self.scaler_type == "standard":
            self.scaler = StandardScaler()
            self.scaler.fit(X_imputed)
        elif self.scaler_type == "robust":
            self.scaler = RobustScaler()
            self.scaler.fit(X_imputed)
        else:
            self.scaler = None

        # 3. Fit label encoder on training labels
        self.label_encoder.fit(y_train)
        self.is_fitted = True
        return self

    def transform(
        self,
        X: np.ndarray,
        y: Optional[List[str]] = None,
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Applies fitted imputation, scaling, and label encoding to input arrays.
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted on training data before calling transform.")

        if len(X) == 0:
            empty = np.empty((0, self.schema.num_features), dtype=np.float32)
            return empty, None

        # 1. Impute missing/infinite using fitted training medians
        X_imputed = self._impute(X)

        # 2. Scale features using fitted scaler
        if self.scaler is not None:
            X_scaled = self.scaler.transform(X_imputed).astype(np.float32)
        else:
            X_scaled = X_imputed.astype(np.float32)

        # 3. Transform labels if provided
        y_encoded = None
        if y is not None:
            # Handle unseen test labels gracefully
            known_classes = set(self.label_encoder.classes_)
            sanitized_y = [lbl if lbl in known_classes else "UNKNOWN" for lbl in y]
            if "UNKNOWN" not in known_classes and any(lbl not in known_classes for lbl in y):
                # Fallback to first known class to prevent crashing
                fallback_class = self.label_encoder.classes_[0]
                sanitized_y = [lbl if lbl in known_classes else fallback_class for lbl in y]
            y_encoded = self.label_encoder.transform(sanitized_y)

        return X_scaled, y_encoded

    def fit_transform(
        self,
        X_train: np.ndarray,
        y_train: List[str],
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Convenience method to fit on training data and return transformed training sets."""
        self.fit(X_train, y_train)
        X_tr, y_tr = self.transform(X_train, y_train)
        assert y_tr is not None
        return X_tr, y_tr

    def _impute(self, X: np.ndarray) -> np.ndarray:
        """Replaces NaN, Inf, and -Inf values with fitted training feature medians."""
        X_clean = np.copy(X)
        for col_idx in range(X_clean.shape[1]):
            col = X_clean[:, col_idx]
            invalid_mask = np.isnan(col) | np.isinf(col)
            if np.any(invalid_mask):
                median_val = self.feature_medians[col_idx] if self.feature_medians is not None else 0.0
                X_clean[invalid_mask, col_idx] = median_val
        return X_clean

    def export_artifacts(self) -> PreprocessingArtifacts:
        """Exports fitted preprocessing parameters as serializable artifacts."""
        if not self.is_fitted:
            raise RuntimeError("Cannot export artifacts before fitting.")

        s_mean = None
        s_scale = None
        if isinstance(self.scaler, StandardScaler) and self.scaler.mean_ is not None:
            s_mean = self.scaler.mean_.tolist()
            s_scale = self.scaler.scale_.tolist() if self.scaler.scale_ is not None else None
        elif isinstance(self.scaler, RobustScaler) and self.scaler.center_ is not None:
            s_mean = self.scaler.center_.tolist()
            s_scale = self.scaler.scale_.tolist() if self.scaler.scale_ is not None else None

        return PreprocessingArtifacts(
            scaler_type=self.scaler_type,
            feature_names=self.schema.feature_names,
            label_classes=self.label_encoder.classes_.tolist(),
            scaler_mean=s_mean,
            scaler_scale=s_scale,
            imputer_medians=self.feature_medians.tolist() if self.feature_medians is not None else None,
        )

