"""High-performance chunked dataset loader for CIC-IDS2017 and multi-dataset architectures."""

from __future__ import annotations

import csv
import glob
import logging
import math
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Generator, Iterator, List, Optional, Set, Tuple
import numpy as np

from ml.data.feature_mapping import AttackCategory, AttackLabelMapper
from ml.features.feature_schema import CANONICAL_FEATURES, FeatureSchema

logger = logging.getLogger("dpi_ids_ips.ml.loader")


def normalize_column_name(col: str) -> str:
    """Normalizes raw CSV column names: lowercases, strips whitespace and special chars."""
    clean = col.strip().lower()
    # Replace non-alphanumeric with underscores
    clean = re.sub(r"[^a-z0-9]+", "_", clean)
    return clean.strip("_")


@dataclass
class DatasetStats:
    """Statistics captured during dataset ingestion."""
    files_discovered: List[str] = field(default_factory=list)
    files_loaded: List[str] = field(default_factory=list)
    total_rows_read: int = 0
    valid_rows_retained: int = 0
    duplicate_rows_removed: int = 0
    nan_inf_rows_sanitized: int = 0
    corrupt_rows_rejected: int = 0
    class_distribution: Dict[str, int] = field(default_factory=dict)
    original_label_distribution: Dict[str, int] = field(default_factory=dict)
    unknown_labels_encountered: Set[str] = field(default_factory=set)


class DatasetLoader:
    """
    Robust, chunked dataset loader for network intrusion datasets (CIC-IDS2017, UNSW-NB15, etc.).
    Extracts canonical features, validates and sanitizes numeric values, and handles varying column sets.
    """

    def __init__(
        self,
        schema: Optional[FeatureSchema] = None,
        label_mapper: Optional[AttackLabelMapper] = None,
        drop_duplicates: bool = True,
        chunk_size: int = 50000,
    ) -> None:
        self.schema = schema or FeatureSchema(selected_only=True)
        self.label_mapper = label_mapper or AttackLabelMapper()
        self.drop_duplicates = drop_duplicates
        self.chunk_size = chunk_size
        self.stats = DatasetStats()

    def discover_files(self, dataset_dir: str) -> List[str]:
        """Discovers all CSV files within the configured dataset directory."""
        if not os.path.exists(dataset_dir):
            logger.warning(f"Dataset directory does not exist: {dataset_dir}")
            return []

        pattern = os.path.join(dataset_dir, "*.csv")
        csv_files = sorted(glob.glob(pattern))
        if not csv_files:
            # Check subdirectories
            csv_files = sorted(glob.glob(os.path.join(dataset_dir, "**", "*.csv"), recursive=True))

        self.stats.files_discovered = list(csv_files)
        return csv_files

    def load_dataset(
        self,
        dataset_dir_or_files: str | List[str],
        max_rows_per_file: Optional[int] = None,
        row_filter: Optional[Callable[[Dict[str, float], str], bool]] = None,
    ) -> Tuple[np.ndarray, List[str], List[str]]:
        """
        Loads and processes multiple CSV files into canonical feature arrays.

        Args:
            dataset_dir_or_files: Directory path or explicit list of CSV file paths.
            max_rows_per_file: Optional ceiling on rows loaded per file (useful for fast smoke tests).
            row_filter: Optional predicate (feature_dict, label) -> bool.

        Returns:
            Tuple of:
            - X (np.ndarray): 2D array of shape (N, num_features), dtype float32.
            - y (List[str]): Canonical mapped category per row (e.g. "DDoS", "BENIGN").
            - y_orig (List[str]): Original cleaned raw labels.
        """
        if isinstance(dataset_dir_or_files, str):
            files = self.discover_files(dataset_dir_or_files)
        else:
            files = list(dataset_dir_or_files)
            self.stats.files_discovered = files

        all_features: List[List[float]] = []
        all_labels: List[str] = []
        all_orig_labels: List[str] = []

        seen_rows_hashes: Set[int] = set()

        for fpath in files:
            fname = os.path.basename(fpath)
            logger.info(f"Loading dataset file: {fname}")

            try:
                file_features, file_labels, file_orig_labels = self._load_single_file(
                    filepath=fpath,
                    max_rows=max_rows_per_file,
                    seen_hashes=seen_rows_hashes,
                    row_filter=row_filter,
                )
                all_features.extend(file_features)
                all_labels.extend(file_labels)
                all_orig_labels.extend(file_orig_labels)
                self.stats.files_loaded.append(fname)
            except Exception as e:
                logger.error(f"Error loading CSV file {fname}: {e}", exc_info=True)

        self.stats.valid_rows_retained = len(all_labels)

        # Convert to float32 numpy array
        if all_features:
            X = np.array(all_features, dtype=np.float32)
        else:
            X = np.empty((0, self.schema.num_features), dtype=np.float32)

        return X, all_labels, all_orig_labels

    def load_balanced_dataset(
        self,
        dataset_dir_or_files: str | List[str],
        max_benign_per_file: int = 5000,
        max_attack_per_class: int = 5000,
        random_seed: int = 42,
    ) -> Tuple[np.ndarray, List[str], List[str]]:
        """
        Loads a balanced subset across all CSV files ensuring minority attack classes
        are retained while preventing majority benign/DoS classes from drowning them.

        Args:
            dataset_dir_or_files: Directory path or list of file paths.
            max_benign_per_file: Max BENIGN flows to take per file.
            max_attack_per_class: Max attack flows to take per attack class.
            random_seed: Seed for reproducible sampling.

        Returns:
            Tuple of (X, y, y_orig).
        """
        if isinstance(dataset_dir_or_files, str):
            files = self.discover_files(dataset_dir_or_files)
        else:
            files = list(dataset_dir_or_files)
            self.stats.files_discovered = files

        all_features: List[List[float]] = []
        all_labels: List[str] = []
        all_orig_labels: List[str] = []

        seen_rows_hashes: Set[int] = set()
        class_counts: Dict[str, int] = {}

        for fpath in files:
            fname = os.path.basename(fpath)
            logger.info(f"Loading balanced slice from file: {fname}")

            file_benign_count = 0

            def balanced_filter(feat_dict: Dict[str, float], label: str) -> bool:
                nonlocal file_benign_count
                if label == AttackCategory.BENIGN:
                    if file_benign_count >= max_benign_per_file:
                        return False
                    file_benign_count += 1
                    return True
                else:
                    current_count = class_counts.get(label, 0)
                    if current_count >= max_attack_per_class:
                        return False
                    class_counts[label] = current_count + 1
                    return True

            try:
                file_features, file_labels, file_orig_labels = self._load_single_file(
                    filepath=fpath,
                    max_rows=None,
                    seen_hashes=seen_rows_hashes,
                    row_filter=balanced_filter,
                )
                all_features.extend(file_features)
                all_labels.extend(file_labels)
                all_orig_labels.extend(file_orig_labels)
                self.stats.files_loaded.append(fname)
            except Exception as e:
                logger.error(f"Error loading CSV file {fname}: {e}", exc_info=True)

        self.stats.valid_rows_retained = len(all_labels)

        if all_features:
            X = np.array(all_features, dtype=np.float32)
        else:
            X = np.empty((0, self.schema.num_features), dtype=np.float32)

        return X, all_labels, all_orig_labels

    def _load_single_file(
        self,
        filepath: str,
        max_rows: Optional[int],
        seen_hashes: Set[int],
        row_filter: Optional[Callable[[Dict[str, float], str], bool]],
    ) -> Tuple[List[List[float]], List[str], List[str]]:
        """Processes a single CSV file, mapping columns and handling missing/infinite values."""
        features_list: List[List[float]] = []
        labels_list: List[str] = []
        orig_labels_list: List[str] = []

        with open(filepath, "r", encoding="utf-8", errors="ignore") as fp:
            reader = csv.reader(fp)
            raw_header = next(reader, None)
            if not raw_header:
                return [], [], []

            # Normalize header columns
            norm_header = [normalize_column_name(c) for c in raw_header]
            col_to_idx = {c: i for i, c in enumerate(norm_header)}

            # Locate label column
            label_col_idx = -1
            for l_candidate in ("label", "attack", "class"):
                if l_candidate in col_to_idx:
                    label_col_idx = col_to_idx[l_candidate]
                    break

            # Map canonical features to CSV column indices
            # For each canonical feature, find its corresponding index in this specific CSV
            feat_indices: List[Optional[int]] = []
            for f in self.schema.features:
                idx = None
                if f.cicids2017_column and f.cicids2017_column in col_to_idx:
                    idx = col_to_idx[f.cicids2017_column]
                feat_indices.append(idx)

            # Special column indices for derived fields (tot_pkts, tot_bytes)
            fwd_pkts_idx = col_to_idx.get("total_fwd_packets")
            bwd_pkts_idx = col_to_idx.get("total_backward_packets")
            fwd_bytes_idx = col_to_idx.get("total_length_of_fwd_packets")
            bwd_bytes_idx = col_to_idx.get("total_length_of_bwd_packets")

            rows_read_in_file = 0

            for row in reader:
                if not row or len(row) < 2:
                    self.stats.corrupt_rows_rejected += 1
                    continue

                self.stats.total_rows_read += 1
                rows_read_in_file += 1

                # Extract label
                raw_label_str = row[label_col_idx].strip() if (label_col_idx >= 0 and len(row) > label_col_idx) else "UNKNOWN"
                canon_label, orig_clean = self.label_mapper.map_label(raw_label_str)

                # Record label distribution
                self.stats.class_distribution[canon_label] = self.stats.class_distribution.get(canon_label, 0) + 1
                self.stats.original_label_distribution[orig_clean] = self.stats.original_label_distribution.get(orig_clean, 0) + 1
                if canon_label == AttackCategory.UNKNOWN:
                    self.stats.unknown_labels_encountered.add(raw_label_str)

                # Extract canonical feature values
                row_vector: List[float] = []
                is_row_corrupt = False

                for f_def, idx in zip(self.schema.features, feat_indices):
                    val = 0.0
                    if idx is not None and idx < len(row):
                        cell = row[idx].strip()
                        # Numeric parsing with NaN/Inf handling
                        try:
                            val = float(cell)
                            if math.isnan(val) or math.isinf(val):
                                self.stats.nan_inf_rows_sanitized += 1
                                val = 0.0  # Conservative imputation of non-finite numbers
                        except ValueError:
                            # Non-numeric string in numeric feature
                            val = 0.0
                    else:
                        # Handle derived or missing canonical features
                        if f_def.name == "tot_pkts":
                            try:
                                f_pkts = float(row[fwd_pkts_idx]) if fwd_pkts_idx is not None and fwd_pkts_idx < len(row) else 0.0
                                b_pkts = float(row[bwd_pkts_idx]) if bwd_pkts_idx is not None and bwd_pkts_idx < len(row) else 0.0
                                if math.isnan(f_pkts) or math.isinf(f_pkts):
                                    self.stats.nan_inf_rows_sanitized += 1
                                    f_pkts = 0.0
                                if math.isnan(b_pkts) or math.isinf(b_pkts):
                                    self.stats.nan_inf_rows_sanitized += 1
                                    b_pkts = 0.0
                                val = f_pkts + b_pkts
                            except (ValueError, TypeError):
                                val = 0.0
                        elif f_def.name == "tot_bytes":
                            try:
                                f_b = float(row[fwd_bytes_idx]) if fwd_bytes_idx is not None and fwd_bytes_idx < len(row) else 0.0
                                b_b = float(row[bwd_bytes_idx]) if bwd_bytes_idx is not None and bwd_bytes_idx < len(row) else 0.0
                                if math.isnan(f_b) or math.isinf(f_b):
                                    self.stats.nan_inf_rows_sanitized += 1
                                    f_b = 0.0
                                if math.isnan(b_b) or math.isinf(b_b):
                                    self.stats.nan_inf_rows_sanitized += 1
                                    b_b = 0.0
                                val = f_b + b_b
                            except (ValueError, TypeError):
                                val = 0.0
                        else:
                            val = 0.0

                    row_vector.append(val)

                # Deduplication check
                if self.drop_duplicates:
                    # Hash feature tuple and label
                    row_hash = hash((tuple(row_vector), canon_label))
                    if row_hash in seen_hashes:
                        self.stats.duplicate_rows_removed += 1
                        continue
                    seen_hashes.add(row_hash)

                # Optional row filter
                if row_filter is not None:
                    row_dict = {f.name: row_vector[i] for i, f in enumerate(self.schema.features)}
                    if not row_filter(row_dict, canon_label):
                        continue

                features_list.append(row_vector)
                labels_list.append(canon_label)
                orig_labels_list.append(orig_clean)

                if max_rows and rows_read_in_file >= max_rows:
                    break

        return features_list, labels_list, orig_labels_list
