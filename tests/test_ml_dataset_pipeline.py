"""Unit and integration tests for Phase 5.1 ML Dataset Preparation and Network Feature Engineering."""

from __future__ import annotations

import csv
import math
import os
import tempfile
import numpy as np
import pytest

from ml.data.dataset_loader import DatasetLoader, normalize_column_name
from ml.data.feature_mapping import AttackCategory, AttackLabelMapper, clean_raw_label
from ml.data.preprocessing import DataPreprocessor, PreprocessingArtifacts
from ml.features.feature_schema import CANONICAL_FEATURES, FeatureSchema
from ml.features.flow_features import LiveFlowFeatureExtractor
from models.flow_model import Flow, FlowKey, FlowStats


# --- Test 1: Feature Schema and Canonical Ordering ---
def test_feature_schema_canonical_ordering_and_compatibility():
    """Verifies that the canonical feature schema defines consistent, non-leaking features and compatibility reports."""
    schema = FeatureSchema(selected_only=True)
    assert schema.num_features > 30

    # Ensure leakage-prone fields are strictly excluded
    leakage_fields = {"src_ip", "dst_ip", "flow_id", "timestamp", "label"}
    for f in schema.features:
        assert f.name not in leakage_fields

    # Report structure check
    report = schema.generate_compatibility_report()
    assert report["common_selected_for_ml"] == schema.num_features
    assert report["cicids2017_available_count"] >= schema.num_features


# --- Test 2: Attack Label Mapping & Cleaning ---
def test_attack_label_mapping_and_unknowns():
    """Verifies that CIC-IDS2017 labels are mapped to canonical categories and unknown labels are caught."""
    mapper = AttackLabelMapper()

    # Known CIC-IDS2017 labels
    assert mapper.map_label("BENIGN")[0] == AttackCategory.BENIGN
    assert mapper.map_label("DDoS")[0] == AttackCategory.DDOS
    assert mapper.map_label("PortScan")[0] == AttackCategory.PORTSCAN
    assert mapper.map_label("Bot")[0] == AttackCategory.BOT
    assert mapper.map_label("DoS GoldenEye")[0] == AttackCategory.DOS
    assert mapper.map_label("DoS Slowhttptest")[0] == AttackCategory.DOS
    assert mapper.map_label("FTP-Patator")[0] == AttackCategory.BRUTE_FORCE
    assert mapper.map_label("SSH-Patator")[0] == AttackCategory.BRUTE_FORCE
    assert mapper.map_label("Web Attack \ufffd Brute Force")[0] == AttackCategory.WEB_ATTACK
    assert mapper.map_label("Web Attack \ufffd Sql Injection")[0] == AttackCategory.WEB_ATTACK
    assert mapper.map_label("Web Attack \ufffd XSS")[0] == AttackCategory.WEB_ATTACK
    assert mapper.map_label("Heartbleed")[0] == AttackCategory.HEARTBLEED
    assert mapper.map_label("Infiltration")[0] == AttackCategory.INFILTRATION

    # Unknown label handling
    cat, orig = mapper.map_label("NovelZeroDayAttack123")
    assert cat == AttackCategory.UNKNOWN
    assert orig == "NovelZeroDayAttack123"
    assert "NovelZeroDayAttack123" in mapper.discovered_unknown_labels


# --- Test 3: Synthetic Dataset Loading, Column Normalization & Imputation ---
def test_dataset_loader_synthetic_files():
    """Tests loading multiple synthetic CSV files with varying columns, NaN/Inf values, and duplicate removal."""
    loader = DatasetLoader(drop_duplicates=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create CSV 1 (Normal with header variation)
        csv1 = os.path.join(tmpdir, "day1.csv")
        with open(csv1, "w", newline="", encoding="utf-8") as fp:
            writer = csv.writer(fp)
            writer.writerow([" Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets", "Label"])
            writer.writerow(["80", "15000", "5", "3", "BENIGN"])
            writer.writerow(["443", "20000", "10", "8", "DDoS"])
            # Duplicate row
            writer.writerow(["80", "15000", "5", "3", "BENIGN"])
            # Row with NaN and Inf
            writer.writerow(["8080", "NaN", "Infinity", "0", "PortScan"])

        # Create CSV 2 (Empty file & Malformed rows)
        csv2 = os.path.join(tmpdir, "day2.csv")
        with open(csv2, "w", newline="", encoding="utf-8") as fp:
            writer = csv.writer(fp)
            writer.writerow(["destination_port", "flow_duration", "label"])
            writer.writerow(["22", "50000", "SSH-Patator"])
            writer.writerow(["bad_row"])  # Corrupt row

        X, y, y_orig = loader.load_dataset([csv1, csv2])

        # Verification:
        # Total valid retained rows: 4 (row 1, row 2, row 4 [sanitized], and day2 row 1; 1 duplicate and 1 corrupt dropped)
        assert len(X) == 4
        assert len(y) == 4
        assert len(y_orig) == 4
        assert X.shape[1] == loader.schema.num_features

        # Check NaN/Inf sanitized to numeric floats
        assert not np.isnan(X).any()
        assert not np.isinf(X).any()

        # Check stats
        assert loader.stats.duplicate_rows_removed >= 1
        assert loader.stats.corrupt_rows_rejected >= 1
        assert "BENIGN" in loader.stats.class_distribution
        assert "DDoS" in loader.stats.class_distribution


# --- Test 4: Live Flow Feature Extraction ---
def test_live_flow_feature_extraction():
    """Verifies that LiveFlowFeatureExtractor extracts ordered canonical features from a live Flow object."""
    extractor = LiveFlowFeatureExtractor()

    key = FlowKey(ip_a="10.8.0.2", port_a=50000, ip_b="8.8.8.8", port_b=53, protocol="UDP")
    stats = FlowStats(
        packets_forward=5,
        packets_reverse=4,
        bytes_forward=400,
        bytes_reverse=800,
        first_seen=100.0,
        last_seen=100.5,
    )
    flow = Flow(
        flow_id=1,
        key=key,
        initiator_ip="10.8.0.2",
        initiator_port=50000,
        responder_ip="8.8.8.8",
        responder_port=53,
        protocol="UDP",
        stats=stats,
    )
    # Add optional tracking arrays
    flow.fwd_packet_lengths = [80, 80, 80, 80, 80]
    flow.bwd_packet_lengths = [200, 200, 200, 200]
    flow.tcp_flags_counts = {"SYN": 1, "ACK": 8}

    feat_dict = extractor.extract_features(flow)
    assert len(feat_dict) == extractor.schema.num_features
    assert feat_dict["dst_port"] == 53.0
    assert feat_dict["tot_fwd_pkts"] == 5.0
    assert feat_dict["tot_bwd_pkts"] == 4.0
    assert feat_dict["tot_pkts"] == 9.0
    assert feat_dict["tot_bytes"] == 1200.0
    assert feat_dict["flow_duration"] == 500_000.0  # 0.5s in microseconds

    # Check numpy vector conversion
    vec = extractor.extract_vector(flow)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (extractor.schema.num_features,)
    assert vec.dtype == np.float32


# --- Test 5: Preprocessing & Data Leakage Prevention ---
def test_data_preprocessor_leakage_prevention():
    """Verifies that DataPreprocessor fits scalers and imputers ONLY on train data without test leakage."""
    preprocessor = DataPreprocessor(scaler_type="standard")

    # Synthetic dataset: 100 samples with 2 classes
    np.random.seed(42)
    num_samples = 100
    num_feats = preprocessor.schema.num_features
    X = np.random.randn(num_samples, num_feats).astype(np.float32)
    # Introduce NaN and Inf into test/val region
    X[85, 0] = np.nan
    X[90, 1] = np.inf

    y = ["BENIGN"] * 70 + ["DDoS"] * 30

    # 1. Split data before fitting
    X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.split_dataset(
        X, y, test_size=0.2, val_size=0.1, random_state=42
    )

    assert len(X_train) == 70
    assert len(X_val) == 10
    assert len(X_test) == 20

    # 2. Fit strictly on training set
    preprocessor.fit(X_train, y_train)
    assert preprocessor.is_fitted
    assert preprocessor.feature_medians is not None

    # Train scaler mean must reflect training distribution only
    train_mean_0 = float(np.mean(X_train[:, 0]))
    assert math.isclose(preprocessor.scaler.mean_[0], train_mean_0, rel_tol=1e-3)

    # 3. Transform validation and test sets without leakage
    X_train_trans, y_train_enc = preprocessor.transform(X_train, y_train)
    X_val_trans, y_val_enc = preprocessor.transform(X_val, y_val)
    X_test_trans, y_test_enc = preprocessor.transform(X_test, y_test)

    # Check transformed arrays
    assert not np.isnan(X_test_trans).any()
    assert not np.isinf(X_test_trans).any()
    assert len(y_test_enc) == 20

    # 4. Export and serialize artifacts
    artifacts = preprocessor.export_artifacts()
    assert artifacts.scaler_type == "standard"
    assert len(artifacts.feature_names) == num_feats
    assert len(artifacts.label_classes) == 2


# --- Test 6: Local CIC-IDS2017 Dataset Smoke Test ---
def test_local_cicids2017_smoke_test():
    """Smoke test running on the local CIC-IDS2017 CSV files (sampled to 1,000 rows for test efficiency)."""
    # Try relative to cwd or project root
    candidates = [
        "ml/data/datasets/cicids2017",
        "project_networking/ml/data/datasets/cicids2017",
        os.path.join(os.path.dirname(__file__), "..", "ml", "data", "datasets", "cicids2017"),
    ]
    dataset_dir = None
    for cand in candidates:
        if os.path.exists(cand):
            dataset_dir = cand
            break

    if not dataset_dir:
        pytest.skip("Local CIC-IDS2017 dataset directory not found.")

    loader = DatasetLoader(chunk_size=1000)
    files = loader.discover_files(dataset_dir)
    assert len(files) == 8  # Exactly 8 CSV files present

    # Load small slice (500 rows per file) across the files
    X, y, y_orig = loader.load_dataset(files, max_rows_per_file=500)
    assert len(X) > 0
    assert len(X) == len(y)
    assert X.shape[1] == loader.schema.num_features
    assert not np.isnan(X).any()
    assert not np.isinf(X).any()
    assert "BENIGN" in loader.stats.class_distribution
