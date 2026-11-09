"""Unit and integration tests for ML model training, evaluation, and inference."""

import os
import shutil
import tempfile
import numpy as np
import pytest

from ml.data.feature_mapping import AttackCategory
from ml.data.preprocessing import DataPreprocessor, PreprocessingArtifacts
from ml.evaluation.metrics import (
    evaluate_anomaly_detector,
    evaluate_multiclass_classifier,
)
from ml.features.feature_schema import FeatureSchema
from ml.models.model_interface import (
    AnomalyDecision,
    IsolationForestModel,
    RandomForestModel,
)
from ml.models.model_loader import (
    load_isolation_forest_bundle,
    load_random_forest_bundle,
    save_model_bundle,
)
from ml.training.train_isolation_forest import train_isolation_forest
from ml.training.train_pipeline import ModelTrainingPipeline
from ml.training.train_random_forest import train_random_forest


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def synthetic_data():
    """Generates a small deterministic synthetic dataset for fast unit tests."""
    np.random.seed(42)
    schema = FeatureSchema(selected_only=True)
    n_features = schema.num_features

    # 100 Benign samples (cluster 1)
    X_benign = np.random.normal(loc=10.0, scale=1.0, size=(100, n_features)).astype(np.float32)
    y_benign = [AttackCategory.BENIGN] * 100

    # 30 DoS samples (cluster 2)
    X_dos = np.random.normal(loc=50.0, scale=2.0, size=(30, n_features)).astype(np.float32)
    y_dos = [AttackCategory.DOS] * 30

    # 30 PortScan samples (cluster 3)
    X_scan = np.random.normal(loc=100.0, scale=3.0, size=(30, n_features)).astype(np.float32)
    y_scan = [AttackCategory.PORTSCAN] * 30

    X = np.vstack([X_benign, X_dos, X_scan])
    y = y_benign + y_dos + y_scan

    return schema, X, y


def test_isolation_forest_training_and_inference(synthetic_data, temp_dir):
    schema, X, y = synthetic_data
    preprocessor = DataPreprocessor(schema=schema, scaler_type="standard")

    X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.split_dataset(
        X, y, test_size=0.25, val_size=0.1, random_state=42
    )
    preprocessor.fit(X_train, y_train)

    X_train_s, _ = preprocessor.transform(X_train)
    X_test_s, _ = preprocessor.transform(X_test)

    model, metrics = train_isolation_forest(
        X_train=X_train_s,
        y_train=y_train,
        X_test=X_test_s,
        y_test=y_test,
        feature_names=schema.feature_names,
        n_estimators=50,
        contamination=0.15,
        random_state=42,
        output_dir=temp_dir,
    )

    assert isinstance(model, IsolationForestModel)
    assert metrics.total_samples == len(X_test)
    assert metrics.accuracy > 0.7  # Should cleanly separate benign cluster from distant attacks

    # Inference test
    results = model.predict(X_test_s[:5])
    assert len(results) == 5
    for r in results:
        assert r.decision in (AnomalyDecision.NORMAL, AnomalyDecision.ANOMALY)
        assert isinstance(r.anomaly_score, float)
        assert isinstance(r.is_anomaly, bool)


def test_random_forest_training_and_multiclass(synthetic_data, temp_dir):
    schema, X, y = synthetic_data
    preprocessor = DataPreprocessor(schema=schema, scaler_type="standard")

    X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.split_dataset(
        X, y, test_size=0.25, val_size=0.1, random_state=42
    )
    preprocessor.fit(X_train, y_train)

    X_train_s, _ = preprocessor.transform(X_train)
    X_test_s, _ = preprocessor.transform(X_test)

    model, metrics = train_random_forest(
        X_train=X_train_s,
        y_train=y_train,
        X_test=X_test_s,
        y_test=y_test,
        feature_names=schema.feature_names,
        n_estimators=50,
        max_depth=10,
        random_state=42,
        output_dir=temp_dir,
    )

    assert isinstance(model, RandomForestModel)
    assert metrics.num_classes == 3
    assert set(metrics.classes) == {AttackCategory.BENIGN, AttackCategory.DOS, AttackCategory.PORTSCAN}
    assert metrics.accuracy > 0.9

    # Multiclass probability outputs
    results = model.predict(X_test_s[:5])
    assert len(results) == 5
    for r in results:
        assert r.predicted_class in metrics.classes
        assert 0.0 <= r.confidence <= 1.0
        assert len(r.class_probabilities) == 3
        assert sum(r.class_probabilities.values()) == pytest.approx(1.0, abs=1e-4)


def test_model_bundle_save_and_reload(synthetic_data, temp_dir):
    schema, X, y = synthetic_data
    preprocessor = DataPreprocessor(schema=schema, scaler_type="standard")
    X_train, _, X_test, y_train, _, y_test = preprocessor.split_dataset(X, y, test_size=0.2, val_size=0.0)
    preprocessor.fit(X_train, y_train)
    artifacts = preprocessor.export_artifacts()

    # Train and save IsolationForest
    if_model, _ = train_isolation_forest(
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        feature_names=schema.feature_names,
        output_dir=temp_dir,
        preprocessing=artifacts,
    )

    # Train and save RandomForest
    rf_model, _ = train_random_forest(
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        feature_names=schema.feature_names,
        output_dir=temp_dir,
        preprocessing=artifacts,
    )

    # Reload IsolationForest
    if_dir = os.path.join(temp_dir, "isolation_forest")
    loaded_if, loaded_prep_if = load_isolation_forest_bundle(if_dir)
    assert loaded_if.expected_num_features == schema.num_features
    assert loaded_prep_if is not None
    assert loaded_prep_if.scaler_type == "standard"

    # Reload RandomForest
    rf_dir = os.path.join(temp_dir, "random_forest")
    loaded_rf, loaded_prep_rf = load_random_forest_bundle(rf_dir)
    assert loaded_rf.expected_num_features == schema.num_features
    assert len(loaded_rf.class_names) == 3

    # Check predictions match before and after reload
    p1 = if_model.predict(X_test[:2])
    p2 = loaded_if.predict(X_test[:2])
    assert [x.decision for x in p1] == [x.decision for x in p2]


def test_feature_order_and_dimension_validation(synthetic_data, temp_dir):
    schema, X, y = synthetic_data
    rf_model, _ = train_random_forest(
        X_train=X,
        y_train=y,
        X_test=X,
        y_test=y,
        feature_names=schema.feature_names,
        output_dir=temp_dir,
    )

    # Valid input
    assert len(rf_model.predict(X[:1])) == 1

    # Invalid feature count (e.g. 10 features instead of schema.num_features)
    with pytest.raises(ValueError, match="Feature dimension mismatch"):
        rf_model.predict(np.zeros((1, 10), dtype=np.float32))


def test_missing_artifacts_handling():
    with pytest.raises(FileNotFoundError):
        load_isolation_forest_bundle("non_existent_dir_123")


def test_reproducibility(synthetic_data):
    schema, X, y = synthetic_data
    m1, met1 = train_random_forest(
        X_train=X, y_train=y, X_test=X, y_test=y, feature_names=schema.feature_names, random_state=42
    )
    m2, met2 = train_random_forest(
        X_train=X, y_train=y, X_test=X, y_test=y, feature_names=schema.feature_names, random_state=42
    )

    preds1 = [r.predicted_class for r in m1.predict(X)]
    preds2 = [r.predicted_class for r in m2.predict(X)]
    assert preds1 == preds2
    assert met1.accuracy == met2.accuracy


def test_real_cicids2017_smoke_training(temp_dir):
    """Smoke test training both models on real local CIC-IDS2017 files."""
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

    pipeline = ModelTrainingPipeline(
        output_dir=temp_dir,
        scaler_type="standard",
        random_state=42,
    )

    # Run pipeline with small sample limits for fast smoke test
    results = pipeline.run_training_pipeline(
        dataset_path=dataset_dir,
        max_benign_per_file=500,
        max_attack_per_class=500,
        if_estimators=20,
        if_contamination=0.05,
        rf_estimators=20,
        rf_max_depth=10,
    )

    assert results["train_rows"] > 0
    assert results["test_rows"] > 0
    assert results["feature_count"] == 40
    assert "accuracy" in results["isolation_forest_metrics"]
    assert "accuracy" in results["random_forest_metrics"]

    # Verify saved artifacts exist on disk
    assert os.path.exists(os.path.join(temp_dir, "isolation_forest", "model.joblib"))
    assert os.path.exists(os.path.join(temp_dir, "isolation_forest", "metadata.json"))
    assert os.path.exists(os.path.join(temp_dir, "random_forest", "model.joblib"))
    assert os.path.exists(os.path.join(temp_dir, "random_forest", "metadata.json"))
    assert os.path.exists(os.path.join(temp_dir, "reports", "isolation_forest_evaluation.json"))
    assert os.path.exists(os.path.join(temp_dir, "reports", "random_forest_evaluation.json"))

