"""Runtime integration engine for ML model inference and alert generation."""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple
import numpy as np

from ml.features.feature_schema import FeatureSchema
from ml.features.flow_features import LiveFlowFeatureExtractor
from ml.models.model_interface import (
    AnomalyDecision,
    IsolationForestModel,
    RandomForestModel,
)
from ml.models.model_loader import (
    load_isolation_forest_bundle,
    load_random_forest_bundle,
)
from ml.data.preprocessing import PreprocessingArtifacts
from ml.runtime.config import MLInferenceJob, MLRuntimeConfig, MLTelemetryMetrics
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.flow_model import Flow, TCPState

logger = logging.getLogger("dpi_ids_ips.ml.runtime.engine")


class MLRuntimeEngine:
    """
    Coordinates asynchronous runtime inference for Random Forest and Isolation Forest models.
    
    Guarantees:
    - Never executes inference inside the packet capture or per-packet processing thread.
    - Uses a bounded queue with explicit drop & telemetry accounting when saturated.
    - Prevents duplicate evaluations for the same flow.
    - Transforms features using saved PreprocessingArtifacts before inference.
    - Emits structured IDSAlert objects with advisory severity (never CRITICAL, never BLOCK).
    - Catches worker exceptions without affecting host pipeline or packet capture.
    """

    def __init__(
        self,
        config: Optional[MLRuntimeConfig] = None,
        on_alert_generated: Optional[Callable[[IDSAlert], None]] = None,
    ) -> None:
        self.config = config or MLRuntimeConfig()
        self.on_alert_generated = on_alert_generated

        self.metrics = MLTelemetryMetrics()
        self.schema = FeatureSchema(selected_only=True)
        self.feature_extractor = LiveFlowFeatureExtractor(schema=self.schema)

        # Loaded model bundles
        self.rf_model: Optional[RandomForestModel] = None
        self.rf_prep: Optional[PreprocessingArtifacts] = None
        self.if_model: Optional[IsolationForestModel] = None
        self.if_prep: Optional[PreprocessingArtifacts] = None

        self._alert_id_counter = 500000  # Offset to avoid collision with standard IDS alert IDs
        self._alert_id_lock = threading.Lock()

        # Deduplication state: tracks evaluated milestones per flow ID (bounded OrderedDict for LRU eviction)
        # Milestones: 0 = initial maturity; >=1 = packet milestones (e.g. 100, 1000); -1, -2... = byte milestones
        self._submitted_flows_lock = threading.Lock()
        self._flow_milestones_evaluated: Dict[int, Set[int]] = {}
        self._max_tracked_flows = 50000

        # Asynchronous worker infrastructure
        self._queue: queue.Queue[Optional[MLInferenceJob]] = queue.Queue(
            maxsize=self.config.queue_capacity
        )
        self._workers: List[threading.Thread] = []
        self._is_running = False

        # Load models safely
        if self.config.enabled:
            self._load_artifacts()
            self.start()

    def _next_alert_id(self) -> int:
        with self._alert_id_lock:
            self._alert_id_counter += 1
            return self._alert_id_counter

    def _load_artifacts(self) -> None:
        """Loads model bundles gracefully; on failure or missing files, disables ML without crashing."""
        base_dir = self.config.artifacts_dir
        if not os.path.exists(base_dir):
            if base_dir in ("ml/artifacts", "artifacts"):
                # Default path provided; check relative to module root or project_networking
                alt_dir = os.path.join(os.path.dirname(__file__), "..", "artifacts")
                if os.path.exists(alt_dir):
                    base_dir = os.path.abspath(alt_dir)
                elif os.path.exists(os.path.join("project_networking", base_dir)):
                    base_dir = os.path.abspath(os.path.join("project_networking", base_dir))
                else:
                    logger.warning(f"Configured ML artifacts directory '{base_dir}' does not exist. Disabling ML models.")
                    self.rf_model = None
                    self.if_model = None
                    return
            else:
                logger.warning(f"Configured ML artifacts directory '{base_dir}' does not exist. Disabling ML models.")
                self.rf_model = None
                self.if_model = None
                return

        # 1. Load Random Forest
        if self.config.random_forest_enabled:
            rf_dir = os.path.join(base_dir, "random_forest")
            try:
                self.rf_model, self.rf_prep = load_random_forest_bundle(rf_dir)
                logger.info(
                    f"Successfully loaded RandomForest model ({self.rf_model.expected_num_features} features, "
                    f"classes: {self.rf_model.class_names}) from {rf_dir}"
                )
            except Exception as e:
                logger.warning(
                    f"Could not load RandomForest model from {rf_dir}: {e}. Disabling RandomForest."
                )
                self.rf_model = None

        # 2. Load Isolation Forest
        if self.config.isolation_forest_enabled:
            if_dir = os.path.join(base_dir, "isolation_forest")
            try:
                self.if_model, self.if_prep = load_isolation_forest_bundle(if_dir)
                logger.info(
                    f"Successfully loaded IsolationForest model ({self.if_model.expected_num_features} features, "
                    f"contamination: {self.if_model.contamination}) from {if_dir}"
                )
            except Exception as e:
                logger.warning(
                    f"Could not load IsolationForest model from {if_dir}: {e}. Disabling IsolationForest."
                )
                self.if_model = None

    def start(self) -> None:
        """Starts asynchronous inference worker threads."""
        if self._is_running:
            return

        self._is_running = True
        for i in range(self.config.num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"MLInferenceWorker-{i+1}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)
        logger.info(
            f"Started {len(self._workers)} ML inference worker threads with queue capacity {self.config.queue_capacity}."
        )

    def stop(self, timeout: float = 2.0) -> None:
        """Gracefully terminates worker threads without data races, draining pending jobs within timeout."""
        if not self._is_running:
            return

        self._is_running = False
        start_t = time.perf_counter()

        # Attempt to drain pending queue items if practical within half of the allocated timeout
        drain_timeout = max(0.1, timeout * 0.5)
        deadline = start_t + drain_timeout
        while not self._queue.empty() and time.perf_counter() < deadline:
            time.sleep(0.02)

        # Send poison pills to all workers
        for _ in self._workers:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass

        # Join workers with remaining timeout
        for t in self._workers:
            remaining = max(0.05, timeout - (time.perf_counter() - start_t))
            t.join(timeout=remaining)

        self._workers.clear()
        logger.info("ML inference workers gracefully stopped.")

    def _get_flow_pending_milestones(self, flow: Flow) -> List[int]:
        """
        Determines which milestones (if any) are eligible for evaluation on this flow.
        Milestone conventions:
        - 0: Initial maturity (terminal TCP state or >= min_packets and >= min_duration).
        - positive integer M: Packet count milestone (e.g. 100, 1000).
        - negative integer -B: Byte volume milestone (e.g. -500000, -5000000).
        """
        with self._submitted_flows_lock:
            evaluated = self._flow_milestones_evaluated.get(flow.flow_id, set())

        pending: List[int] = []
        stats = flow.stats

        # 1. Check initial maturity milestone (0)
        if 0 not in evaluated:
            is_terminal = flow.tcp_state in (
                TCPState.CLOSED,
                TCPState.RESET,
                TCPState.FIN_WAIT,
                TCPState.FIN_WAIT_1,
                TCPState.FIN_WAIT_2,
                TCPState.TIME_WAIT,
            )
            has_min_packets = stats.total_packets >= self.config.min_packets_for_inference
            has_min_duration = stats.duration >= self.config.min_duration_for_inference

            if is_terminal or (has_min_packets and has_min_duration):
                pending.append(0)

        # 2. Check packet milestones (sorted ascending)
        for m in sorted(getattr(self.config, "packet_milestones", [100, 1000])):
            if m not in evaluated and stats.total_packets >= m:
                pending.append(m)

        # 3. Check byte milestones (sorted ascending)
        for bm in sorted(getattr(self.config, "byte_milestones", [500_000, 5_000_000])):
            m_key = -bm
            if m_key not in evaluated and stats.total_bytes >= bm:
                pending.append(m_key)

        return pending

    def should_evaluate_flow(self, flow: Flow) -> bool:
        """
        Determines whether a flow has matured sufficiently or crossed a new milestone.
        Conditions:
        - Engine must be running and enabled with at least one active model.
        - Flow has at least one pending unevaluated milestone (0, packet milestone, or byte milestone).
        """
        if not self._is_running or not self.config.enabled or (self.rf_model is None and self.if_model is None):
            return False

        return len(self._get_flow_pending_milestones(flow)) > 0

    def submit_flow(self, flow: Flow) -> bool:
        """
        Non-blocking submission of a flow to the asynchronous ML inference queue.
        Guarantees zero blocking of packet capture.
        Supports milestone-based re-evaluation for long-lived flows without redundant submissions.
        """
        if not self._is_running or not self.config.enabled or (self.rf_model is None and self.if_model is None):
            return False

        pending = self._get_flow_pending_milestones(flow)
        if not pending:
            return False

        with self._submitted_flows_lock:
            # Re-check under lock
            evaluated = self._flow_milestones_evaluated.setdefault(flow.flow_id, set())
            actually_new = [m for m in pending if m not in evaluated]
            if not actually_new:
                return False

            # Bounded cache management
            if len(self._flow_milestones_evaluated) >= self._max_tracked_flows:
                # Evict oldest half to maintain bounded memory
                remove_count = len(self._flow_milestones_evaluated) // 2
                it = iter(list(self._flow_milestones_evaluated.keys()))
                for _ in range(remove_count):
                    try:
                        del self._flow_milestones_evaluated[next(it)]
                    except (StopIteration, KeyError):
                        break

            # Mark milestones as evaluated
            evaluated.update(actually_new)

        # Extract features vector (40 features)
        try:
            feat_vec = self.feature_extractor.extract_vector(flow)
        except Exception as ex:
            logger.error(f"Failed to extract features for flow {flow.flow_id}: {ex}")
            return False

        job = MLInferenceJob(
            flow_id=flow.flow_id,
            flow_key_repr=f"{flow.source_repr} <-> {flow.dest_repr} ({flow.protocol})",
            source_ip=flow.initiator_ip,
            destination_ip=flow.responder_ip,
            source_port=flow.initiator_port,
            destination_port=flow.responder_port,
            protocol=flow.protocol,
            features_vector=feat_vec,
            timestamp=flow.stats.last_seen or time.time(),
        )

        try:
            self._queue.put_nowait(job)
            self.metrics.record_job_submitted()
            return True
        except queue.Full:
            self.metrics.record_queue_drop()
            logger.debug("ML inference queue saturated; dropping inference job.")
            return False

    def _worker_loop(self) -> None:
        """Main loop executed by worker threads."""
        while self._is_running:
            try:
                job = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if job is None:
                # Poison pill received
                self._queue.task_done()
                break

            start_t = time.perf_counter()
            try:
                self._process_inference_job(job)
                latency_ms = (time.perf_counter() - start_t) * 1000.0
                self.metrics.record_job_processed(latency_ms)
            except Exception as e:
                self.metrics.record_inference_failure()
                logger.error(f"Error in ML worker inference: {e}", exc_info=True)
            finally:
                self._queue.task_done()

    def _process_inference_job(self, job: MLInferenceJob) -> None:
        """Executes model inference and generates advisory alerts."""
        X_raw = job.features_vector.reshape(1, -1)

        # 1. Random Forest Classification
        if self.rf_model is not None:
            # Transform features using preprocessing artifacts
            X_scaled = self._scale_features(X_raw, self.rf_prep)
            results = self.rf_model.predict(X_scaled)
            if results:
                res = results[0]
                pred_class = res.predicted_class
                confidence = res.confidence

                # Alert only if NOT BENIGN and confidence meets threshold
                if pred_class != "BENIGN" and confidence >= self.config.rf_confidence_threshold:
                    self.metrics.record_rf_classification()
                    alert = self._create_rf_alert(job, pred_class, confidence, res.class_probabilities)
                    self._dispatch_alert(alert)

        # 2. Isolation Forest Anomaly Detection
        if self.if_model is not None:
            X_scaled = self._scale_features(X_raw, self.if_prep)
            results = self.if_model.predict(X_scaled)
            if results:
                res = results[0]
                if res.decision == AnomalyDecision.ANOMALY:
                    self.metrics.record_if_anomaly()
                    alert = self._create_if_alert(job, res.anomaly_score)
                    self._dispatch_alert(alert)

    def _scale_features(self, X: np.ndarray, prep: Optional[PreprocessingArtifacts]) -> np.ndarray:
        """Applies saved imputer medians and scaling parameters without modifying raw input."""
        if prep is None:
            return X

        X_out = np.copy(X)
        # Impute
        if prep.imputer_medians is not None:
            medians = np.array(prep.imputer_medians, dtype=np.float32)
            nan_mask = np.isnan(X_out)
            if nan_mask.any():
                X_out[nan_mask] = np.take(medians, np.where(nan_mask)[1])

        # Standard Scale
        if prep.scaler_type == "standard" and prep.scaler_mean is not None and prep.scaler_scale is not None:
            mean = np.array(prep.scaler_mean, dtype=np.float32)
            scale = np.array(prep.scaler_scale, dtype=np.float32)
            scale = np.where(scale == 0.0, 1.0, scale)
            X_out = (X_out - mean) / scale

        return X_out

    def _create_rf_alert(
        self,
        job: MLInferenceJob,
        pred_class: str,
        confidence: float,
        probs: Dict[str, float],
    ) -> IDSAlert:
        """Creates a structured IDSAlert for Random Forest classification."""
        evidence_dict = {
            "model": "RandomForest",
            "model_version": self.rf_model.model_version if self.rf_model else "1.0.0",
            "predicted_attack": pred_class,
            "confidence": round(confidence, 4),
            "flow_id": job.flow_id,
            "flow_key": job.flow_key_repr,
            "top_probabilities": {
                k: round(v, 4)
                for k, v in sorted(probs.items(), key=lambda item: item[1], reverse=True)[:3]
            },
        }

        # Advisory severity (never CRITICAL)
        sev = Severity.HIGH if confidence >= 0.95 else Severity.MEDIUM

        return IDSAlert.create(
            alert_id=self._next_alert_id(),
            timestamp=job.timestamp,
            source_ip=job.source_ip,
            destination_ip=job.destination_ip,
            source_port=job.source_port,
            destination_port=job.destination_port,
            protocol=job.protocol,
            category=DetectionCategory.ML_CLASSIFICATION,
            severity=sev,
            matched_rule=f"ML-RF-{pred_class.upper().replace(' ', '_')}",
            evidence=json.dumps(evidence_dict),
            recommended_action=DecisionAction.ALERT,  # Strictly advisory
        )

    def _create_if_alert(self, job: MLInferenceJob, anomaly_score: float) -> IDSAlert:
        """Creates a structured IDSAlert for Isolation Forest anomaly detection."""
        evidence_dict = {
            "model": "IsolationForest",
            "model_version": self.if_model.model_version if self.if_model else "1.0.0",
            "anomaly_score": round(anomaly_score, 4),
            "flow_id": job.flow_id,
            "flow_key": job.flow_key_repr,
        }

        return IDSAlert.create(
            alert_id=self._next_alert_id(),
            timestamp=job.timestamp,
            source_ip=job.source_ip,
            destination_ip=job.destination_ip,
            source_port=job.source_port,
            destination_port=job.destination_port,
            protocol=job.protocol,
            category=DetectionCategory.ML_ANOMALY,
            severity=Severity.LOW,  # Always low advisory severity
            matched_rule="ML-IF-FLOW_ANOMALY",
            evidence=json.dumps(evidence_dict),
            recommended_action=DecisionAction.ALERT,  # Strictly advisory
        )

    def _dispatch_alert(self, alert: IDSAlert) -> None:
        """Delivers alert to registered callback."""
        if self.on_alert_generated:
            try:
                self.on_alert_generated(alert)
            except Exception as e:
                logger.error(f"Error in ML on_alert_generated callback: {e}")
