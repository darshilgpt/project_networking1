"""Runtime ML configuration options, telemetry metrics, and data contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Any, Dict, Optional


@dataclass
class MLRuntimeConfig:
    """Configuration options for runtime ML inference integration."""
    enabled: bool = True
    random_forest_enabled: bool = True
    isolation_forest_enabled: bool = True
    rf_confidence_threshold: float = 0.85
    artifacts_dir: str = "ml/artifacts"
    queue_capacity: int = 1000
    num_workers: int = 2
    # Flow maturity criteria
    min_packets_for_inference: int = 5
    min_duration_for_inference: float = 0.05  # 50 ms


@dataclass
class MLTelemetryMetrics:
    """Thread-safe telemetry metrics for ML runtime pipeline."""
    jobs_submitted: int = 0
    jobs_processed: int = 0
    queue_drops: int = 0
    inference_failures: int = 0
    rf_classifications: int = 0
    if_anomalies: int = 0
    total_inference_latency_ms: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_job_submitted(self) -> None:
        with self._lock:
            self.jobs_submitted += 1

    def record_queue_drop(self) -> None:
        with self._lock:
            self.queue_drops += 1

    def record_job_processed(self, latency_ms: float) -> None:
        with self._lock:
            self.jobs_processed += 1
            self.total_inference_latency_ms += latency_ms

    def record_inference_failure(self) -> None:
        with self._lock:
            self.inference_failures += 1

    def record_rf_classification(self) -> None:
        with self._lock:
            self.rf_classifications += 1

    def record_if_anomaly(self) -> None:
        with self._lock:
            self.if_anomalies += 1

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            avg_lat = (
                self.total_inference_latency_ms / max(self.jobs_processed, 1)
                if self.jobs_processed > 0
                else 0.0
            )
            return {
                "jobs_submitted": self.jobs_submitted,
                "jobs_processed": self.jobs_processed,
                "queue_drops": self.queue_drops,
                "inference_failures": self.inference_failures,
                "rf_classifications": self.rf_classifications,
                "if_anomalies": self.if_anomalies,
                "avg_inference_latency_ms": round(avg_lat, 3),
            }


@dataclass
class MLInferenceJob:
    """Asynchronous inference work item."""
    flow_id: int
    flow_key_repr: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    features_vector: Any  # np.ndarray of 40 features
    timestamp: float

