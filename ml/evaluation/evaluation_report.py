"""Evaluation report generation for machine-learning intrusion detection models."""

from __future__ import annotations

import json
import os
from typing import Any, Dict
from ml.evaluation.metrics import AnomalyEvaluationMetrics, ClassificationEvaluationMetrics


def save_evaluation_report(
    metrics: AnomalyEvaluationMetrics | ClassificationEvaluationMetrics,
    filepath_json: str,
    filepath_txt: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Saves structured metrics to a machine-readable JSON file and readable text summary."""
    data = metrics.to_dict()
    if extra_metadata:
        data["metadata"] = extra_metadata

    os.makedirs(os.path.dirname(filepath_json), exist_ok=True)
    with open(filepath_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    if filepath_txt:
        os.makedirs(os.path.dirname(filepath_txt), exist_ok=True)
        with open(filepath_txt, "w", encoding="utf-8") as f:
            f.write(generate_text_summary(data))


def generate_text_summary(data: Dict[str, Any]) -> str:
    """Formats metrics dictionary into a readable markdown report."""
    lines = []
    model_name = data.get("model_name", "Model")
    lines.append(f"# Model Evaluation Report: {model_name}\n")

    meta = data.get("metadata", {})
    if meta:
        lines.append("## Metadata & Parameters")
        for k, v in meta.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")

    lines.append("## Evaluation Performance")
    if "contamination" in data:
        # Anomaly detector
        lines.append(f"- **Total Test Samples**: {data.get('total_samples')}")
        lines.append(f"- **Normal / Anomaly Samples**: {data.get('normal_samples')} / {data.get('anomaly_samples')}")
        lines.append(f"- **Contamination**: {data.get('contamination')}")
        lines.append(f"- **Accuracy**: {data.get('accuracy', 0):.4f}")
        lines.append(f"- **Precision**: {data.get('precision', 0):.4f}")
        lines.append(f"- **Recall**: {data.get('recall', 0):.4f}")
        lines.append(f"- **F1-Score**: {data.get('f1', 0):.4f}")
        lines.append(f"- **False Positive Rate**: {data.get('false_positive_rate', 0):.4f}")
        lines.append(f"- **ROC-AUC**: {data.get('roc_auc')}")
        lines.append(f"- **PR-AUC**: {data.get('pr_auc')}")
        lines.append("")
        lines.append("### Confusion Matrix [ [TN, FP], [FN, TP] ]")
        cm = data.get("confusion_matrix", [])
        lines.append(f"```json\n{json.dumps(cm, indent=2)}\n```")
    else:
        # Multiclass classifier
        lines.append(f"- **Total Test Samples**: {data.get('total_samples')}")
        lines.append(f"- **Accuracy**: {data.get('accuracy', 0):.4f}")
        lines.append(f"- **Macro Precision / Recall / F1**: {data.get('macro_precision', 0):.4f} / {data.get('macro_recall', 0):.4f} / {data.get('macro_f1', 0):.4f}")
        lines.append(f"- **Weighted Precision / Recall / F1**: {data.get('weighted_precision', 0):.4f} / {data.get('weighted_recall', 0):.4f} / {data.get('weighted_f1', 0):.4f}")
        lines.append("")
        lines.append("### Per-Class Metrics")
        lines.append("| Class | Support | Precision | Recall | F1 |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for cls_name, vals in data.get("per_class_metrics", {}).items():
            lines.append(
                f"| {cls_name} | {vals.get('support')} | {vals.get('precision', 0):.4f} | {vals.get('recall', 0):.4f} | {vals.get('f1', 0):.4f} |"
            )
        lines.append("")
        lines.append("### Confusion Matrix")
        lines.append(f"Classes: {data.get('classes', [])}")
        cm = data.get("confusion_matrix", [])
        lines.append(f"```json\n{json.dumps(cm, indent=2)}\n```")

    lines.append("\n> [!NOTE]")
    lines.append("> Benchmark-dataset performance (e.g. CIC-IDS2017) does not guarantee equivalent real-world")
    lines.append("> network performance due to operational base-rate fallacies, evolving attacks, and zero-day variability.")

    return "\n".join(lines)

