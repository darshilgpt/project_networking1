# Model Evaluation Report: IsolationForest

## Metadata & Parameters
- **n_estimators**: 100
- **contamination**: 0.05
- **max_samples**: auto
- **random_state**: 42
- **train_rows_benign**: 16799
- **train_rows_total**: 28060
- **train_duration_seconds**: 0.316
- **feature_count**: 40

## Evaluation Performance
- **Total Test Samples**: 8018
- **Normal / Anomaly Samples**: 4801 / 3217
- **Contamination**: 0.05
- **Accuracy**: 0.6453
- **Precision**: 0.7146
- **Recall**: 0.1930
- **F1-Score**: 0.3040
- **False Positive Rate**: 0.0517
- **ROC-AUC**: 0.6201384904722407
- **PR-AUC**: 0.5101532132739159

### Confusion Matrix [ [TN, FP], [FN, TP] ]
```json
[
  [
    4553,
    248
  ],
  [
    2596,
    621
  ]
]
```

> [!NOTE]
> Benchmark-dataset performance (e.g. CIC-IDS2017) does not guarantee equivalent real-world
> network performance due to operational base-rate fallacies, evolving attacks, and zero-day variability.