# Model Evaluation Report: RandomForest

## Metadata & Parameters
- **n_estimators**: 100
- **max_depth**: 20
- **class_weight**: balanced
- **random_state**: 42
- **train_rows**: 28060
- **train_duration_seconds**: 0.593
- **classes_trained**: [np.str_('BENIGN'), np.str_('Bot'), np.str_('Brute Force'), np.str_('DDoS'), np.str_('DoS'), np.str_('Heartbleed'), np.str_('Infiltration'), np.str_('PortScan'), np.str_('Web Attack')]
- **feature_count**: 40

## Evaluation Performance
- **Total Test Samples**: 8018
- **Accuracy**: 0.9860
- **Macro Precision / Recall / F1**: 0.9749 / 0.9793 / 0.9757
- **Weighted Precision / Recall / F1**: 0.9875 / 0.9860 / 0.9864

### Per-Class Metrics
| Class | Support | Precision | Recall | F1 |
| :--- | :--- | :--- | :--- | :--- |
| BENIGN | 4801 | 0.9981 | 0.9794 | 0.9886 |
| Bot | 390 | 0.8534 | 1.0000 | 0.9209 |
| Brute Force | 600 | 1.0000 | 1.0000 | 1.0000 |
| DDoS | 600 | 0.9983 | 0.9983 | 0.9983 |
| DoS | 600 | 0.9933 | 0.9917 | 0.9925 |
| Heartbleed | 2 | 1.0000 | 1.0000 | 1.0000 |
| Infiltration | 7 | 1.0000 | 0.8571 | 0.9231 |
| PortScan | 600 | 0.9983 | 0.9967 | 0.9975 |
| Web Attack | 418 | 0.9324 | 0.9904 | 0.9606 |

### Confusion Matrix
Classes: [np.str_('BENIGN'), np.str_('Bot'), np.str_('Brute Force'), np.str_('DDoS'), np.str_('DoS'), np.str_('Heartbleed'), np.str_('Infiltration'), np.str_('PortScan'), np.str_('Web Attack')]
```json
[
  [
    4702,
    67,
    0,
    1,
    3,
    0,
    0,
    1,
    27
  ],
  [
    0,
    390,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  ],
  [
    0,
    0,
    600,
    0,
    0,
    0,
    0,
    0,
    0
  ],
  [
    1,
    0,
    0,
    599,
    0,
    0,
    0,
    0,
    0
  ],
  [
    4,
    0,
    0,
    0,
    595,
    0,
    0,
    0,
    1
  ],
  [
    0,
    0,
    0,
    0,
    0,
    2,
    0,
    0,
    0
  ],
  [
    1,
    0,
    0,
    0,
    0,
    0,
    6,
    0,
    0
  ],
  [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    598,
    2
  ],
  [
    3,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
    414
  ]
]
```

> [!NOTE]
> Benchmark-dataset performance (e.g. CIC-IDS2017) does not guarantee equivalent real-world
> network performance due to operational base-rate fallacies, evolving attacks, and zero-day variability.