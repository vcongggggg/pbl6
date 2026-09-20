"""Model Evaluation, Metrics Profiling, and Scientific Reporting.

Implements Task 5.2 (Issue #23) for the PBL6 Machine Learning Defense Engine.
Computes Confusion Matrices, Per-Class F1, ROC-AUC, Latency Overhead,
and generates formatted benchmark reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

CANONICAL_CLASSES: list[str] = [
    "BENIGN",
    "SQLI",
    "XSS",
    "PATH_TRAVERSAL",
    "COMMAND_INJECTION",
]


def evaluate_classifier(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    classes: list[str] = CANONICAL_CLASSES,
) -> dict[str, Any]:
    """Evaluates classifier performance across standard metrics."""
    y_pred = model.predict(X_test)
    proba = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None

    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1_mac = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    f1_wt = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    cm = confusion_matrix(y_test, y_pred, labels=classes)
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    tn = cm[benign_idx, benign_idx]
    fp = cm[benign_idx, :].sum() - tn
    fpr_benign = float(fp / max(1, (fp + tn)))
    youden_j = float(rec_macro - fpr_benign)

    roc_auc_macro = None
    if proba is not None and len(np.unique(y_test)) == len(classes):
        try:
            roc_auc_macro = float(roc_auc_score(y_test, proba, multi_class="ovr", average="macro"))
        except Exception:
            roc_auc_macro = None

    class_rep = classification_report(y_test, y_pred, labels=classes, output_dict=True, zero_division=0)

    return {
        "accuracy": round(acc, 4),
        "precision_macro": round(prec_macro, 4),
        "recall_macro": round(rec_macro, 4),
        "f1_macro": round(f1_mac, 4),
        "f1_weighted": round(f1_wt, 4),
        "fpr_benign": round(fpr_benign, 4),
        "youden_index_j": round(youden_j, 4),
        "roc_auc_macro": round(roc_auc_macro, 4) if roc_auc_macro is not None else None,
        "confusion_matrix": cm.tolist(),
        "classification_report": class_rep,
    }


def save_evaluation_json(metrics: dict[str, Any], output_path: str | Path) -> Path:
    """Saves evaluation metrics dictionary as JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    return path
