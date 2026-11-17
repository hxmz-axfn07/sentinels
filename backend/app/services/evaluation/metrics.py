from collections.abc import Sequence


def binary_metrics(
    actual_positive: Sequence[bool], predicted_positive: Sequence[bool]
) -> dict[str, int | float | list[list[int]] | None]:
    """Calculate capture-level binary metrics, preserving undefined denominators as null."""
    if len(actual_positive) != len(predicted_positive):
        raise ValueError("Actual and predicted label counts must match.")

    tp = fp = tn = fn = 0
    for actual, predicted in zip(actual_positive, predicted_positive, strict=True):
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif not actual and not predicted:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is None or recall is None:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else None

    return {
        "sample_count": len(actual_positive),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": false_positive_rate,
    }
