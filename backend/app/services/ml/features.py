from __future__ import annotations

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.utils.validation import check_is_fitted

FEATURE_SCHEMA_VERSION = "flow-v1"
FEATURE_NAMES = (
    "duration_seconds",
    "total_packets",
    "total_bytes",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "packet_length_min",
    "packet_length_max",
    "packet_length_mean",
    "packet_length_stddev",
    "interarrival_min",
    "interarrival_max",
    "interarrival_mean",
    "interarrival_stddev",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    "packets_per_second",
    "bytes_per_second",
)


class FlowFeaturePreprocessor(BaseEstimator, TransformerMixin):
    """Impute null metrics, log-compress values, and discard constant dimensions."""

    def fit(self, X: np.ndarray, y: object = None) -> FlowFeaturePreprocessor:
        values = _validated_matrix(X)
        if values.shape[1] != len(FEATURE_NAMES):
            raise ValueError("Flow feature count does not match the flow-v1 schema.")
        medians = []
        for column in values.T:
            present = column[~np.isnan(column)]
            medians.append(float(np.median(present)) if present.size else 0.0)
        self.n_features_in_ = len(FEATURE_NAMES)
        self.medians_ = np.asarray(medians, dtype=np.float64)
        expanded = self._expand(values)
        self.active_dimensions_ = np.ptp(expanded, axis=0) > 0
        if not self.active_dimensions_.any():
            raise ValueError("Training flows have no varying feature information.")
        self.active_feature_names_ = tuple(
            name
            for name, active in zip(self._expanded_names(), self.active_dimensions_, strict=True)
            if active
        )
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        check_is_fitted(self, ("medians_", "active_dimensions_"))
        values = _validated_matrix(X)
        if values.shape[1] != self.n_features_in_:
            raise ValueError("Flow feature count does not match the trained model schema.")
        return self._expand(values)[:, self.active_dimensions_]

    def _expand(self, values: np.ndarray) -> np.ndarray:
        missing = np.isnan(values)
        imputed = np.where(missing, self.medians_, values)
        transformed = np.log1p(imputed)
        expanded = np.concatenate((transformed, missing.astype(np.float64)), axis=1)
        if not np.isfinite(expanded).all():
            raise ValueError("Preprocessing produced a non-finite feature value.")
        return expanded

    @staticmethod
    def _expanded_names() -> tuple[str, ...]:
        return tuple(f"log1p:{name}" for name in FEATURE_NAMES) + tuple(
            f"missing:{name}" for name in FEATURE_NAMES
        )


def _validated_matrix(values: np.ndarray) -> np.ndarray:
    matrix = np.asarray(values, dtype=np.float64)
    if matrix.ndim != 2:
        raise ValueError("Flow features must be a two-dimensional matrix.")
    if np.isinf(matrix).any():
        raise ValueError("Infinite flow features are not supported.")
    present = matrix[~np.isnan(matrix)]
    if (present < 0).any():
        raise ValueError("Flow features must be nonnegative.")
    return matrix
