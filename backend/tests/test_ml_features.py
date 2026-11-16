import numpy as np
import pytest

from app.services.ml.engine import MIN_TRAINING_SAMPLES, train_pipeline
from app.services.ml.features import FEATURE_NAMES, FlowFeaturePreprocessor


def rows(count: int = 24) -> np.ndarray:
    values = np.zeros((count, len(FEATURE_NAMES)), dtype=np.float64)
    values[:, FEATURE_NAMES.index("total_packets")] = np.arange(count)
    values[:, FEATURE_NAMES.index("total_bytes")] = np.arange(count) * 64
    values[:, FEATURE_NAMES.index("duration_seconds")] = np.arange(count) / 10
    values[:, FEATURE_NAMES.index("interarrival_mean")] = np.nan
    return values


def test_preprocessor_keeps_fixed_feature_order_imputes_missing_and_drops_constants() -> None:
    training = rows()
    preprocessor = FlowFeaturePreprocessor().fit(training)
    transformed = preprocessor.transform(training)

    assert transformed.shape[0] == 24
    assert transformed.shape[1] == len(preprocessor.active_feature_names_)
    assert "log1p:total_packets" in preprocessor.active_feature_names_
    assert "missing:interarrival_mean" not in preprocessor.active_feature_names_
    assert np.isfinite(transformed).all()
    assert preprocessor.transform(training[:3]).tolist() == transformed[:3].tolist()


def test_preprocessor_retains_a_variable_missingness_indicator() -> None:
    training = rows()
    index = FEATURE_NAMES.index("interarrival_mean")
    training[0, index] = 0.5
    preprocessor = FlowFeaturePreprocessor().fit(training)

    assert f"missing:{FEATURE_NAMES[index]}" in preprocessor.active_feature_names_
    assert np.isfinite(preprocessor.transform(training)).all()


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda values: values.__setitem__((0, 0), np.inf), "Infinite"),
        (lambda values: values.__setitem__((0, 0), -1), "nonnegative"),
    ],
)
def test_preprocessor_rejects_invalid_values(mutate, message: str) -> None:
    training = rows()
    mutate(training)

    with pytest.raises(ValueError, match=message):
        FlowFeaturePreprocessor().fit(training)


def test_preprocessor_rejects_schema_mismatch_and_all_constant_data() -> None:
    preprocessor = FlowFeaturePreprocessor()
    with pytest.raises(ValueError, match="feature count"):
        preprocessor.fit(np.zeros((MIN_TRAINING_SAMPLES, len(FEATURE_NAMES) - 1)))
    with pytest.raises(ValueError, match="no varying feature"):
        preprocessor.fit(np.zeros((MIN_TRAINING_SAMPLES, len(FEATURE_NAMES))))


def test_training_is_reproducible_and_scores_are_finite() -> None:
    training = rows()
    options = {
        "n_estimators": 50,
        "contamination": 0.1,
        "max_samples": "auto",
        "random_seed": 42,
    }
    first, _ = train_pipeline(training, **options)
    second, _ = train_pipeline(training, **options)
    first_preprocessor = first.named_steps["preprocessor"]
    first_estimator = first.named_steps["isolation_forest"]
    second_preprocessor = second.named_steps["preprocessor"]
    second_estimator = second.named_steps["isolation_forest"]

    features = first_preprocessor.transform(training)
    scores = -first_estimator.decision_function(features)
    assert np.array_equal(
        first_estimator.predict(features),
        second_estimator.predict(second_preprocessor.transform(training)),
    )
    assert np.isfinite(scores).all()


def test_synthetic_outlier_has_anomaly_label_and_higher_relative_score() -> None:
    training = np.zeros((100, len(FEATURE_NAMES)), dtype=np.float64)
    packet_index = FEATURE_NAMES.index("total_packets")
    byte_index = FEATURE_NAMES.index("total_bytes")
    duration_index = FEATURE_NAMES.index("duration_seconds")
    training[:, packet_index] = np.arange(100)
    training[:, byte_index] = training[:, packet_index] * 64
    training[:, duration_index] = np.linspace(1, 2, 100)
    fixtures = np.zeros((2, len(FEATURE_NAMES)), dtype=np.float64)
    fixtures[:, packet_index] = [50, 100_000]
    fixtures[:, byte_index] = fixtures[:, packet_index] * 64
    fixtures[:, duration_index] = [1.5, 1_000]
    pipeline, _ = train_pipeline(
        training,
        n_estimators=200,
        contamination=0.05,
        max_samples="auto",
        random_seed=42,
    )
    preprocessor = pipeline.named_steps["preprocessor"]
    estimator = pipeline.named_steps["isolation_forest"]
    transformed = preprocessor.transform(fixtures)
    labels = estimator.predict(transformed)
    scores = -estimator.decision_function(transformed)

    assert labels.tolist() == [1, -1]
    assert scores[1] > scores[0]
    assert np.isfinite(scores).all()


def test_training_rejects_insufficient_rows_and_invalid_max_samples() -> None:
    with pytest.raises(ValueError, match="At least"):
        train_pipeline(
            rows(MIN_TRAINING_SAMPLES - 1),
            n_estimators=50,
            contamination="auto",
            max_samples="auto",
            random_seed=42,
        )
    with pytest.raises(ValueError, match="max_samples"):
        train_pipeline(
            rows(),
            n_estimators=50,
            contamination="auto",
            max_samples=25,
            random_seed=42,
        )
