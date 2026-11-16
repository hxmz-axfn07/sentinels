from __future__ import annotations

import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal
from uuid import uuid4

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.analysis import Analysis
from app.models.anomaly import AnomalyModel, AnomalyResult
from app.models.flow import NetworkFlow
from app.services.ml.artifacts import load_model_artifact, save_model_artifact
from app.services.ml.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FlowFeaturePreprocessor

MIN_TRAINING_SAMPLES = 20
FLOW_BATCH_SIZE = 500
ALGORITHM_NAME = "IsolationForest"
PREPROCESSING_CONFIG = {
    "missing_values": "per-feature training median plus a missingness indicator",
    "all_missing_features": "median value is 0 and the indicator is retained if it varies",
    "skewed_values": "log1p",
    "constant_dimensions": "removed after imputation and transformation",
    "scaling": "none; Isolation Forest uses feature-wise random tree splits",
}


@dataclass(frozen=True, slots=True)
class TrainingData:
    rows: np.ndarray
    sample_count: int
    population_count: int


@dataclass(frozen=True, slots=True)
class InferenceSummary:
    result_count: int
    anomaly_count: int
    normal_count: int
    reused: bool


def collect_training_data(
    db: Session,
    analysis_ids: Sequence[int],
    sample_limit: int,
    random_seed: int,
) -> TrainingData:
    ordered_ids = sorted(set(analysis_ids))
    population_count = int(
        db.scalar(
            select(func.count(NetworkFlow.id)).where(NetworkFlow.analysis_id.in_(ordered_ids))
        )
        or 0
    )
    rng = random.Random(random_seed)
    reservoir: list[list[float]] = []
    seen = 0
    for analysis_id in ordered_ids:
        last_id = 0
        while True:
            rows = db.execute(
                select(NetworkFlow.id, *[getattr(NetworkFlow, name) for name in FEATURE_NAMES])
                .where(NetworkFlow.analysis_id == analysis_id, NetworkFlow.id > last_id)
                .order_by(NetworkFlow.id)
                .limit(FLOW_BATCH_SIZE)
            ).all()
            if not rows:
                break
            for row in rows:
                feature_values = [_to_float(value) for value in row[1:]]
                if seen < sample_limit:
                    reservoir.append(feature_values)
                else:
                    replacement = rng.randrange(seen + 1)
                    if replacement < sample_limit:
                        reservoir[replacement] = feature_values
                seen += 1
            last_id = rows[-1][0]
    return TrainingData(
        rows=np.asarray(reservoir, dtype=np.float64),
        sample_count=len(reservoir),
        population_count=population_count,
    )


def train_pipeline(
    rows: np.ndarray,
    *,
    n_estimators: int,
    contamination: float | Literal["auto"],
    max_samples: int | Literal["auto"],
    random_seed: int,
) -> tuple[Pipeline, tuple[str, ...]]:
    if rows.ndim != 2 or rows.shape[1] != len(FEATURE_NAMES):
        raise ValueError("Training data does not match the flow-v1 feature schema.")
    if rows.shape[0] < MIN_TRAINING_SAMPLES:
        raise ValueError(f"At least {MIN_TRAINING_SAMPLES} training flows are required.")
    if isinstance(max_samples, int) and max_samples > rows.shape[0]:
        raise ValueError("max_samples cannot exceed the number of selected training flows.")
    preprocessing = FlowFeaturePreprocessor()
    estimator = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples=max_samples,
        random_state=random_seed,
        n_jobs=1,
    )
    pipeline = Pipeline([("preprocessor", preprocessing), ("isolation_forest", estimator)])
    pipeline.fit(rows)
    return pipeline, preprocessing.active_feature_names_


def create_model_record(
    *,
    pipeline: Pipeline,
    active_feature_names: Sequence[str],
    training_analysis_ids: Sequence[int],
    training_sample_count: int,
    training_population_count: int,
    n_estimators: int,
    contamination: float | Literal["auto"],
    max_samples: int | Literal["auto"],
    random_seed: int,
    storage_dir: Path,
) -> tuple[AnomalyModel, str]:
    artifact_key = save_model_artifact(pipeline, storage_dir)
    now = datetime.now(UTC)
    model_version = str(uuid4())
    estimator = pipeline.named_steps["isolation_forest"]
    record = AnomalyModel(
        model_version=model_version,
        algorithm=ALGORITHM_NAME,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=list(FEATURE_NAMES),
        active_feature_names=list(active_feature_names),
        preprocessing_config=PREPROCESSING_CONFIG,
        isolation_forest_config={
            "n_estimators": n_estimators,
            "contamination": contamination,
            "max_samples": max_samples,
            "resolved_max_samples": estimator.max_samples_,
            "random_state": random_seed,
            "n_jobs": 1,
        },
        random_seed=random_seed,
        training_analysis_ids=list(sorted(set(training_analysis_ids))),
        training_sample_count=training_sample_count,
        training_population_count=training_population_count,
        sklearn_version=sklearn.__version__,
        artifact_key=artifact_key,
        status="ready",
        trained_at=now,
    )
    return record, artifact_key


def load_trained_pipeline(model: AnomalyModel, storage_dir: Path) -> Pipeline:
    if model.status != "ready":
        raise ValueError("The selected model is not ready for inference.")
    if model.feature_schema_version != FEATURE_SCHEMA_VERSION or model.feature_names != list(
        FEATURE_NAMES
    ):
        raise ValueError("The stored model feature schema is incompatible with this application.")
    if model.sklearn_version != sklearn.__version__:
        raise ValueError("The stored model requires a different scikit-learn version.")
    artifact = load_model_artifact(storage_dir, model.artifact_key)
    if not isinstance(artifact, Pipeline) or set(artifact.named_steps) != {
        "preprocessor",
        "isolation_forest",
    }:
        raise ValueError("The stored model artifact has an invalid application model structure.")
    if not isinstance(artifact.named_steps["preprocessor"], FlowFeaturePreprocessor):
        raise ValueError("The stored model preprocessor is not supported.")
    if not isinstance(artifact.named_steps["isolation_forest"], IsolationForest):
        raise ValueError("The stored estimator is not Isolation Forest.")
    return artifact


def count_existing_results(db: Session, analysis_id: int, model_id: int) -> int:
    return int(
        db.scalar(
            select(func.count(AnomalyResult.id)).where(
                AnomalyResult.analysis_id == analysis_id,
                AnomalyResult.model_id == model_id,
            )
        )
        or 0
    )


def run_inference(
    db: Session,
    *,
    analysis_id: int,
    model: AnomalyModel,
    pipeline: Pipeline,
) -> InferenceSummary:
    estimator = pipeline.named_steps["isolation_forest"]
    preprocessor = pipeline.named_steps["preprocessor"]
    result_count = anomaly_count = normal_count = 0
    last_id = 0
    while True:
        columns = [getattr(NetworkFlow, name) for name in FEATURE_NAMES]
        rows = db.execute(
            select(NetworkFlow.id, NetworkFlow.flow_id, *columns)
            .where(NetworkFlow.analysis_id == analysis_id, NetworkFlow.id > last_id)
            .order_by(NetworkFlow.id)
            .limit(FLOW_BATCH_SIZE)
        ).all()
        if not rows:
            break
        matrix = np.asarray(
            [[_to_float(value) for value in row[2:]] for row in rows], dtype=np.float64
        )
        transformed = preprocessor.transform(matrix)
        predictions = estimator.predict(transformed)
        scores = -estimator.decision_function(transformed)
        pending = []
        for row, prediction, score in zip(rows, predictions, scores, strict=True):
            score_value = float(score)
            if not math.isfinite(score_value):
                raise ValueError("Isolation Forest produced a non-finite anomaly score.")
            label = "anomaly" if int(prediction) == -1 else "normal"
            pending.append(
                AnomalyResult(
                    model_id=model.id,
                    model_version=model.model_version,
                    analysis_id=analysis_id,
                    flow_id=row[1],
                    prediction=label,
                    anomaly_score=Decimal(str(score_value)),
                )
            )
            anomaly_count += label == "anomaly"
            normal_count += label == "normal"
        db.add_all(pending)
        db.flush()
        result_count += len(pending)
        last_id = rows[-1][0]
    if result_count == 0:
        raise ValueError("The selected analysis has no persisted flows to score.")
    return InferenceSummary(result_count, anomaly_count, normal_count, reused=False)


def validate_training_analyses(db: Session, analysis_ids: Sequence[int]) -> None:
    analyses = db.scalars(select(Analysis).where(Analysis.id.in_(set(analysis_ids)))).all()
    found = {analysis.id: analysis for analysis in analyses}
    missing = sorted(set(analysis_ids) - found.keys())
    if missing:
        raise LookupError(f"Training analysis not found: {missing[0]}.")
    incomplete = sorted(
        analysis_id
        for analysis_id, analysis in found.items()
        if analysis.status != "completed" or analysis.flow_generation_status != "completed"
    )
    if incomplete:
        raise RuntimeError(f"Training analysis {incomplete[0]} is not ready with generated flows.")


def _to_float(value: object) -> float:
    if value is None:
        return float("nan")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Flow metadata contains an infinite feature value.")
    return result
