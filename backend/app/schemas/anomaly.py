from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PredictionLabel = Literal["normal", "anomaly"]


class ModelTrainingRequest(BaseModel):
    analysis_ids: list[int] = Field(min_length=1, max_length=100)
    n_estimators: int = Field(default=200, ge=50, le=1_000)
    contamination: float | Literal["auto"] = "auto"
    max_samples: int | Literal["auto"] = "auto"
    random_seed: int = Field(default=42, ge=0, le=4_294_967_295)

    @field_validator("analysis_ids")
    @classmethod
    def require_distinct_analysis_ids(cls, values: list[int]) -> list[int]:
        if len(values) != len(set(values)):
            raise ValueError("analysis_ids must be unique")
        if any(value < 1 for value in values):
            raise ValueError("analysis IDs must be positive")
        return values

    @field_validator("contamination")
    @classmethod
    def validate_contamination(cls, value: float | str) -> float | str:
        if value != "auto" and (not 0 < value <= 0.5):
            raise ValueError("contamination must be 'auto' or a number in (0, 0.5]")
        return value

    @model_validator(mode="after")
    def validate_max_samples(self) -> ModelTrainingRequest:
        if isinstance(self.max_samples, int) and self.max_samples < 2:
            raise ValueError("max_samples must be at least 2 or 'auto'")
        return self


class ModelRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    model_version: str
    algorithm: str
    feature_schema_version: str
    feature_names: list[str]
    active_feature_names: list[str]
    preprocessing_config: dict[str, Any]
    isolation_forest_config: dict[str, Any]
    random_seed: int
    training_analysis_ids: list[int]
    training_sample_count: int
    training_population_count: int
    sklearn_version: str
    status: Literal["ready"]
    created_at: datetime
    trained_at: datetime


class ModelList(BaseModel):
    items: list[ModelRead]
    total: int
    offset: int
    limit: int


class InferenceRequest(BaseModel):
    model_id: int = Field(ge=1)


class InferenceRead(BaseModel):
    analysis_id: int
    model_id: int
    model_version: str
    result_count: int
    anomaly_count: int
    normal_count: int
    reused: bool


class FlowReference(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    flow_id: str
    protocol_name: str
    endpoint_a_ip: str | None
    endpoint_a_port: int | None
    endpoint_b_ip: str | None
    endpoint_b_port: int | None
    total_packets: int
    total_bytes: int
    duration_seconds: Decimal | None


class AnomalyResultRead(BaseModel):
    id: int
    model_id: int
    model_version: str
    analysis_id: int
    flow_id: str
    prediction: PredictionLabel
    anomaly_score: Decimal
    created_at: datetime
    flow: FlowReference


class AnomalyResultList(BaseModel):
    items: list[AnomalyResultRead]
    total: int
    offset: int
    limit: int
    model_id: int
    model_version: str


class AnomalySummary(BaseModel):
    analysis_id: int
    model_id: int | None
    model_version: str | None
    status: Literal["not_started", "completed"]
    result_count: int
    anomaly_count: int
    normal_count: int
