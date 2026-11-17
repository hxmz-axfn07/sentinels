from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EvaluationCreate(BaseModel):
    random_seed: int = Field(default=1101, ge=0, le=2_147_483_647)
    repeat_count: int = Field(default=3, ge=1, le=5)


class EvaluationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    dataset_version: str
    random_seed: int
    repeat_count: int
    status: Literal["running", "completed", "failed"]
    failure_summary: str | None
    results: dict[str, Any] | None
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime


class EvaluationRunSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    dataset_version: str
    random_seed: int
    repeat_count: int
    status: Literal["running", "completed", "failed"]
    failure_summary: str | None
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime


class EvaluationRunList(BaseModel):
    items: list[EvaluationRunSummary]
    total: int
    offset: int
    limit: int
