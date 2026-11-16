from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.hybrid import HybridSeverity

PipelineStageName = Literal["flows", "detection", "inference", "hybrid"]
PipelineStatus = Literal["running", "completed", "failed"]
StageStatus = Literal["pending", "running", "completed", "skipped", "failed"]


class PipelineRunRequest(BaseModel):
    stages: list[PipelineStageName] = Field(min_length=1, max_length=4)
    model_id: int | None = Field(default=None, ge=1)
    detection_run_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_selections(self) -> "PipelineRunRequest":
        if len(self.stages) != len(set(self.stages)):
            raise ValueError("stages must not contain duplicates")
        needs_model = "inference" in self.stages or "hybrid" in self.stages
        if needs_model != (self.model_id is not None):
            raise ValueError("model_id is required only when inference or hybrid is requested")
        needs_selected_run = "hybrid" in self.stages and "detection" not in self.stages
        if needs_selected_run != (self.detection_run_id is not None):
            raise ValueError(
                "detection_run_id is required for hybrid unless detection is requested; "
                "omit it when detection is requested"
            )
        return self


class PipelineStageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: int
    analysis_id: int
    stage: PipelineStageName
    execution_order: int
    requested: bool
    status: StageStatus
    reused: bool
    result_summary: dict[str, Any] | None
    error_summary: str | None
    started_at: datetime | None
    completed_at: datetime | None


class PipelineRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analysis_id: int
    pipeline_version: str
    requested_stages: list[PipelineStageName]
    model_id: int | None
    model_version: str | None
    detection_run_id: int | None
    hybrid_assessment_id: int | None
    status: PipelineStatus
    failure_summary: str | None
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime
    stages: list[PipelineStageRead]
    risk_score: Decimal | None = None
    severity: HybridSeverity | None = None
    reused_run: bool = False


class PipelineRunList(BaseModel):
    items: list[PipelineRunRead]
    total: int
    offset: int
    limit: int


class PipelineSummary(BaseModel):
    analysis_id: int
    status: Literal["not_started", "running", "completed", "failed"]
    latest_run: PipelineRunRead | None
