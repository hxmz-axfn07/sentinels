from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IncidentStatus = Literal["open", "acknowledged", "investigating", "resolved", "closed"]
IncidentPriority = Literal["low", "medium", "high", "critical"]
IncidentEvidenceType = Literal["rule_finding", "ml_anomaly", "hybrid_assessment"]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    priority: IncidentPriority = "medium"
    event_ids: list[str] = Field(default_factory=list, max_length=100)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    priority: IncidentPriority | None = None


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    resolution_summary: str | None = Field(default=None, max_length=10000)


class IncidentEvidenceAttach(BaseModel):
    event_ids: list[str] = Field(min_length=1, max_length=100)


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


class IncidentNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    body: str
    created_by: str | None
    created_at: datetime


class IncidentHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action: str
    details: dict[str, Any]
    actor: str | None
    created_at: datetime


class IncidentEvidenceRead(BaseModel):
    id: int
    source_type: IncidentEvidenceType
    source_id: int
    event_id: str
    analysis_id: int
    original_filename: str
    severity: str | None
    anomaly_score: str | None
    risk_score: str | None
    source_ip: str | None
    destination_ip: str | None
    protocol: str | None
    explanation: str
    flow_ids: list[str]
    model_id: int | None
    model_version: str | None
    evidence: dict[str, Any]
    attached_at: datetime


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: str
    status: IncidentStatus
    priority: IncidentPriority
    created_by: str | None
    assigned_to: str | None
    resolution_summary: str | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    evidence_count: int
    analysis_ids: list[int]


class IncidentDetail(IncidentRead):
    evidence: list[IncidentEvidenceRead]
    notes: list[IncidentNoteRead]
    history: list[IncidentHistoryRead]
    local_single_user: bool = True


class IncidentList(BaseModel):
    items: list[IncidentRead]
    total: int
    offset: int
    limit: int


class IncidentSummary(BaseModel):
    total: int
    status_counts: dict[str, int]
    priority_counts: dict[str, int]
