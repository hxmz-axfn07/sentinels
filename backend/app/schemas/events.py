from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

EventType = Literal["rule_finding", "ml_anomaly", "hybrid_assessment"]


class SecurityEventRead(BaseModel):
    event_id: str
    event_type: EventType
    analysis_id: int
    original_filename: str
    recorded_at: datetime
    timestamp_label: Literal["finding recorded", "anomaly scored", "assessment created"]
    severity: str | None
    risk_score: str | None
    anomaly_score: str | None = None
    source_ip: str | None
    destination_ip: str | None
    protocol: str | None
    context_note: str | None = None
    explanation: str
    rule_id: str | None = None
    model_id: int | None = None
    model_version: str | None = None
    flow_id: str | None = None
    related_reference: str


class SecurityEventList(BaseModel):
    items: list[SecurityEventRead]
    total: int
    offset: int
    limit: int


class SecurityEventDetail(BaseModel):
    event: SecurityEventRead
    evidence: dict[str, Any]
    related_flow_ids: list[str]
