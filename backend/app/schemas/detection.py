from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

DetectionSeverity = Literal["low", "medium", "high", "critical"]
DetectionStatus = Literal["not_started", "processing", "completed", "failed"]


class DetectionRunRead(BaseModel):
    id: int
    analysis_id: int
    config_hash: str
    status: Literal["processing", "completed", "failed"]
    finding_count: int
    error_message: str | None
    created_at: datetime
    completed_at: datetime | None
    reused: bool = False


class FlowReference(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    flow_id: str
    protocol_name: str
    endpoint_a_ip: str | None
    endpoint_a_port: int | None
    endpoint_b_ip: str | None
    endpoint_b_port: int | None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    run_id: int
    analysis_id: int
    rule_id: str
    rule_name: str
    severity: DetectionSeverity
    source_ip: str | None
    destination_ip: str | None
    protocol_name: str | None
    explanation: str
    evidence: dict[str, Any]
    supporting_flow_count: int
    supporting_flow_sample_truncated: bool
    created_at: datetime
    supporting_flows: list[FlowReference]


class FindingList(BaseModel):
    items: list[FindingRead]
    total: int
    offset: int
    limit: int
    run_id: int | None


class RuleFindingCount(BaseModel):
    rule_id: str
    count: int


class DetectionSummary(BaseModel):
    analysis_id: int
    run_id: int | None
    status: DetectionStatus
    finding_count: int
    severity_counts: dict[DetectionSeverity, int]
    rule_counts: list[RuleFindingCount]
    config_hash: str | None
    error_message: str | None
    created_at: datetime | None
    completed_at: datetime | None
