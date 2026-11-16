from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

HybridSeverity = Literal["informational", "low", "medium", "high", "critical"]
CorrelationLevel = Literal["exact_flow", "endpoint_pair", "rule_only", "ml_only", "flow_only"]
EvidenceSource = Literal["rule", "ml"]


class HybridAssessmentRequest(BaseModel):
    detection_run_id: int = Field(ge=1)
    model_id: int = Field(ge=1)


class HybridAssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analysis_id: int
    detection_run_id: int
    model_id: int
    model_version: str
    scoring_config_version: str
    scoring_config_hash: str
    scoring_config: dict[str, Any]
    risk_score: Decimal
    severity: HybridSeverity
    rule_evidence_count: int
    ml_anomaly_count: int
    correlated_evidence_count: int
    risk_group_count: int
    explanation: str
    created_at: datetime
    reused: bool = False


class HybridAssessmentList(BaseModel):
    items: list[HybridAssessmentRead]
    total: int
    offset: int
    limit: int


class HybridSummary(BaseModel):
    analysis_id: int
    status: Literal["not_started", "completed"]
    assessment: HybridAssessmentRead | None


class HybridRiskGroupRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    analysis_id: int
    group_key: str
    correlation_level: CorrelationLevel
    endpoint_a_ip: str | None
    endpoint_b_ip: str | None
    protocol_name: str | None
    risk_score: Decimal
    rule_component: Decimal
    ml_component: Decimal
    exact_flow_bonus: Decimal
    severity: HybridSeverity
    rule_evidence_count: int
    ml_anomaly_count: int
    correlated_flow_count: int
    explanation: str
    created_at: datetime


class HybridRiskGroupList(BaseModel):
    items: list[HybridRiskGroupRead]
    total: int
    offset: int
    limit: int
    assessment_id: int


class HybridEvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    group_id: int
    assessment_id: int
    analysis_id: int
    source: EvidenceSource
    source_id: int
    detection_finding_id: int | None
    anomaly_result_id: int | None
    detection_run_id: int
    model_id: int
    model_version: str
    flow_id: str | None
    rule_id: str | None
    rule_name: str | None
    original_severity: str | None
    prediction: str | None
    anomaly_score: Decimal | None
    evidence: dict[str, Any]
    created_at: datetime


class HybridEvidenceList(BaseModel):
    items: list[HybridEvidenceRead]
    total: int
    offset: int
    limit: int
    group_id: int
