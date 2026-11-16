from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyResult
from app.models.detection import DetectionFinding, DetectionRun
from app.models.flow import NetworkFlow
from app.models.hybrid import HybridAssessment

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


class OverviewAnalysis(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    original_filename: str
    file_size_bytes: int
    capture_format: str
    status: str
    packet_count: int | None
    flow_count: int | None
    flow_generation_status: str
    created_at: datetime
    detection_status: Literal["not_started", "running", "completed", "failed"]
    finding_count: int
    ml_status: Literal["not_started", "completed"]
    anomaly_count: int
    hybrid_status: Literal["not_started", "completed"]
    risk_score: str | None
    severity: str | None


class OverviewFinding(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analysis_id: int
    rule_id: str
    rule_name: str
    severity: Literal["high", "critical"]
    source_ip: str | None
    destination_ip: str | None
    explanation: str
    created_at: datetime


class Overview(BaseModel):
    analysis_count: int
    completed_analysis_count: int
    packet_count: int
    flow_count: int
    rule_finding_count: int
    high_priority_finding_count: int
    rule_analysis_count: int
    ml_anomaly_count: int
    ml_analysis_count: int
    hybrid_assessment_count: int
    severity_counts: dict[str, int]
    protocol_distribution: list[dict[str, int | str]]
    recent_analyses: list[OverviewAnalysis]
    recent_high_priority_findings: list[OverviewFinding]


class AnalysisHistory(BaseModel):
    items: list[OverviewAnalysis]
    total: int
    offset: int
    limit: int


@router.get("/overview", response_model=Overview)
def get_overview(db: Session = Depends(get_db)) -> Overview:  # noqa: B008
    """Return current persisted totals using only each analysis's latest completed run."""
    analysis_count = db.scalar(select(func.count(Analysis.id))) or 0
    completed_analysis_count = (
        db.scalar(select(func.count(Analysis.id)).where(Analysis.status == "completed")) or 0
    )
    packet_count = (
        db.scalar(
            select(func.coalesce(func.sum(Analysis.packet_count), 0)).where(
                Analysis.status == "completed"
            )
        )
        or 0
    )
    flow_count = (
        db.scalar(
            select(func.coalesce(func.sum(Analysis.flow_count), 0)).where(
                Analysis.status == "completed", Analysis.flow_generation_status == "completed"
            )
        )
        or 0
    )

    latest_detection = (
        select(func.max(DetectionRun.id).label("run_id"))
        .where(DetectionRun.status == "completed")
        .group_by(DetectionRun.analysis_id)
        .subquery()
    )
    finding_rows = db.execute(
        select(DetectionFinding.severity, func.count(DetectionFinding.id))
        .join(latest_detection, DetectionFinding.run_id == latest_detection.c.run_id)
        .group_by(DetectionFinding.severity)
    ).all()
    finding_counts = {str(severity): int(count) for severity, count in finding_rows}
    rule_finding_count = sum(finding_counts.values())
    high_priority_finding_count = sum(
        finding_counts.get(severity, 0) for severity in ("high", "critical")
    )
    rule_analysis_count = db.scalar(select(func.count()).select_from(latest_detection)) or 0
    recent_high_priority_findings = db.scalars(
        select(DetectionFinding)
        .join(latest_detection, DetectionFinding.run_id == latest_detection.c.run_id)
        .where(DetectionFinding.severity.in_(("high", "critical")))
        .order_by(DetectionFinding.created_at.desc(), DetectionFinding.id.desc())
        .limit(8)
    ).all()

    latest_ml_result = (
        select(func.max(AnomalyResult.id).label("result_id"))
        .group_by(AnomalyResult.analysis_id)
        .subquery()
    )
    latest_model = (
        select(AnomalyResult.analysis_id, AnomalyResult.model_id)
        .join(latest_ml_result, AnomalyResult.id == latest_ml_result.c.result_id)
        .subquery()
    )
    ml_anomaly_count = (
        db.scalar(
            select(func.count(AnomalyResult.id))
            .join(
                latest_model,
                (AnomalyResult.analysis_id == latest_model.c.analysis_id)
                & (AnomalyResult.model_id == latest_model.c.model_id),
            )
            .where(AnomalyResult.prediction == "anomaly")
        )
        or 0
    )
    ml_analysis_count = db.scalar(select(func.count()).select_from(latest_model)) or 0

    latest_assessment = (
        select(func.max(HybridAssessment.id).label("assessment_id"))
        .group_by(HybridAssessment.analysis_id)
        .subquery()
    )
    severity_counts = {name: 0 for name in ("informational", "low", "medium", "high", "critical")}
    hybrid_rows = db.execute(
        select(HybridAssessment.severity, func.count(HybridAssessment.id))
        .join(latest_assessment, HybridAssessment.id == latest_assessment.c.assessment_id)
        .group_by(HybridAssessment.severity)
    ).all()
    severity_counts.update({str(name): int(count) for name, count in hybrid_rows})

    protocol_rows = db.execute(
        select(NetworkFlow.protocol_name, func.count(NetworkFlow.id))
        .join(Analysis, Analysis.id == NetworkFlow.analysis_id)
        .where(Analysis.status == "completed", Analysis.flow_generation_status == "completed")
        .group_by(NetworkFlow.protocol_name)
        .order_by(func.count(NetworkFlow.id).desc(), NetworkFlow.protocol_name)
        .limit(8)
    ).all()

    recent = db.scalars(
        select(Analysis).order_by(Analysis.created_at.desc(), Analysis.id.desc()).limit(10)
    ).all()
    summaries = _summarize_analyses(db, recent)

    return Overview(
        analysis_count=analysis_count,
        completed_analysis_count=completed_analysis_count,
        packet_count=int(packet_count),
        flow_count=int(flow_count),
        rule_finding_count=rule_finding_count,
        high_priority_finding_count=high_priority_finding_count,
        rule_analysis_count=rule_analysis_count,
        ml_anomaly_count=int(ml_anomaly_count),
        ml_analysis_count=int(ml_analysis_count),
        hybrid_assessment_count=sum(severity_counts.values()),
        severity_counts=severity_counts,
        protocol_distribution=[
            {"protocol": protocol, "flow_count": int(count)} for protocol, count in protocol_rows
        ],
        recent_analyses=summaries,
        recent_high_priority_findings=recent_high_priority_findings,
    )


@router.get("/analyses", response_model=AnalysisHistory)
def get_analysis_history(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db),  # noqa: B008
) -> AnalysisHistory:
    """Return paginated analyses with latest persisted stage status."""
    total = db.scalar(select(func.count(Analysis.id))) or 0
    analyses = db.scalars(
        select(Analysis)
        .order_by(Analysis.created_at.desc(), Analysis.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return AnalysisHistory(
        items=_summarize_analyses(db, analyses), total=int(total), offset=offset, limit=limit
    )


def _summarize_analyses(db: Session, analyses: list[Analysis]) -> list[OverviewAnalysis]:
    ids = [analysis.id for analysis in analyses]
    detection_latest = {}
    ml_latest = {}
    risk_latest = {}
    anomaly_counts = {}
    if ids:
        latest_run_ids = (
            select(DetectionRun.analysis_id, func.max(DetectionRun.id).label("run_id"))
            .where(DetectionRun.analysis_id.in_(ids))
            .group_by(DetectionRun.analysis_id)
            .subquery()
        )
        run_rows = db.execute(
            select(DetectionRun.analysis_id, DetectionRun.status, DetectionRun.finding_count).join(
                latest_run_ids, DetectionRun.id == latest_run_ids.c.run_id
            )
        ).all()
        detection_latest = {analysis_id: (status, count) for analysis_id, status, count in run_rows}
        latest_result_ids = (
            select(AnomalyResult.analysis_id, func.max(AnomalyResult.id).label("result_id"))
            .where(AnomalyResult.analysis_id.in_(ids))
            .group_by(AnomalyResult.analysis_id)
            .subquery()
        )
        ml_rows = db.execute(
            select(AnomalyResult.analysis_id, AnomalyResult.id, AnomalyResult.model_id).join(
                latest_result_ids, AnomalyResult.id == latest_result_ids.c.result_id
            )
        ).all()
        ml_latest = {
            analysis_id: (model_id, result_id) for analysis_id, result_id, model_id in ml_rows
        }
        latest_assessment_ids = (
            select(
                HybridAssessment.analysis_id,
                func.max(HybridAssessment.id).label("assessment_id"),
            )
            .where(HybridAssessment.analysis_id.in_(ids))
            .group_by(HybridAssessment.analysis_id)
            .subquery()
        )
        risk_rows = db.scalars(
            select(HybridAssessment).join(
                latest_assessment_ids,
                HybridAssessment.id == latest_assessment_ids.c.assessment_id,
            )
        ).all()
        risk_latest = {item.analysis_id: item for item in risk_rows}
        selected_models = (
            select(AnomalyResult.analysis_id, AnomalyResult.model_id)
            .join(latest_result_ids, AnomalyResult.id == latest_result_ids.c.result_id)
            .subquery()
        )
        anomaly_rows = db.execute(
            select(AnomalyResult.analysis_id, func.count(AnomalyResult.id))
            .join(
                selected_models,
                (AnomalyResult.analysis_id == selected_models.c.analysis_id)
                & (AnomalyResult.model_id == selected_models.c.model_id),
            )
            .where(AnomalyResult.prediction == "anomaly")
            .group_by(AnomalyResult.analysis_id)
        ).all()
        anomaly_counts = {analysis_id: count for analysis_id, count in anomaly_rows}

    summaries = []
    for analysis in analyses:
        run_state = detection_latest.get(analysis.id)
        model_state = ml_latest.get(analysis.id)
        latest_risk = risk_latest.get(analysis.id)
        summaries.append(
            OverviewAnalysis(
                id=analysis.id,
                original_filename=analysis.original_filename,
                file_size_bytes=analysis.file_size_bytes,
                capture_format=analysis.capture_format,
                status=analysis.status,
                packet_count=analysis.packet_count if analysis.status == "completed" else None,
                flow_count=analysis.flow_count
                if analysis.flow_generation_status == "completed"
                else None,
                flow_generation_status=analysis.flow_generation_status,
                created_at=analysis.created_at,
                detection_status=run_state[0] if run_state else "not_started",
                finding_count=run_state[1] if run_state and run_state[0] == "completed" else 0,
                ml_status="completed" if model_state else "not_started",
                anomaly_count=anomaly_counts.get(analysis.id, 0),
                hybrid_status="completed" if latest_risk else "not_started",
                risk_score=str(latest_risk.risk_score) if latest_risk else None,
                severity=latest_risk.severity if latest_risk else None,
            )
        )
    return summaries
