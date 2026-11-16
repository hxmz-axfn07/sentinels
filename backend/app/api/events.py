from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, func, literal, select, union_all
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyResult
from app.models.detection import DetectionFinding
from app.models.flow import NetworkFlow
from app.models.hybrid import HybridAssessment, HybridEvidence
from app.schemas.events import SecurityEventDetail, SecurityEventList, SecurityEventRead

router = APIRouter(prefix="/api/v1/events", tags=["security-events"])


@router.get("", response_model=SecurityEventList)
def list_security_events(
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
    severity: str | None = Query(None, pattern="^(informational|low|medium|high|critical)$"),
    event_type: Literal["rule_finding", "ml_anomaly", "hybrid_assessment"] | None = None,
    analysis_id: int | None = Query(None, ge=1),
    protocol: str | None = Query(None, min_length=1, max_length=32),
    recorded_after: datetime | None = None,
    recorded_before: datetime | None = None,
    db: Session = Depends(get_db),  # noqa: B008
) -> SecurityEventList:
    if recorded_after and recorded_before and recorded_after > recorded_before:
        raise HTTPException(
            status_code=422, detail="recorded_after must not exceed recorded_before."
        )

    parts = []
    if event_type in (None, "rule_finding"):
        parts.append(
            select(
                DetectionFinding.id.label("source_id"),
                literal("rule_finding").label("event_type"),
                DetectionFinding.analysis_id.label("analysis_id"),
                Analysis.original_filename.label("original_filename"),
                DetectionFinding.created_at.label("recorded_at"),
                literal("finding recorded").label("timestamp_label"),
                DetectionFinding.severity.label("severity"),
                literal(None, type_=String).label("risk_score"),
                DetectionFinding.source_ip.label("source_ip"),
                DetectionFinding.destination_ip.label("destination_ip"),
                DetectionFinding.protocol_name.label("protocol"),
                DetectionFinding.explanation.label("explanation"),
                DetectionFinding.rule_id.label("rule_id"),
                literal(None).label("model_id"),
                literal(None, type_=String).label("model_version"),
                literal(None, type_=String).label("flow_id"),
            ).join(Analysis, Analysis.id == DetectionFinding.analysis_id)
        )
    if event_type in (None, "ml_anomaly"):
        parts.append(
            select(
                AnomalyResult.id.label("source_id"),
                literal("ml_anomaly").label("event_type"),
                AnomalyResult.analysis_id.label("analysis_id"),
                Analysis.original_filename.label("original_filename"),
                AnomalyResult.created_at.label("recorded_at"),
                literal("anomaly scored").label("timestamp_label"),
                literal(None, type_=String).label("severity"),
                literal(None, type_=String).label("risk_score"),
                NetworkFlow.first_packet_source_ip.label("source_ip"),
                NetworkFlow.first_packet_destination_ip.label("destination_ip"),
                NetworkFlow.protocol_name.label("protocol"),
                literal("Flow marked anomalous relative to the selected model.").label(
                    "explanation"
                ),
                literal(None, type_=String).label("rule_id"),
                AnomalyResult.model_id.label("model_id"),
                AnomalyResult.model_version.label("model_version"),
                AnomalyResult.flow_id.label("flow_id"),
            )
            .join(Analysis, Analysis.id == AnomalyResult.analysis_id)
            .join(
                NetworkFlow,
                (NetworkFlow.analysis_id == AnomalyResult.analysis_id)
                & (NetworkFlow.flow_id == AnomalyResult.flow_id),
            )
            .where(AnomalyResult.prediction == "anomaly")
        )
    if event_type in (None, "hybrid_assessment"):
        parts.append(
            select(
                HybridAssessment.id.label("source_id"),
                literal("hybrid_assessment").label("event_type"),
                HybridAssessment.analysis_id.label("analysis_id"),
                Analysis.original_filename.label("original_filename"),
                HybridAssessment.created_at.label("recorded_at"),
                literal("assessment created").label("timestamp_label"),
                HybridAssessment.severity.label("severity"),
                cast(HybridAssessment.risk_score, String).label("risk_score"),
                literal(None, type_=String).label("source_ip"),
                literal(None, type_=String).label("destination_ip"),
                literal(None, type_=String).label("protocol"),
                HybridAssessment.explanation.label("explanation"),
                literal(None, type_=String).label("rule_id"),
                HybridAssessment.model_id.label("model_id"),
                HybridAssessment.model_version.label("model_version"),
                literal(None, type_=String).label("flow_id"),
            ).join(Analysis, Analysis.id == HybridAssessment.analysis_id)
        )

    events = union_all(*parts).subquery("security_events")
    query = select(events)
    if analysis_id is not None:
        query = query.where(events.c.analysis_id == analysis_id)
    if severity is not None:
        query = query.where(events.c.severity == severity)
    if protocol is not None:
        query = query.where(events.c.protocol == protocol.upper())
    if recorded_after is not None:
        query = query.where(events.c.recorded_at >= recorded_after)
    if recorded_before is not None:
        query = query.where(events.c.recorded_at <= recorded_before)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        db.execute(
            query.order_by(
                events.c.recorded_at.desc(), events.c.event_type, events.c.source_id.desc()
            )
            .offset(offset)
            .limit(limit)
        )
        .mappings()
        .all()
    )
    items = [
        SecurityEventRead(
            event_id=f"{row['event_type']}:{row['source_id']}",
            event_type=row["event_type"],
            analysis_id=row["analysis_id"],
            original_filename=row["original_filename"],
            recorded_at=row["recorded_at"],
            timestamp_label=row["timestamp_label"],
            severity=row["severity"],
            risk_score=row["risk_score"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            protocol=row["protocol"],
            explanation=row["explanation"],
            rule_id=row["rule_id"],
            model_id=row["model_id"],
            model_version=row["model_version"],
            flow_id=row["flow_id"],
            related_reference=f"{row['event_type']}:{row['source_id']}",
        )
        for row in rows
    ]
    return SecurityEventList(items=items, total=int(total), offset=offset, limit=limit)


@router.get("/{event_id}", response_model=SecurityEventDetail)
def get_security_event(
    event_id: str,
    db: Session = Depends(get_db),  # noqa: B008
) -> SecurityEventDetail:
    try:
        kind, raw_id = event_id.split(":", maxsplit=1)
        record_id = int(raw_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail="Security event not found.") from None
    if record_id < 1:
        raise HTTPException(status_code=404, detail="Security event not found.")

    if kind == "rule_finding":
        finding = db.get(DetectionFinding, record_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="Security event not found.")
        analysis = db.get(Analysis, finding.analysis_id)
        event = SecurityEventRead(
            event_id=event_id,
            event_type="rule_finding",
            analysis_id=finding.analysis_id,
            original_filename=analysis.original_filename,
            recorded_at=finding.created_at,
            timestamp_label="finding recorded",
            severity=finding.severity,
            risk_score=None,
            source_ip=finding.source_ip,
            destination_ip=finding.destination_ip,
            protocol=finding.protocol_name,
            explanation=finding.explanation,
            rule_id=finding.rule_id,
            related_reference=event_id,
        )
        return SecurityEventDetail(
            event=event,
            evidence=finding.evidence,
            related_flow_ids=[flow.flow_id for flow in finding.supporting_flows],
        )

    if kind == "ml_anomaly":
        result = db.get(AnomalyResult, record_id)
        if result is None or result.prediction != "anomaly":
            raise HTTPException(status_code=404, detail="Security event not found.")
        analysis = db.get(Analysis, result.analysis_id)
        flow = db.scalar(
            select(NetworkFlow).where(
                NetworkFlow.analysis_id == result.analysis_id,
                NetworkFlow.flow_id == result.flow_id,
            )
        )
        if flow is None:
            raise HTTPException(status_code=404, detail="Security event not found.")
        event = SecurityEventRead(
            event_id=event_id,
            event_type="ml_anomaly",
            analysis_id=result.analysis_id,
            original_filename=analysis.original_filename,
            recorded_at=result.created_at,
            timestamp_label="anomaly scored",
            severity=None,
            risk_score=None,
            source_ip=flow.first_packet_source_ip,
            destination_ip=flow.first_packet_destination_ip,
            protocol=flow.protocol_name,
            explanation="Flow marked anomalous relative to the selected model.",
            model_id=result.model_id,
            model_version=result.model_version,
            flow_id=result.flow_id,
            related_reference=event_id,
        )
        return SecurityEventDetail(
            event=event,
            evidence={"prediction": result.prediction, "anomaly_score": str(result.anomaly_score)},
            related_flow_ids=[result.flow_id],
        )

    if kind == "hybrid_assessment":
        assessment = db.get(HybridAssessment, record_id)
        if assessment is None:
            raise HTTPException(status_code=404, detail="Security event not found.")
        analysis = db.get(Analysis, assessment.analysis_id)
        evidence_rows = db.scalars(
            select(HybridEvidence).where(HybridEvidence.assessment_id == assessment.id)
        ).all()
        evidence = [
            {
                "source": row.source,
                "source_id": row.source_id,
                "flow_id": row.flow_id,
                "rule_id": row.rule_id,
                "rule_name": row.rule_name,
                "original_severity": row.original_severity,
                "prediction": row.prediction,
                "anomaly_score": str(row.anomaly_score) if row.anomaly_score is not None else None,
                "evidence": row.evidence,
            }
            for row in evidence_rows
        ]
        event = SecurityEventRead(
            event_id=event_id,
            event_type="hybrid_assessment",
            analysis_id=assessment.analysis_id,
            original_filename=analysis.original_filename,
            recorded_at=assessment.created_at,
            timestamp_label="assessment created",
            severity=assessment.severity,
            risk_score=str(assessment.risk_score),
            source_ip=None,
            destination_ip=None,
            protocol=None,
            explanation=assessment.explanation,
            model_id=assessment.model_id,
            model_version=assessment.model_version,
            related_reference=event_id,
        )
        return SecurityEventDetail(
            event=event,
            evidence={
                "detection_run_id": assessment.detection_run_id,
                "model_id": assessment.model_id,
                "model_version": assessment.model_version,
                "rule_evidence_count": assessment.rule_evidence_count,
                "ml_anomaly_count": assessment.ml_anomaly_count,
                "correlated_evidence_count": assessment.correlated_evidence_count,
                "risk_groups": evidence,
            },
            related_flow_ids=list(
                dict.fromkeys(row.flow_id for row in evidence_rows if row.flow_id)
            ),
        )

    raise HTTPException(status_code=404, detail="Security event not found.")
