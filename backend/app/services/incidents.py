from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import func, select, tuple_
from sqlalchemy.orm import Session

from app.models.analysis import Analysis
from app.models.anomaly import AnomalyResult
from app.models.detection import DetectionFinding, detection_finding_flows
from app.models.flow import NetworkFlow
from app.models.hybrid import HybridAssessment, HybridEvidence
from app.models.incident import Incident, IncidentEvidence, IncidentHistory, IncidentNote
from app.schemas.incidents import (
    IncidentCreate,
    IncidentDetail,
    IncidentEvidenceRead,
    IncidentHistoryRead,
    IncidentList,
    IncidentNoteCreate,
    IncidentNoteRead,
    IncidentRead,
    IncidentStatusUpdate,
    IncidentSummary,
    IncidentUpdate,
)


class IncidentReferenceError(ValueError):
    pass


class IncidentTransitionError(ValueError):
    pass


def list_incidents(
    db: Session,
    *,
    offset: int,
    limit: int,
    status: str | None,
    priority: str | None,
    search: str | None,
) -> IncidentList:
    query = select(Incident)
    if status:
        query = query.where(Incident.status == status)
    if priority:
        query = query.where(Incident.priority == priority)
    if search:
        query = query.where(Incident.title.ilike(f"%{search}%"))
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    incidents = db.scalars(
        query.order_by(Incident.updated_at.desc(), Incident.id.desc()).offset(offset).limit(limit)
    ).all()
    return IncidentList(
        items=_read_incidents(db, incidents), total=total, offset=offset, limit=limit
    )


def incident_summary(db: Session) -> IncidentSummary:
    status_rows = db.execute(
        select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    ).all()
    priority_rows = db.execute(
        select(Incident.priority, func.count(Incident.id)).group_by(Incident.priority)
    ).all()
    status_counts = {state: int(count) for state, count in status_rows}
    priority_counts = {priority: int(count) for priority, count in priority_rows}
    total = sum(status_counts.values())
    return IncidentSummary(
        total=total,
        status_counts=status_counts,
        priority_counts=priority_counts,
    )


def get_incident(db: Session, incident_id: int) -> IncidentDetail | None:
    incident = db.get(Incident, incident_id)
    if incident is None:
        return None
    links = db.scalars(
        select(IncidentEvidence)
        .where(IncidentEvidence.incident_id == incident_id)
        .order_by(IncidentEvidence.created_at, IncidentEvidence.id)
        .limit(100)
    ).all()
    notes = db.scalars(
        select(IncidentNote)
        .where(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at.desc(), IncidentNote.id.desc())
        .limit(100)
    ).all()
    history = db.scalars(
        select(IncidentHistory)
        .where(IncidentHistory.incident_id == incident_id)
        .order_by(IncidentHistory.created_at.desc(), IncidentHistory.id.desc())
        .limit(100)
    ).all()
    return IncidentDetail(
        **_read_incidents(db, [incident])[0].model_dump(),
        evidence=_serialize_evidence(db, links),
        notes=[IncidentNoteRead.model_validate(note) for note in reversed(notes)],
        history=[IncidentHistoryRead.model_validate(entry) for entry in reversed(history)],
    )


def create_incident(db: Session, data: IncidentCreate) -> Incident:
    incident = Incident(
        title=data.title.strip(), description=data.description.strip(), priority=data.priority
    )
    db.add(incident)
    db.flush()
    _history(db, incident.id, "incident_created", {"title": incident.title})
    add_evidence(db, incident, data.event_ids)
    return incident


def update_incident(db: Session, incident: Incident, data: IncidentUpdate) -> None:
    changes = {}
    for key in ("title", "description", "priority"):
        value = getattr(data, key)
        if value is not None and value != getattr(incident, key):
            before = getattr(incident, key)
            setattr(incident, key, value.strip() if isinstance(value, str) else value)
            changes[key] = {"from": before, "to": getattr(incident, key)}
    if changes:
        incident.updated_at = datetime.now(UTC)
        _history(db, incident.id, "incident_updated", changes)


def update_status(db: Session, incident: Incident, data: IncidentStatusUpdate) -> None:
    transitions = {
        "open": {"acknowledged", "investigating", "resolved"},
        "acknowledged": {"open", "investigating", "resolved"},
        "investigating": {"acknowledged", "resolved"},
        "resolved": {"investigating", "closed"},
        "closed": {"investigating"},
    }
    if data.status == incident.status:
        return
    if data.status not in transitions[incident.status]:
        raise IncidentTransitionError(f"Cannot transition from {incident.status} to {data.status}.")
    if data.status == "resolved" and not (data.resolution_summary or "").strip():
        raise IncidentTransitionError("A resolution summary is required to resolve an incident.")
    old = incident.status
    incident.status = data.status
    incident.updated_at = datetime.now(UTC)
    if data.status == "resolved":
        incident.resolution_summary = data.resolution_summary.strip()
        incident.resolved_at = datetime.now(UTC)
        action = "incident_resolved"
    elif old in {"resolved", "closed"} and data.status == "investigating":
        incident.resolution_summary = None
        incident.resolved_at = None
        action = "incident_reopened"
    elif data.status == "closed":
        action = "incident_closed"
    else:
        action = "status_changed"
    _history(db, incident.id, action, {"from": old, "to": data.status})


def add_evidence(db: Session, incident: Incident, event_ids: list[str]) -> int:
    added = 0
    seen: set[str] = set()
    for event_id in event_ids:
        if event_id in seen:
            continue
        seen.add(event_id)
        source_type, source_id = _parse_event_id(event_id)
        existing = db.scalar(
            select(IncidentEvidence).where(
                IncidentEvidence.incident_id == incident.id,
                IncidentEvidence.source_type == source_type,
                IncidentEvidence.source_id == source_id,
            )
        )
        if existing:
            continue
        link = _make_evidence_link(db, incident.id, source_type, source_id)
        db.add(link)
        _history(
            db,
            incident.id,
            "evidence_attached",
            {"event_id": event_id, "analysis_id": link.analysis_id},
        )
        added += 1
    return added


def remove_evidence(db: Session, incident: Incident, evidence_id: int) -> bool:
    link = db.scalar(
        select(IncidentEvidence).where(
            IncidentEvidence.id == evidence_id, IncidentEvidence.incident_id == incident.id
        )
    )
    if link is None:
        return False
    event_id = f"{link.source_type}:{link.source_id}"
    db.delete(link)
    _history(db, incident.id, "evidence_detached", {"event_id": event_id})
    return True


def add_note(db: Session, incident: Incident, data: IncidentNoteCreate) -> IncidentNote:
    note = IncidentNote(incident_id=incident.id, body=data.body.strip())
    db.add(note)
    incident.updated_at = datetime.now(UTC)
    _history(db, incident.id, "note_added", {})
    return note


def _make_evidence_link(
    db: Session, incident_id: int, source_type: str, source_id: int
) -> IncidentEvidence:
    if source_type == "rule_finding":
        source = db.get(DetectionFinding, source_id)
        if source is None:
            raise IncidentReferenceError("Rule finding was not found.")
        return IncidentEvidence(
            incident_id=incident_id,
            analysis_id=source.analysis_id,
            source_type=source_type,
            source_id=source_id,
            detection_finding_id=source.id,
            detection_run_id=source.run_id,
        )
    if source_type == "ml_anomaly":
        source = db.get(AnomalyResult, source_id)
        if source is None or source.prediction != "anomaly":
            raise IncidentReferenceError("ML anomaly indicator was not found.")
        return IncidentEvidence(
            incident_id=incident_id,
            analysis_id=source.analysis_id,
            source_type=source_type,
            source_id=source_id,
            anomaly_result_id=source.id,
            model_id=source.model_id,
            model_version=source.model_version,
        )
    if source_type == "hybrid_assessment":
        source = db.get(HybridAssessment, source_id)
        if source is None:
            raise IncidentReferenceError("Hybrid assessment was not found.")
        return IncidentEvidence(
            incident_id=incident_id,
            analysis_id=source.analysis_id,
            source_type=source_type,
            source_id=source_id,
            hybrid_assessment_id=source.id,
        )
    raise IncidentReferenceError("Unsupported security event type.")


def _parse_event_id(event_id: str) -> tuple[str, int]:
    try:
        source_type, raw_id = event_id.split(":", maxsplit=1)
        source_id = int(raw_id)
    except (ValueError, TypeError):
        raise IncidentReferenceError("Security event reference is invalid.") from None
    if source_type not in {"rule_finding", "ml_anomaly", "hybrid_assessment"} or source_id < 1:
        raise IncidentReferenceError("Security event reference is invalid.")
    return source_type, source_id


def _serialize_evidence(db: Session, links: list[IncidentEvidence]) -> list[IncidentEvidenceRead]:
    if not links:
        return []
    analysis_ids = {link.analysis_id for link in links}
    analyses = {
        analysis.id: analysis
        for analysis in db.scalars(select(Analysis).where(Analysis.id.in_(analysis_ids))).all()
    }
    rule_ids = {link.source_id for link in links if link.source_type == "rule_finding"}
    ml_ids = {link.source_id for link in links if link.source_type == "ml_anomaly"}
    hybrid_ids = {link.source_id for link in links if link.source_type == "hybrid_assessment"}
    findings = {
        item.id: item
        for item in db.scalars(
            select(DetectionFinding).where(DetectionFinding.id.in_(rule_ids))
        ).all()
    }
    anomalies = {
        item.id: item
        for item in db.scalars(select(AnomalyResult).where(AnomalyResult.id.in_(ml_ids))).all()
    }
    assessments = {
        item.id: item
        for item in db.scalars(
            select(HybridAssessment).where(HybridAssessment.id.in_(hybrid_ids))
        ).all()
    }
    rule_flows: dict[int, list[str]] = defaultdict(list)
    if rule_ids:
        for finding_id, flow_id in db.execute(
            select(detection_finding_flows.c.finding_id, NetworkFlow.flow_id)
            .join(NetworkFlow, NetworkFlow.id == detection_finding_flows.c.flow_id)
            .where(detection_finding_flows.c.finding_id.in_(rule_ids))
            .order_by(detection_finding_flows.c.finding_id, NetworkFlow.flow_id)
        ):
            rule_flows[finding_id].append(flow_id)
    hybrid_refs: dict[int, list[dict[str, object]]] = defaultdict(list)
    hybrid_flow_ids: dict[int, list[str]] = defaultdict(list)
    if hybrid_ids:
        rows = db.execute(
            select(
                HybridEvidence.assessment_id,
                HybridEvidence.flow_id,
                HybridEvidence.source,
                HybridEvidence.source_id,
                HybridEvidence.rule_id,
                HybridEvidence.rule_name,
                HybridEvidence.original_severity,
                HybridEvidence.prediction,
                HybridEvidence.anomaly_score,
                HybridEvidence.evidence,
            )
            .where(HybridEvidence.assessment_id.in_(hybrid_ids))
            .order_by(HybridEvidence.assessment_id, HybridEvidence.id)
        ).all()
        for row in rows:
            hybrid_refs[row.assessment_id].append(
                {
                    "flow_id": row.flow_id,
                    "source": row.source,
                    "source_id": row.source_id,
                    "rule_id": row.rule_id,
                    "rule_name": row.rule_name,
                    "original_severity": row.original_severity,
                    "prediction": row.prediction,
                    "anomaly_score": str(row.anomaly_score)
                    if row.anomaly_score is not None
                    else None,
                    "evidence": row.evidence,
                }
            )
            if row.flow_id and row.flow_id not in hybrid_flow_ids[row.assessment_id]:
                hybrid_flow_ids[row.assessment_id].append(row.flow_id)
    flow_keys = [(item.analysis_id, item.flow_id) for item in anomalies.values()]
    flows = (
        db.scalars(
            select(NetworkFlow).where(
                tuple_(NetworkFlow.analysis_id, NetworkFlow.flow_id).in_(flow_keys)
            )
        ).all()
        if flow_keys
        else []
    )
    flows_by_key = {(flow.analysis_id, flow.flow_id): flow for flow in flows}
    result = []
    for link in links:
        base = {
            "id": link.id,
            "source_type": link.source_type,
            "source_id": link.source_id,
            "event_id": f"{link.source_type}:{link.source_id}",
            "analysis_id": link.analysis_id,
            "original_filename": analyses[link.analysis_id].original_filename,
            "attached_at": link.created_at,
        }
        if link.source_type == "rule_finding":
            finding = findings[link.source_id]
            result.append(
                IncidentEvidenceRead(
                    **base,
                    severity=finding.severity,
                    anomaly_score=None,
                    risk_score=None,
                    source_ip=finding.source_ip,
                    destination_ip=finding.destination_ip,
                    protocol=finding.protocol_name,
                    explanation=finding.explanation,
                    flow_ids=rule_flows.get(finding.id, []),
                    model_id=None,
                    model_version=None,
                    evidence=finding.evidence,
                )
            )
        elif link.source_type == "ml_anomaly":
            anomaly = anomalies[link.source_id]
            flow = flows_by_key.get((anomaly.analysis_id, anomaly.flow_id))
            result.append(
                IncidentEvidenceRead(
                    **base,
                    severity=None,
                    anomaly_score=str(anomaly.anomaly_score),
                    risk_score=None,
                    source_ip=flow.first_packet_source_ip if flow else None,
                    destination_ip=flow.first_packet_destination_ip if flow else None,
                    protocol=flow.protocol_name if flow else None,
                    explanation="Flow marked anomalous relative to the selected model.",
                    flow_ids=[anomaly.flow_id],
                    model_id=anomaly.model_id,
                    model_version=anomaly.model_version,
                    evidence={
                        "prediction": anomaly.prediction,
                        "anomaly_score": str(anomaly.anomaly_score),
                    },
                )
            )
        else:
            assessment = assessments[link.source_id]
            result.append(
                IncidentEvidenceRead(
                    **base,
                    severity=assessment.severity,
                    anomaly_score=None,
                    risk_score=str(assessment.risk_score),
                    source_ip=None,
                    destination_ip=None,
                    protocol=None,
                    explanation=assessment.explanation,
                    flow_ids=hybrid_flow_ids.get(assessment.id, []),
                    model_id=assessment.model_id,
                    model_version=assessment.model_version,
                    evidence={
                        "detection_run_id": assessment.detection_run_id,
                        "model_id": assessment.model_id,
                        "model_version": assessment.model_version,
                        "rule_evidence_count": assessment.rule_evidence_count,
                        "ml_anomaly_count": assessment.ml_anomaly_count,
                        "correlated_evidence_count": assessment.correlated_evidence_count,
                        "risk_groups": hybrid_refs.get(assessment.id, []),
                    },
                )
            )
    return result


def _read_incidents(db: Session, incidents: list[Incident]) -> list[IncidentRead]:
    if not incidents:
        return []
    ids = [incident.id for incident in incidents]
    counts: dict[int, int] = defaultdict(int)
    analysis_ids: dict[int, set[int]] = defaultdict(set)
    for incident_id, analysis_id, count in db.execute(
        select(
            IncidentEvidence.incident_id,
            IncidentEvidence.analysis_id,
            func.count(IncidentEvidence.id),
        )
        .where(IncidentEvidence.incident_id.in_(ids))
        .group_by(IncidentEvidence.incident_id, IncidentEvidence.analysis_id)
    ):
        counts[incident_id] += int(count)
        analysis_ids[incident_id].add(analysis_id)
    return [
        IncidentRead(
            **{
                column.name: getattr(incident, column.name) for column in Incident.__table__.columns
            },
            evidence_count=counts[incident.id],
            analysis_ids=sorted(analysis_ids[incident.id]),
        )
        for incident in incidents
    ]


def _history(db: Session, incident_id: int, action: str, details: dict[str, object]) -> None:
    db.add(IncidentHistory(incident_id=incident_id, action=action, details=details))
