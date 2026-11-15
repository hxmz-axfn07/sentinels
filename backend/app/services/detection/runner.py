import hashlib
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.models.detection import DetectionFinding, DetectionRun, detection_finding_flows
from app.models.flow import NetworkFlow
from app.services.detection.config import DetectionConfig
from app.services.detection.rules import DetectionCandidate, FlowLike, evaluate_rules

logger = logging.getLogger(__name__)
FLOW_BATCH_SIZE = 500
FINDING_BATCH_SIZE = 100


def configuration_hash(config: DetectionConfig) -> str:
    serialized = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def start_or_reuse_run(
    db: Session, analysis_id: int, config: DetectionConfig
) -> tuple[DetectionRun, bool]:
    """Claim a config-specific run; callers lock and validate the analysis first."""
    config_hash = configuration_hash(config)
    run = db.scalar(
        select(DetectionRun).where(
            DetectionRun.analysis_id == analysis_id,
            DetectionRun.config_hash == config_hash,
        )
    )
    if run is not None and run.status == "completed":
        return run, False
    if run is None:
        run = DetectionRun(
            analysis_id=analysis_id,
            config_hash=config_hash,
            config_snapshot=config.model_dump(mode="json"),
            status="processing",
            finding_count=0,
        )
        db.add(run)
        db.flush()
    else:
        run.status = "processing"
        run.finding_count = 0
        run.error_message = None
        run.completed_at = None
    return run, True


def execute_run(db: Session, run: DetectionRun, config: DetectionConfig) -> int:
    flow_iterator = _iter_analysis_flows(db, run.analysis_id)
    finding_count = 0
    pending: list[tuple[DetectionCandidate, DetectionFinding]] = []

    for candidate in evaluate_rules(flow_iterator, config):
        finding = DetectionFinding(
            run_id=run.id,
            analysis_id=run.analysis_id,
            finding_key=candidate.finding_key,
            rule_id=candidate.rule_id,
            rule_name=candidate.rule_name,
            severity=candidate.severity,
            source_ip=candidate.source_ip,
            destination_ip=candidate.destination_ip,
            protocol_name=candidate.protocol_name,
            explanation=candidate.explanation,
            evidence=candidate.evidence,
            supporting_flow_count=candidate.supporting_flow_count,
            supporting_flow_sample_truncated=candidate.supporting_flow_sample_truncated,
        )
        db.add(finding)
        pending.append((candidate, finding))
        finding_count += 1
        if len(pending) >= FINDING_BATCH_SIZE:
            _flush_findings(db, pending)
            pending.clear()

    if pending:
        _flush_findings(db, pending)
    run.finding_count = finding_count
    run.status = "completed"
    run.error_message = None
    run.completed_at = datetime.now(UTC)
    return finding_count


def mark_run_failed(db: Session, run_id: int) -> None:
    """Persist a generic failure after the finding transaction has rolled back."""
    try:
        run = db.get(DetectionRun, run_id)
        if run is None:
            return
        run.status = "failed"
        run.finding_count = 0
        run.error_message = "Detection did not complete."
        run.completed_at = datetime.now(UTC)
        db.commit()
    except Exception as error:
        db.rollback()
        logger.error("Could not persist failed detection run %s (%s)", run_id, type(error).__name__)


def _iter_analysis_flows(db: Session, analysis_id: int) -> Iterator[FlowLike]:
    last_id = 0
    columns = (
        NetworkFlow.id,
        NetworkFlow.protocol_name,
        NetworkFlow.endpoint_a_ip,
        NetworkFlow.endpoint_a_port,
        NetworkFlow.endpoint_b_ip,
        NetworkFlow.endpoint_b_port,
        NetworkFlow.first_packet_source_ip,
        NetworkFlow.first_packet_source_port,
        NetworkFlow.first_packet_destination_ip,
        NetworkFlow.first_packet_destination_port,
        NetworkFlow.forward_syn_only_count,
        NetworkFlow.backward_syn_only_count,
        NetworkFlow.forward_syn_ack_count,
        NetworkFlow.backward_syn_ack_count,
    )
    while True:
        rows = (
            db.execute(
                select(*columns)
                .where(NetworkFlow.analysis_id == analysis_id, NetworkFlow.id > last_id)
                .order_by(NetworkFlow.id)
                .limit(FLOW_BATCH_SIZE)
            )
            .mappings()
            .all()
        )
        if not rows:
            return
        for row in rows:
            yield _FlowObservation(**row)
        last_id = rows[-1]["id"]


def _flush_findings(
    db: Session, pending: list[tuple[DetectionCandidate, DetectionFinding]]
) -> None:
    db.flush()
    links = [
        {"finding_id": finding.id, "flow_id": flow_id}
        for candidate, finding in pending
        for flow_id in candidate.supporting_flow_ids
    ]
    if links:
        db.execute(insert(detection_finding_flows), links)


@dataclass(frozen=True, slots=True)
class _FlowObservation:
    id: int
    protocol_name: str
    endpoint_a_ip: str | None
    endpoint_a_port: int | None
    endpoint_b_ip: str | None
    endpoint_b_port: int | None
    first_packet_source_ip: str | None
    first_packet_source_port: int | None
    first_packet_destination_ip: str | None
    first_packet_destination_port: int | None
    forward_syn_only_count: int | None
    backward_syn_only_count: int | None
    forward_syn_ack_count: int | None
    backward_syn_ack_count: int | None
