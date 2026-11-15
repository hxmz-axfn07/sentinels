import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.detection import DetectionFinding, DetectionRun
from app.schemas.detection import (
    DetectionRunRead,
    DetectionSeverity,
    DetectionSummary,
    FindingList,
    FindingRead,
    RuleFindingCount,
)
from app.services.detection.runner import (
    execute_run,
    mark_run_failed,
    start_or_reuse_run,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/analyses", tags=["detection"])


@router.post("/{analysis_id}/detections/run", response_model=DetectionRunRead)
def run_analysis_detection(
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> DetectionRunRead:
    analysis = db.scalar(select(Analysis).where(Analysis.id == analysis_id).with_for_update())
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if analysis.status != "completed":
        raise HTTPException(
            status_code=409,
            detail={"code": "analysis_not_completed", "message": "Analysis is not completed."},
        )
    if analysis.flow_generation_status != "completed":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "flows_not_ready",
                "message": "Generate flows before running detection.",
            },
        )
    active_run = db.scalar(
        select(DetectionRun).where(
            DetectionRun.analysis_id == analysis_id, DetectionRun.status == "processing"
        )
    )
    if active_run is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "detection_in_progress",
                "message": "Detection is already running for this analysis.",
            },
        )

    run, should_execute = start_or_reuse_run(db, analysis_id, settings.detection_config)
    if not should_execute:
        return DetectionRunRead.model_validate({**_run_values(run), "reused": True})
    db.commit()

    try:
        run = db.get(DetectionRun, run.id)
        if run is None:
            raise RuntimeError("Detection run disappeared before execution.")
        execute_run(db, run, settings.detection_config)
        db.commit()
        db.refresh(run)
        return DetectionRunRead.model_validate({**_run_values(run), "reused": False})
    except Exception as error:
        run_id = run.id
        db.rollback()
        mark_run_failed(db, run_id)
        logger.error("Detection run %s failed (%s)", run_id, type(error).__name__)
        raise HTTPException(
            status_code=500,
            detail={"code": "detection_failed", "message": "Detection did not complete."},
        ) from None


@router.get("/{analysis_id}/findings", response_model=FindingList)
def list_analysis_findings(
    analysis_id: int = Path(ge=1),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: DetectionSeverity | None = None,
    rule_id: str | None = Query(None, min_length=1, max_length=64),
    run_id: int | None = Query(None, ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> FindingList:
    _require_analysis(db, analysis_id)
    run = _resolve_run(db, analysis_id, run_id)
    if run is None:
        return FindingList(items=[], total=0, offset=offset, limit=limit, run_id=None)
    _require_finished(run)

    query = select(DetectionFinding).where(DetectionFinding.run_id == run.id)
    if severity is not None:
        query = query.where(DetectionFinding.severity == severity)
    if rule_id is not None:
        query = query.where(DetectionFinding.rule_id == rule_id.strip().upper())
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(
        query.options(selectinload(DetectionFinding.supporting_flows))
        .order_by(DetectionFinding.severity, DetectionFinding.rule_id, DetectionFinding.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return FindingList(
        items=items,
        total=total,
        offset=offset,
        limit=limit,
        run_id=run.id,
    )


@router.get("/{analysis_id}/findings/{finding_id}", response_model=FindingRead)
def get_analysis_finding(
    analysis_id: int = Path(ge=1),
    finding_id: int = Path(ge=1),
    run_id: int | None = Query(None, ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> DetectionFinding:
    _require_analysis(db, analysis_id)
    run = _resolve_run(db, analysis_id, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    _require_finished(run)
    finding = db.scalar(
        select(DetectionFinding)
        .options(selectinload(DetectionFinding.supporting_flows))
        .where(
            DetectionFinding.analysis_id == analysis_id,
            DetectionFinding.run_id == run.id,
            DetectionFinding.id == finding_id,
        )
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding


@router.get("/{analysis_id}/detection-summary", response_model=DetectionSummary)
def get_detection_summary(
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> DetectionSummary:
    _require_analysis(db, analysis_id)
    run = _resolve_run(db, analysis_id, None)
    if run is None:
        return DetectionSummary(
            analysis_id=analysis_id,
            run_id=None,
            status="not_started",
            finding_count=0,
            severity_counts={"low": 0, "medium": 0, "high": 0, "critical": 0},
            rule_counts=[],
            config_hash=None,
            error_message=None,
            created_at=None,
            completed_at=None,
        )

    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    rule_counts: list[RuleFindingCount] = []
    if run.status == "completed":
        for severity, count in db.execute(
            select(DetectionFinding.severity, func.count(DetectionFinding.id))
            .where(DetectionFinding.run_id == run.id)
            .group_by(DetectionFinding.severity)
        ):
            severity_counts[severity] = count
        rule_counts = [
            RuleFindingCount(rule_id=rule_id, count=count)
            for rule_id, count in db.execute(
                select(DetectionFinding.rule_id, func.count(DetectionFinding.id))
                .where(DetectionFinding.run_id == run.id)
                .group_by(DetectionFinding.rule_id)
                .order_by(DetectionFinding.rule_id)
            )
        ]

    return DetectionSummary(
        analysis_id=analysis_id,
        run_id=run.id,
        status=run.status,
        finding_count=run.finding_count,
        severity_counts=severity_counts,
        rule_counts=rule_counts,
        config_hash=run.config_hash,
        error_message=run.error_message,
        created_at=run.created_at,
        completed_at=run.completed_at,
    )


def _require_analysis(db: Session, analysis_id: int) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


def _resolve_run(db: Session, analysis_id: int, run_id: int | None) -> DetectionRun | None:
    query = select(DetectionRun).where(DetectionRun.analysis_id == analysis_id)
    if run_id is not None:
        query = query.where(DetectionRun.id == run_id)
        run = db.scalar(query)
        if run is None:
            raise HTTPException(status_code=404, detail="Detection run not found.")
        return run
    return db.scalar(query.order_by(DetectionRun.id.desc()).limit(1))


def _require_finished(run: DetectionRun) -> None:
    if run.status != "completed":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "detection_not_completed",
                "message": f"Detection run is {run.status}.",
            },
        )


def _run_values(run: DetectionRun) -> dict[str, object]:
    return {
        "id": run.id,
        "analysis_id": run.analysis_id,
        "config_hash": run.config_hash,
        "status": run.status,
        "finding_count": run.finding_count,
        "error_message": run.error_message,
        "created_at": run.created_at,
        "completed_at": run.completed_at,
    }
