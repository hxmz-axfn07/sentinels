import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.hybrid import HybridAssessment
from app.models.pipeline import PipelineRun, PipelineStageExecution
from app.schemas.pipeline import (
    PipelineRunList,
    PipelineRunRead,
    PipelineRunRequest,
    PipelineStageRead,
    PipelineSummary,
)
from app.services.pipeline import PipelineFailure, execute_pipeline, get_pipeline_run

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/analyses", tags=["analysis-pipeline"])


@router.post("/{analysis_id}/pipeline/runs", response_model=PipelineRunRead, status_code=201)
def start_pipeline(
    request: PipelineRunRequest,
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> PipelineRunRead:
    try:
        run, reused = execute_pipeline(db, analysis_id, request)
        return _run_read(db, run, reused=reused)
    except PipelineFailure as error:
        db.rollback()
        raise HTTPException(
            status_code=error.status_code,
            detail={"code": error.code, "message": str(error)},
        ) from None
    except Exception as error:
        db.rollback()
        logger.error(
            "Pipeline start failed for analysis %s (%s)", analysis_id, type(error).__name__
        )
        raise HTTPException(
            status_code=500,
            detail={"code": "pipeline_start_failed", "message": "Pipeline could not start."},
        ) from None


@router.get("/{analysis_id}/pipeline/summary", response_model=PipelineSummary)
def pipeline_summary(
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> PipelineSummary:
    if db.get(Analysis, analysis_id) is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    run = db.scalar(
        select(PipelineRun)
        .options(selectinload(PipelineRun.stages))
        .where(PipelineRun.analysis_id == analysis_id)
        .order_by(PipelineRun.id.desc())
        .limit(1)
    )
    if run is None:
        return PipelineSummary(analysis_id=analysis_id, status="not_started", latest_run=None)
    return PipelineSummary(
        analysis_id=analysis_id,
        status=run.status,
        latest_run=_run_read(db, run),
    )


@router.get("/{analysis_id}/pipeline/runs", response_model=PipelineRunList)
def list_pipeline_runs(
    analysis_id: int = Path(ge=1),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),  # noqa: B008
) -> PipelineRunList:
    if db.get(Analysis, analysis_id) is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    query = select(PipelineRun).where(PipelineRun.analysis_id == analysis_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    runs = db.scalars(
        query.options(selectinload(PipelineRun.stages))
        .order_by(PipelineRun.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return PipelineRunList(
        items=[_run_read(db, run) for run in runs],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/{analysis_id}/pipeline/runs/{run_id}", response_model=PipelineRunRead)
def pipeline_run_detail(
    analysis_id: int = Path(ge=1),
    run_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> PipelineRunRead:
    try:
        return _run_read(db, get_pipeline_run(db, analysis_id, run_id))
    except PipelineFailure as error:
        raise HTTPException(
            status_code=error.status_code,
            detail={"code": error.code, "message": str(error)},
        ) from None


@router.get("/{analysis_id}/pipeline/runs/{run_id}/stages", response_model=list[PipelineStageRead])
def pipeline_stage_details(
    analysis_id: int = Path(ge=1),
    run_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> list[PipelineStageRead]:
    run = db.scalar(
        select(PipelineRun.id).where(
            PipelineRun.id == run_id, PipelineRun.analysis_id == analysis_id
        )
    )
    if run is None:
        if db.get(Analysis, analysis_id) is None:
            raise HTTPException(status_code=404, detail="Analysis not found.")
        raise HTTPException(status_code=404, detail="Pipeline run not found.")
    stages = db.scalars(
        select(PipelineStageExecution)
        .where(PipelineStageExecution.run_id == run_id)
        .order_by(PipelineStageExecution.execution_order)
    ).all()
    return [PipelineStageRead.model_validate(stage) for stage in stages]


def _run_read(db: Session, run: PipelineRun, *, reused: bool = False) -> PipelineRunRead:
    score = severity = None
    if run.hybrid_assessment_id is not None:
        assessment = db.get(HybridAssessment, run.hybrid_assessment_id)
        if assessment is not None:
            score = assessment.risk_score
            severity = assessment.severity
    stages = sorted(run.stages, key=lambda item: item.execution_order)
    return PipelineRunRead.model_validate(
        {
            **{column.name: getattr(run, column.name) for column in run.__table__.columns},
            "stages": stages,
            "risk_score": score,
            "severity": severity,
            "reused_run": reused,
        }
    )
