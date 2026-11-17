import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.evaluation import EvaluationRun
from app.schemas.evaluation import (
    EvaluationCreate,
    EvaluationRunList,
    EvaluationRunRead,
    EvaluationRunSummary,
)
from app.services.evaluation.dataset import DATASET_VERSION
from app.services.evaluation.runner import run_evaluation

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/evaluations", tags=["evaluation"])


@router.post("", response_model=EvaluationRunRead, status_code=status.HTTP_201_CREATED)
def create_evaluation(
    request: EvaluationCreate,
    db: Session = Depends(get_db),  # noqa: B008
) -> EvaluationRunRead:
    run = EvaluationRun(
        dataset_version=DATASET_VERSION,
        random_seed=request.random_seed,
        repeat_count=request.repeat_count,
        status="running",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    try:
        run.results = run_evaluation(
            random_seed=request.random_seed, repeat_count=request.repeat_count
        )
        run.status = "completed"
    except Exception:
        db.rollback()
        logger.exception("Evaluation run %s failed", run.id)
        run = db.get(EvaluationRun, run.id)
        if run is None:
            raise HTTPException(
                status_code=500, detail="Evaluation record was unavailable."
            ) from None
        run.status = "failed"
        run.failure_summary = "Evaluation failed. Review server logs and retry."
    run.completed_at = datetime.now(UTC)
    db.commit()
    db.refresh(run)
    return EvaluationRunRead.model_validate(run)


@router.get("", response_model=EvaluationRunList)
def list_evaluations(
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),  # noqa: B008
) -> EvaluationRunList:
    total = db.scalar(select(func.count()).select_from(EvaluationRun)) or 0
    items = db.scalars(
        select(EvaluationRun)
        .order_by(EvaluationRun.created_at.desc(), EvaluationRun.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return EvaluationRunList(
        items=[EvaluationRunSummary.model_validate(item) for item in items],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/{evaluation_id}", response_model=EvaluationRunRead)
def get_evaluation(
    evaluation_id: int,
    db: Session = Depends(get_db),  # noqa: B008
) -> EvaluationRunRead:
    run = db.get(EvaluationRun, evaluation_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Evaluation run not found.")
    return EvaluationRunRead.model_validate(run)
