import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyModel
from app.models.detection import DetectionRun
from app.models.hybrid import HybridAssessment, HybridEvidence, HybridRiskGroup
from app.schemas.hybrid import (
    HybridAssessmentList,
    HybridAssessmentRead,
    HybridAssessmentRequest,
    HybridEvidenceList,
    HybridRiskGroupList,
    HybridRiskGroupRead,
    HybridSeverity,
    HybridSummary,
)
from app.services.hybrid.engine import HybridInputError, execute_assessment, scoring_config_hash

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/analyses", tags=["hybrid-detection"])


@router.post(
    "/{analysis_id}/hybrid/assessments",
    response_model=HybridAssessmentRead,
    status_code=201,
)
def run_hybrid_assessment(
    request: HybridAssessmentRequest,
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> HybridAssessmentRead:
    analysis = db.scalar(select(Analysis).where(Analysis.id == analysis_id).with_for_update())
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    detection_run = db.get(DetectionRun, request.detection_run_id)
    if detection_run is None or detection_run.analysis_id != analysis_id:
        raise HTTPException(status_code=404, detail="Detection run not found for this analysis.")
    model = db.get(AnomalyModel, request.model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found.")

    try:
        result = execute_assessment(
            db,
            analysis=analysis,
            detection_run=detection_run,
            model=model,
            config=settings.hybrid_scoring_config,
        )
        db.commit()
        db.refresh(result.assessment)
        return HybridAssessmentRead.model_validate(
            {**_assessment_values(result.assessment), "reused": result.reused}
        )
    except HybridInputError as error:
        db.rollback()
        raise HTTPException(
            status_code=error.status_code,
            detail={"code": error.code, "message": str(error)},
        ) from None
    except IntegrityError:
        db.rollback()
        existing = _find_assessment(
            db,
            analysis_id=analysis_id,
            detection_run_id=detection_run.id,
            model_id=model.id,
            scoring_config_hash=scoring_config_hash(settings.hybrid_scoring_config),
        )
        if existing is not None:
            return HybridAssessmentRead.model_validate(
                {**_assessment_values(existing), "reused": True}
            )
        logger.error("Hybrid assessment persistence conflict for analysis %s", analysis_id)
        raise HTTPException(
            status_code=409,
            detail={"code": "assessment_conflict", "message": "Assessment could not be saved."},
        ) from None
    except Exception as error:
        db.rollback()
        logger.error(
            "Hybrid assessment failed for analysis %s (%s)", analysis_id, type(error).__name__
        )
        raise HTTPException(
            status_code=500,
            detail={"code": "assessment_failed", "message": "Hybrid assessment did not complete."},
        ) from None


@router.get("/{analysis_id}/hybrid/summary", response_model=HybridSummary)
def get_hybrid_summary(
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> HybridSummary:
    _require_analysis(db, analysis_id)
    assessment = db.scalar(
        select(HybridAssessment)
        .where(HybridAssessment.analysis_id == analysis_id)
        .order_by(HybridAssessment.id.desc())
        .limit(1)
    )
    if assessment is None:
        return HybridSummary(analysis_id=analysis_id, status="not_started", assessment=None)
    return HybridSummary(
        analysis_id=analysis_id,
        status="completed",
        assessment=_assessment_read(assessment),
    )


@router.get("/{analysis_id}/hybrid/assessments", response_model=HybridAssessmentList)
def list_hybrid_assessments(
    analysis_id: int = Path(ge=1),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: HybridSeverity | None = None,
    db: Session = Depends(get_db),  # noqa: B008
) -> HybridAssessmentList:
    _require_analysis(db, analysis_id)
    query = select(HybridAssessment).where(HybridAssessment.analysis_id == analysis_id)
    if severity is not None:
        query = query.where(HybridAssessment.severity == severity)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(query.order_by(HybridAssessment.id.desc()).offset(offset).limit(limit)).all()
    return HybridAssessmentList(
        items=[_assessment_read(item) for item in items],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get(
    "/{analysis_id}/hybrid/assessments/{assessment_id}", response_model=HybridAssessmentRead
)
def get_hybrid_assessment(
    analysis_id: int = Path(ge=1),
    assessment_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> HybridAssessmentRead:
    _require_analysis(db, analysis_id)
    assessment = _get_assessment(db, analysis_id, assessment_id)
    return _assessment_read(assessment)


@router.get(
    "/{analysis_id}/hybrid/assessments/{assessment_id}/groups",
    response_model=HybridRiskGroupList,
)
def list_hybrid_groups(
    analysis_id: int = Path(ge=1),
    assessment_id: int = Path(ge=1),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: HybridSeverity | None = None,
    db: Session = Depends(get_db),  # noqa: B008
) -> HybridRiskGroupList:
    _get_assessment(db, analysis_id, assessment_id)
    query = select(HybridRiskGroup).where(HybridRiskGroup.assessment_id == assessment_id)
    if severity is not None:
        query = query.where(HybridRiskGroup.severity == severity)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(
        query.order_by(HybridRiskGroup.risk_score.desc(), HybridRiskGroup.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return HybridRiskGroupList(
        items=items, total=total, offset=offset, limit=limit, assessment_id=assessment_id
    )


@router.get(
    "/{analysis_id}/hybrid/assessments/{assessment_id}/groups/{group_id}",
    response_model=HybridRiskGroupRead,
)
def get_hybrid_group(
    analysis_id: int = Path(ge=1),
    assessment_id: int = Path(ge=1),
    group_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> HybridRiskGroupRead:
    _get_assessment(db, analysis_id, assessment_id)
    group = db.scalar(
        select(HybridRiskGroup).where(
            HybridRiskGroup.analysis_id == analysis_id,
            HybridRiskGroup.assessment_id == assessment_id,
            HybridRiskGroup.id == group_id,
        )
    )
    if group is None:
        raise HTTPException(status_code=404, detail="Risk group not found.")
    return group


@router.get(
    "/{analysis_id}/hybrid/assessments/{assessment_id}/groups/{group_id}/evidence",
    response_model=HybridEvidenceList,
)
def list_hybrid_evidence(
    analysis_id: int = Path(ge=1),
    assessment_id: int = Path(ge=1),
    group_id: int = Path(ge=1),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    source: str | None = Query(None, pattern="^(rule|ml)$"),
    db: Session = Depends(get_db),  # noqa: B008
) -> HybridEvidenceList:
    _get_assessment(db, analysis_id, assessment_id)
    group = db.scalar(
        select(HybridRiskGroup.id).where(
            HybridRiskGroup.id == group_id,
            HybridRiskGroup.assessment_id == assessment_id,
            HybridRiskGroup.analysis_id == analysis_id,
        )
    )
    if group is None:
        raise HTTPException(status_code=404, detail="Risk group not found.")
    query = select(HybridEvidence).where(HybridEvidence.group_id == group_id)
    if source is not None:
        query = query.where(HybridEvidence.source == source)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(
        query.order_by(HybridEvidence.source, HybridEvidence.source_id).offset(offset).limit(limit)
    ).all()
    return HybridEvidenceList(
        items=items, total=total, offset=offset, limit=limit, group_id=group_id
    )


def _find_assessment(
    db: Session,
    *,
    analysis_id: int,
    detection_run_id: int,
    model_id: int,
    scoring_config_hash: str,
) -> HybridAssessment | None:
    return db.scalar(
        select(HybridAssessment).where(
            HybridAssessment.analysis_id == analysis_id,
            HybridAssessment.detection_run_id == detection_run_id,
            HybridAssessment.model_id == model_id,
            HybridAssessment.scoring_config_hash == scoring_config_hash,
        )
    )


def _require_analysis(db: Session, analysis_id: int) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


def _get_assessment(db: Session, analysis_id: int, assessment_id: int) -> HybridAssessment:
    assessment = db.scalar(
        select(HybridAssessment).where(
            HybridAssessment.analysis_id == analysis_id,
            HybridAssessment.id == assessment_id,
        )
    )
    if assessment is None:
        raise HTTPException(status_code=404, detail="Hybrid assessment not found.")
    return assessment


def _assessment_read(assessment: HybridAssessment) -> HybridAssessmentRead:
    return HybridAssessmentRead.model_validate(assessment)


def _assessment_values(assessment: HybridAssessment) -> dict[str, object]:
    return {
        name: getattr(assessment, name)
        for name in HybridAssessmentRead.model_fields
        if name != "reused"
    }
