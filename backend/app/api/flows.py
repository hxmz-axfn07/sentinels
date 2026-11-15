import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import IPvAnyAddress
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.flow import NetworkFlow
from app.schemas.flow import FlowGenerationRead, FlowList, FlowRead
from app.services.flow_generation import generate_flows

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/analyses", tags=["flows"])


@router.post("/{analysis_id}/flows/generate", response_model=FlowGenerationRead)
def generate_analysis_flows(
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> FlowGenerationRead:
    analysis = db.scalar(select(Analysis).where(Analysis.id == analysis_id).with_for_update())
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if analysis.status != "completed":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "analysis_not_completed",
                "message": "Flows can only be generated for a completed analysis.",
            },
        )
    if analysis.flow_generation_status == "processing":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "flow_generation_in_progress",
                "message": "Flow generation is already in progress.",
            },
        )
    if analysis.flow_generation_status == "completed":
        return _generation_response(analysis, generated=False)

    analysis.flow_generation_status = "processing"
    analysis.flow_error_message = None
    db.commit()

    try:
        flow_count = generate_flows(db, analysis_id)
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            raise RuntimeError("Analysis disappeared during flow generation.")
        analysis.flow_generation_status = "completed"
        analysis.flow_count = flow_count
        analysis.flow_error_message = None
        analysis.flows_generated_at = datetime.now(UTC)
        db.commit()
        db.refresh(analysis)
        return _generation_response(analysis, generated=True)
    except Exception as error:
        db.rollback()
        try:
            analysis = db.get(Analysis, analysis_id)
            if analysis is not None:
                analysis.flow_generation_status = "failed"
                analysis.flow_count = 0
                analysis.flow_error_message = "Flow generation did not complete."
                analysis.flows_generated_at = None
                db.commit()
        except Exception as database_error:
            db.rollback()
            logger.error(
                "Could not persist flow failure for analysis %s (%s)",
                analysis_id,
                type(database_error).__name__,
            )
        logger.error(
            "Flow generation failed for analysis %s (%s)",
            analysis_id,
            type(error).__name__,
        )
        raise HTTPException(
            status_code=500,
            detail={"code": "flow_generation_failed", "message": "Flow generation failed."},
        ) from None


@router.get("/{analysis_id}/flows", response_model=FlowList)
def list_analysis_flows(
    analysis_id: int = Path(ge=1),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    protocol: str | None = Query(None, min_length=1, max_length=32),
    endpoint: IPvAnyAddress | None = None,
    db: Session = Depends(get_db),  # noqa: B008
) -> FlowList:
    analysis = _get_analysis(db, analysis_id)
    _require_generated(analysis)
    query = select(NetworkFlow).where(NetworkFlow.analysis_id == analysis_id)
    if protocol is not None:
        query = query.where(NetworkFlow.protocol_name == protocol.strip().upper())
    if endpoint is not None:
        address = endpoint.compressed
        query = query.where(
            (NetworkFlow.endpoint_a_ip == address) | (NetworkFlow.endpoint_b_ip == address)
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(query.order_by(NetworkFlow.flow_id).offset(offset).limit(limit)).all()
    return FlowList(items=items, total=total, offset=offset, limit=limit)


@router.get("/{analysis_id}/flows/{flow_id}", response_model=FlowRead)
def get_analysis_flow(
    analysis_id: int = Path(ge=1),
    flow_id: str = Path(pattern="^[a-f0-9]{64}$"),
    db: Session = Depends(get_db),  # noqa: B008
) -> NetworkFlow:
    analysis = _get_analysis(db, analysis_id)
    _require_generated(analysis)
    flow = db.scalar(
        select(NetworkFlow).where(
            NetworkFlow.analysis_id == analysis_id,
            NetworkFlow.flow_id == flow_id,
        )
    )
    if flow is None:
        raise HTTPException(status_code=404, detail="Flow not found.")
    return flow


def _get_analysis(db: Session, analysis_id: int) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


def _require_generated(analysis: Analysis) -> None:
    if analysis.flow_generation_status != "completed":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "flows_not_ready",
                "message": "Flows have not been generated for this analysis.",
            },
        )


def _generation_response(analysis: Analysis, *, generated: bool) -> FlowGenerationRead:
    return FlowGenerationRead(
        analysis_id=analysis.id,
        status=analysis.flow_generation_status,
        flow_count=analysis.flow_count,
        generated=generated,
        flows_generated_at=analysis.flows_generated_at,
    )
