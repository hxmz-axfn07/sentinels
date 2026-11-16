import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyModel, AnomalyResult
from app.models.flow import NetworkFlow
from app.schemas.anomaly import (
    AnomalyResultList,
    AnomalyResultRead,
    AnomalySummary,
    FlowReference,
    InferenceRead,
    InferenceRequest,
    ModelList,
    ModelRead,
    ModelTrainingRequest,
    PredictionLabel,
)
from app.services.ml.engine import (
    MIN_TRAINING_SAMPLES,
    collect_training_data,
    count_existing_results,
    create_model_record,
    load_trained_pipeline,
    run_inference,
    train_pipeline,
    validate_training_analyses,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["machine-learning"])


@router.post("/api/v1/ml/models/train", response_model=ModelRead, status_code=201)
def train_anomaly_model(
    request: ModelTrainingRequest,
    db: Session = Depends(get_db),  # noqa: B008
) -> AnomalyModel:
    try:
        validate_training_analyses(db, request.analysis_ids)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from None
    except RuntimeError as error:
        raise HTTPException(
            status_code=409,
            detail={"code": "training_analysis_not_ready", "message": str(error)},
        ) from None

    data = collect_training_data(
        db,
        request.analysis_ids,
        settings.ml_max_training_samples,
        request.random_seed,
    )
    if data.sample_count < MIN_TRAINING_SAMPLES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "insufficient_training_flows",
                "message": (
                    f"At least {MIN_TRAINING_SAMPLES} flows are required; "
                    f"{data.sample_count} were available."
                ),
            },
        )
    if isinstance(request.max_samples, int) and request.max_samples > data.sample_count:
        raise HTTPException(
            status_code=422,
            detail="max_samples cannot exceed the selected training sample count.",
        )
    try:
        pipeline, active_feature_names = train_pipeline(
            data.rows,
            n_estimators=request.n_estimators,
            contamination=request.contamination,
            max_samples=request.max_samples,
            random_seed=request.random_seed,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_training_features", "message": str(error)},
        ) from None

    artifact_key = None
    try:
        record, artifact_key = create_model_record(
            pipeline=pipeline,
            active_feature_names=active_feature_names,
            training_analysis_ids=request.analysis_ids,
            training_sample_count=data.sample_count,
            training_population_count=data.population_count,
            n_estimators=request.n_estimators,
            contamination=request.contamination,
            max_samples=request.max_samples,
            random_seed=request.random_seed,
            storage_dir=settings.model_storage_dir,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as error:
        db.rollback()
        if artifact_key:
            from app.services.ml.artifacts import remove_model_artifact

            remove_model_artifact(settings.model_storage_dir, artifact_key)
        logger.error("Model training persistence failed (%s)", type(error).__name__)
        raise HTTPException(
            status_code=500,
            detail={"code": "model_persistence_failed", "message": "The model was not saved."},
        ) from None


@router.get("/api/v1/ml/models", response_model=ModelList)
def list_models(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),  # noqa: B008
) -> ModelList:
    total = db.scalar(select(func.count(AnomalyModel.id))) or 0
    items = db.scalars(
        select(AnomalyModel).order_by(AnomalyModel.id.desc()).offset(offset).limit(limit)
    ).all()
    return ModelList(items=items, total=total, offset=offset, limit=limit)


@router.get("/api/v1/ml/models/{model_id}", response_model=ModelRead)
def get_model(
    model_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> AnomalyModel:
    model = db.get(AnomalyModel, model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found.")
    return model


@router.post("/api/v1/analyses/{analysis_id}/ml/inference", response_model=InferenceRead)
def infer_analysis(
    request: InferenceRequest,
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> InferenceRead:
    analysis = db.scalar(select(Analysis).where(Analysis.id == analysis_id).with_for_update())
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if analysis.status != "completed" or analysis.flow_generation_status != "completed":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "analysis_not_ready",
                "message": "Complete packet analysis and flow generation before inference.",
            },
        )
    model = db.get(AnomalyModel, request.model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found.")

    existing_count = count_existing_results(db, analysis_id, model.id)
    if existing_count:
        if existing_count != analysis.flow_count:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "inference_results_incomplete",
                    "message": "Stored inference results do not match the analysis flow count.",
                },
            )
        return _inference_summary(db, analysis_id, model, reused=True)

    try:
        pipeline = load_trained_pipeline(model, settings.model_storage_dir)
    except Exception as error:
        logger.error("Model artifact unavailable for model %s (%s)", model.id, type(error).__name__)
        raise HTTPException(
            status_code=409,
            detail={
                "code": "model_artifact_unavailable",
                "message": "The model artifact is unavailable or incompatible; train a new model.",
            },
        ) from None

    try:
        summary = run_inference(
            db,
            analysis_id=analysis_id,
            model=model,
            pipeline=pipeline,
        )
        db.commit()
    except ValueError as error:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail={"code": "inference_features_invalid", "message": str(error)},
        ) from None
    except Exception as error:
        db.rollback()
        logger.error("Inference failed for analysis %s (%s)", analysis_id, type(error).__name__)
        raise HTTPException(
            status_code=500,
            detail={"code": "inference_failed", "message": "Inference did not complete."},
        ) from None
    return InferenceRead(
        analysis_id=analysis_id,
        model_id=model.id,
        model_version=model.model_version,
        result_count=summary.result_count,
        anomaly_count=summary.anomaly_count,
        normal_count=summary.normal_count,
        reused=False,
    )


@router.get("/api/v1/analyses/{analysis_id}/ml/results", response_model=AnomalyResultList)
def list_anomaly_results(
    analysis_id: int = Path(ge=1),
    model_id: int = Query(ge=1),
    prediction: PredictionLabel | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),  # noqa: B008
) -> AnomalyResultList:
    _require_analysis(db, analysis_id)
    model = _require_model(db, model_id)
    query = (
        select(AnomalyResult, NetworkFlow)
        .join(
            NetworkFlow,
            and_(
                NetworkFlow.analysis_id == AnomalyResult.analysis_id,
                NetworkFlow.flow_id == AnomalyResult.flow_id,
            ),
        )
        .where(AnomalyResult.analysis_id == analysis_id, AnomalyResult.model_id == model_id)
    )
    count_query = select(AnomalyResult.id).where(
        AnomalyResult.analysis_id == analysis_id, AnomalyResult.model_id == model_id
    )
    if prediction is not None:
        query = query.where(AnomalyResult.prediction == prediction)
        count_query = count_query.where(AnomalyResult.prediction == prediction)
    total = db.scalar(select(func.count()).select_from(count_query.subquery())) or 0
    rows = db.execute(
        query.order_by(AnomalyResult.anomaly_score.desc(), AnomalyResult.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return AnomalyResultList(
        items=[_result_read(result, flow) for result, flow in rows],
        total=total,
        offset=offset,
        limit=limit,
        model_id=model.id,
        model_version=model.model_version,
    )


@router.get(
    "/api/v1/analyses/{analysis_id}/ml/results/{result_id}", response_model=AnomalyResultRead
)
def get_anomaly_result(
    analysis_id: int = Path(ge=1),
    result_id: int = Path(ge=1),
    model_id: int = Query(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> AnomalyResultRead:
    _require_analysis(db, analysis_id)
    _require_model(db, model_id)
    row = db.execute(
        select(AnomalyResult, NetworkFlow)
        .join(
            NetworkFlow,
            and_(
                NetworkFlow.analysis_id == AnomalyResult.analysis_id,
                NetworkFlow.flow_id == AnomalyResult.flow_id,
            ),
        )
        .where(
            AnomalyResult.analysis_id == analysis_id,
            AnomalyResult.model_id == model_id,
            AnomalyResult.id == result_id,
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Anomaly result not found.")
    return _result_read(*row)


@router.get("/api/v1/analyses/{analysis_id}/ml/summary", response_model=AnomalySummary)
def get_ml_summary(
    analysis_id: int = Path(ge=1),
    model_id: int | None = Query(None, ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> AnomalySummary:
    _require_analysis(db, analysis_id)
    if model_id is None:
        model = db.scalar(
            select(AnomalyModel)
            .join(AnomalyResult, AnomalyResult.model_id == AnomalyModel.id)
            .where(AnomalyResult.analysis_id == analysis_id)
            .order_by(AnomalyModel.id.desc())
            .limit(1)
        )
    else:
        model = _require_model(db, model_id)
    if model is None:
        return AnomalySummary(
            analysis_id=analysis_id,
            model_id=None,
            model_version=None,
            status="not_started",
            result_count=0,
            anomaly_count=0,
            normal_count=0,
        )
    counts = dict(
        db.execute(
            select(AnomalyResult.prediction, func.count(AnomalyResult.id))
            .where(
                AnomalyResult.analysis_id == analysis_id,
                AnomalyResult.model_id == model.id,
            )
            .group_by(AnomalyResult.prediction)
        ).all()
    )
    anomalies = counts.get("anomaly", 0)
    normal = counts.get("normal", 0)
    return AnomalySummary(
        analysis_id=analysis_id,
        model_id=model.id,
        model_version=model.model_version,
        status="completed" if anomalies + normal else "not_started",
        result_count=anomalies + normal,
        anomaly_count=anomalies,
        normal_count=normal,
    )


def _require_analysis(db: Session, analysis_id: int) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


def _require_model(db: Session, model_id: int) -> AnomalyModel:
    model = db.get(AnomalyModel, model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found.")
    return model


def _inference_summary(
    db: Session, analysis_id: int, model: AnomalyModel, *, reused: bool
) -> InferenceRead:
    counts = dict(
        db.execute(
            select(AnomalyResult.prediction, func.count(AnomalyResult.id))
            .where(
                AnomalyResult.analysis_id == analysis_id,
                AnomalyResult.model_id == model.id,
            )
            .group_by(AnomalyResult.prediction)
        ).all()
    )
    anomalies = counts.get("anomaly", 0)
    normal = counts.get("normal", 0)
    return InferenceRead(
        analysis_id=analysis_id,
        model_id=model.id,
        model_version=model.model_version,
        result_count=anomalies + normal,
        anomaly_count=anomalies,
        normal_count=normal,
        reused=reused,
    )


def _result_read(result: AnomalyResult, flow: NetworkFlow) -> AnomalyResultRead:
    return AnomalyResultRead(
        id=result.id,
        model_id=result.model_id,
        model_version=result.model_version,
        analysis_id=result.analysis_id,
        flow_id=result.flow_id,
        prediction=result.prediction,
        anomaly_score=result.anomaly_score,
        created_at=result.created_at,
        flow=FlowReference.model_validate(flow),
    )
