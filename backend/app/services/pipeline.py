from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyModel, AnomalyResult
from app.models.detection import DetectionRun
from app.models.flow import NetworkFlow
from app.models.packet import PacketRecord
from app.models.pipeline import PipelineRun, PipelineStageExecution
from app.schemas.pipeline import PipelineRunRequest
from app.services.detection.runner import (
    configuration_hash,
    execute_run,
    mark_run_failed,
    start_or_reuse_run,
)
from app.services.flow_generation import generate_flows
from app.services.hybrid.engine import HybridInputError, execute_assessment, scoring_config_hash
from app.services.ml.engine import (
    count_existing_results,
    load_trained_pipeline,
    run_inference,
)

logger = logging.getLogger(__name__)
PIPELINE_VERSION = "pipeline-v1"
STAGE_ORDER = ("flows", "detection", "inference", "hybrid")


class PipelineFailure(Exception):
    def __init__(self, code: str, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def execute_pipeline(
    db: Session, analysis_id: int, request: PipelineRunRequest
) -> tuple[PipelineRun, bool]:
    lock_name = f"sentinel_pipeline_{analysis_id}"
    if db.bind is not None and db.bind.dialect.name == "mysql":
        acquired = db.scalar(text("SELECT GET_LOCK(:name, 0)"), {"name": lock_name})
        if acquired != 1:
            raise PipelineFailure(
                "pipeline_in_progress", "Another pipeline run is already active for this analysis."
            )
    try:
        _fail_interrupted_runs(db, analysis_id)
        return _execute_pipeline_locked(db, analysis_id, request)
    finally:
        if db.bind is not None and db.bind.dialect.name == "mysql":
            try:
                db.scalar(text("SELECT RELEASE_LOCK(:name)"), {"name": lock_name})
            except Exception:
                logger.warning("Could not release pipeline lock for analysis %s", analysis_id)


def _execute_pipeline_locked(
    db: Session, analysis_id: int, request: PipelineRunRequest
) -> tuple[PipelineRun, bool]:
    analysis = db.scalar(select(Analysis).where(Analysis.id == analysis_id).with_for_update())
    if analysis is None:
        raise PipelineFailure("analysis_not_found", "Analysis not found.", 404)
    if analysis.status != "completed":
        raise PipelineFailure(
            "analysis_not_completed", "Pipeline processing requires a completed capture analysis."
        )

    stages = [stage for stage in STAGE_ORDER if stage in request.stages]
    model = _selected_model(db, request.model_id) if request.model_id is not None else None
    selected_run = (
        _selected_detection_run(db, analysis_id, request.detection_run_id)
        if request.detection_run_id is not None
        else None
    )
    request_hash = _request_hash(stages, model, selected_run)

    existing = db.scalar(
        select(PipelineRun)
        .options(selectinload(PipelineRun.stages))
        .where(
            PipelineRun.analysis_id == analysis_id,
            PipelineRun.request_hash == request_hash,
            PipelineRun.status == "completed",
        )
        .order_by(PipelineRun.id.desc())
    )
    if existing is not None:
        return existing, True
    active = db.scalar(
        select(PipelineRun.id).where(
            PipelineRun.analysis_id == analysis_id, PipelineRun.status == "running"
        )
    )
    if active is not None:
        raise PipelineFailure(
            "pipeline_in_progress", "Another pipeline run is already active for this analysis."
        )

    run = PipelineRun(
        analysis_id=analysis_id,
        pipeline_version=PIPELINE_VERSION,
        request_hash=request_hash,
        requested_stages=stages,
        model_id=model.id if model else None,
        model_version=model.model_version if model else None,
        detection_run_id=selected_run.id if selected_run else None,
        status="running",
    )
    db.add(run)
    db.flush()
    stage_rows = {
        stage_name: PipelineStageExecution(
            run_id=run.id,
            analysis_id=analysis_id,
            stage=stage_name,
            execution_order=index,
            requested=stage_name in stages,
            status="pending" if stage_name in stages else "skipped",
            reused=False,
            result_summary=None,
        )
        for index, stage_name in enumerate(STAGE_ORDER, start=1)
    }
    db.add_all(stage_rows.values())
    db.commit()

    selected_detection_run = selected_run
    failed_stage = "flows"
    try:
        if "flows" in stages:
            _run_flow_stage(db, run, stage_rows["flows"])
        elif _needs_flows(stages):
            _record_existing_flow_prerequisite(db, run, stage_rows["flows"])

        failed_stage = "detection"
        if "detection" in stages:
            selected_detection_run = _run_detection_stage(db, run, stage_rows["detection"])
        elif "hybrid" in stages:
            _record_existing_detection_prerequisite(
                db, run, stage_rows["detection"], selected_detection_run
            )

        failed_stage = "inference"
        if "inference" in stages:
            assert model is not None
            _run_inference_stage(db, run, stage_rows["inference"], model)
        elif "hybrid" in stages:
            assert model is not None
            _record_existing_inference_prerequisite(db, run, stage_rows["inference"], model)

        failed_stage = "hybrid"
        if "hybrid" in stages:
            assert model is not None and selected_detection_run is not None
            _run_hybrid_stage(
                db,
                run,
                stage_rows["hybrid"],
                selected_detection_run,
                model,
            )

        run.status = "completed"
        run.completed_at = _now()
        db.commit()
    except PipelineFailure as error:
        _fail_run(db, run, stage_rows, error, failed_stage)
    except Exception as error:
        logger.error("Pipeline %s failed (%s)", run.id, type(error).__name__)
        _fail_run(
            db,
            run,
            stage_rows,
            PipelineFailure("stage_failed", "The requested pipeline stage did not complete."),
            failed_stage,
        )

    completed_run = _load_run(db, analysis_id, run.id)
    if completed_run is None:
        raise RuntimeError("Persisted pipeline run could not be reloaded.")
    return completed_run, False


def _fail_interrupted_runs(db: Session, analysis_id: int) -> None:
    """Recover runs left active after their process ended; MySQL locks exclude live runs."""
    interrupted = db.scalars(
        select(PipelineRun)
        .options(selectinload(PipelineRun.stages))
        .where(PipelineRun.analysis_id == analysis_id, PipelineRun.status == "running")
    ).all()
    for run in interrupted:
        active_stage = next((stage for stage in run.stages if stage.status == "running"), None)
        if active_stage is None:
            active_stage = next(
                (stage for stage in run.stages if stage.requested and stage.status == "pending"),
                None,
            )
        if active_stage is not None:
            active_stage.status = "failed"
            active_stage.error_summary = "Execution ended before the stage completed."
            active_stage.completed_at = _now()
        failed_order = active_stage.execution_order if active_stage is not None else 0
        for stage in run.stages:
            if stage.status == "pending" and stage.execution_order > failed_order:
                stage.status = "skipped"
                stage.error_summary = "Skipped because execution ended during an earlier stage."
                stage.completed_at = _now()
        run.status = "failed"
        run.failure_summary = "Pipeline execution ended before a final status was recorded."
        run.completed_at = _now()
    if interrupted:
        db.commit()


def get_pipeline_run(db: Session, analysis_id: int, run_id: int) -> PipelineRun:
    run = _load_run(db, analysis_id, run_id)
    if run is None:
        raise PipelineFailure("pipeline_run_not_found", "Pipeline run not found.", 404)
    return run


def _run_flow_stage(db: Session, run: PipelineRun, stage: PipelineStageExecution) -> None:
    analysis = db.get(Analysis, run.analysis_id)
    if analysis is None:
        raise PipelineFailure("analysis_not_found", "Analysis not found.", 404)
    if analysis.flow_generation_status == "completed":
        _validate_completed_flows(db, analysis)
        _complete_stage(
            db,
            stage,
            {"flow_count": analysis.flow_count},
            reused=True,
        )
        return
    if analysis.flow_generation_status == "processing":
        raise PipelineFailure("flow_generation_in_progress", "Flow generation is already running.")
    packet_count = (
        db.scalar(
            select(func.count(PacketRecord.id)).where(PacketRecord.analysis_id == analysis.id)
        )
        or 0
    )
    if packet_count != analysis.packet_count:
        raise PipelineFailure(
            "packet_metadata_inconsistent",
            "Persisted packet metadata does not match the completed analysis count.",
        )

    _start_stage(db, stage)
    analysis.flow_generation_status = "processing"
    analysis.flow_error_message = None
    db.commit()
    try:
        flow_count = generate_flows(db, analysis.id)
        analysis = db.get(Analysis, run.analysis_id)
        if analysis is None:
            raise RuntimeError("Analysis disappeared during flow generation.")
        analysis.flow_generation_status = "completed"
        analysis.flow_count = flow_count
        analysis.flow_error_message = None
        analysis.flows_generated_at = _now()
        db.flush()
        _complete_stage(db, stage, {"flow_count": flow_count}, reused=False, commit=False)
        db.commit()
    except Exception as error:
        db.rollback()
        logger.error("Pipeline flow stage failed (%s)", type(error).__name__)
        raise PipelineFailure("flow_generation_failed", "Flow generation failed.") from None


def _record_existing_flow_prerequisite(
    db: Session, run: PipelineRun, stage: PipelineStageExecution
) -> None:
    analysis = db.get(Analysis, run.analysis_id)
    if analysis is None or analysis.flow_generation_status != "completed":
        raise PipelineFailure(
            "flows_not_ready", "Generate flows before requesting dependent stages."
        )
    _validate_completed_flows(db, analysis)
    _complete_stage(db, stage, {"flow_count": analysis.flow_count}, reused=True)


def _run_detection_stage(
    db: Session, run: PipelineRun, stage: PipelineStageExecution
) -> DetectionRun:
    analysis = db.get(Analysis, run.analysis_id)
    if analysis is None or analysis.flow_generation_status != "completed":
        raise PipelineFailure("flows_not_ready", "Generate flows before rule detection.")
    _validate_completed_flows(db, analysis)
    active = db.scalar(
        select(DetectionRun.id).where(
            DetectionRun.analysis_id == analysis.id, DetectionRun.status == "processing"
        )
    )
    if active is not None:
        raise PipelineFailure("detection_in_progress", "Rule detection is already running.")

    _start_stage(db, stage)
    detection_run, should_execute = start_or_reuse_run(db, analysis.id, settings.detection_config)
    run.detection_run_id = detection_run.id
    if not should_execute:
        _complete_stage(
            db,
            stage,
            {"detection_run_id": detection_run.id, "finding_count": detection_run.finding_count},
            reused=True,
        )
        return detection_run
    db.commit()
    try:
        execute_run(db, detection_run, settings.detection_config)
        _complete_stage(
            db,
            stage,
            {"detection_run_id": detection_run.id, "finding_count": detection_run.finding_count},
            reused=False,
            commit=False,
        )
        db.commit()
    except Exception as error:
        db.rollback()
        mark_run_failed(db, detection_run.id)
        logger.error("Pipeline rule stage failed (%s)", type(error).__name__)
        raise PipelineFailure("detection_failed", "Rule detection did not complete.") from None
    return detection_run


def _record_existing_detection_prerequisite(
    db: Session,
    run: PipelineRun,
    stage: PipelineStageExecution,
    detection_run: DetectionRun | None,
) -> None:
    if detection_run is None or detection_run.status != "completed":
        raise PipelineFailure(
            "detection_run_required", "Select a completed rule run before hybrid assessment."
        )
    if detection_run.finding_count != _finding_count(db, detection_run.id):
        raise PipelineFailure(
            "detection_results_inconsistent", "Selected rule results are incomplete."
        )
    run.detection_run_id = detection_run.id
    _complete_stage(
        db,
        stage,
        {"detection_run_id": detection_run.id, "finding_count": detection_run.finding_count},
        reused=True,
    )


def _run_inference_stage(
    db: Session, run: PipelineRun, stage: PipelineStageExecution, model: AnomalyModel
) -> None:
    analysis = db.get(Analysis, run.analysis_id)
    if analysis is None or analysis.flow_generation_status != "completed":
        raise PipelineFailure("flows_not_ready", "Generate flows before ML inference.")
    if analysis.flow_count <= 0:
        raise PipelineFailure("analysis_has_no_flows", "ML inference requires at least one flow.")
    _start_stage(db, stage)
    existing_count = count_existing_results(db, analysis.id, model.id)
    if existing_count:
        if existing_count != analysis.flow_count:
            raise PipelineFailure(
                "inference_results_incomplete",
                "Stored inference results do not match the analysis flow count.",
            )
        counts = _inference_counts(db, analysis.id, model.id)
        _complete_stage(
            db,
            stage,
            {
                "model_id": model.id,
                "model_version": model.model_version,
                **counts,
            },
            reused=True,
        )
        return
    try:
        pipeline = load_trained_pipeline(model, settings.model_storage_dir)
        result = run_inference(db, analysis_id=analysis.id, model=model, pipeline=pipeline)
        summary = {
            "model_id": model.id,
            "model_version": model.model_version,
            "result_count": result.result_count,
            "anomaly_count": result.anomaly_count,
            "normal_count": result.normal_count,
        }
        db.flush()
        _complete_stage(db, stage, summary, reused=False, commit=False)
        db.commit()
    except Exception as error:
        db.rollback()
        logger.error("Pipeline inference stage failed (%s)", type(error).__name__)
        raise PipelineFailure("inference_failed", "ML inference did not complete.") from None


def _record_existing_inference_prerequisite(
    db: Session,
    run: PipelineRun,
    stage: PipelineStageExecution,
    model: AnomalyModel,
) -> None:
    analysis = db.get(Analysis, run.analysis_id)
    if (
        analysis is None
        or analysis.flow_generation_status != "completed"
        or analysis.flow_count <= 0
    ):
        raise PipelineFailure("flows_not_ready", "Generate flows before hybrid assessment.")
    result_count = count_existing_results(db, analysis.id, model.id)
    if result_count != analysis.flow_count:
        raise PipelineFailure(
            "inference_results_incomplete",
            "Run inference for every flow with the selected model before hybrid assessment.",
        )
    run.model_id = model.id
    run.model_version = model.model_version
    _complete_stage(
        db,
        stage,
        {
            "model_id": model.id,
            "model_version": model.model_version,
            **_inference_counts(db, analysis.id, model.id),
        },
        reused=True,
    )


def _run_hybrid_stage(
    db: Session,
    run: PipelineRun,
    stage: PipelineStageExecution,
    detection_run: DetectionRun,
    model: AnomalyModel,
) -> None:
    _start_stage(db, stage)
    try:
        analysis = db.get(Analysis, run.analysis_id)
        if analysis is None:
            raise PipelineFailure("analysis_not_found", "Analysis not found.", 404)
        result = execute_assessment(
            db,
            analysis=analysis,
            detection_run=detection_run,
            model=model,
            config=settings.hybrid_scoring_config,
        )
        assessment = result.assessment
        run.detection_run_id = detection_run.id
        run.hybrid_assessment_id = assessment.id
        _complete_stage(
            db,
            stage,
            {
                "assessment_id": assessment.id,
                "risk_score": str(assessment.risk_score),
                "severity": assessment.severity,
                "risk_group_count": assessment.risk_group_count,
                "detection_run_id": detection_run.id,
                "model_id": model.id,
                "model_version": model.model_version,
            },
            reused=result.reused,
            commit=False,
        )
        db.commit()
    except PipelineFailure:
        db.rollback()
        raise
    except HybridInputError as error:
        db.rollback()
        raise PipelineFailure(error.code, str(error), error.status_code) from None
    except Exception as error:
        db.rollback()
        logger.error("Pipeline hybrid stage failed (%s)", type(error).__name__)
        raise PipelineFailure(
            "hybrid_assessment_failed", "Hybrid assessment did not complete."
        ) from None


def _start_stage(db: Session, stage: PipelineStageExecution) -> None:
    stage.status = "running"
    stage.started_at = _now()
    stage.completed_at = None
    stage.error_summary = None
    db.commit()


def _complete_stage(
    db: Session,
    stage: PipelineStageExecution,
    result: dict[str, object],
    *,
    reused: bool,
    commit: bool = True,
) -> None:
    stage.status = "completed"
    stage.reused = reused
    stage.result_summary = result
    stage.error_summary = None
    stage.started_at = stage.started_at or _now()
    stage.completed_at = _now()
    if commit:
        db.commit()


def _fail_run(
    db: Session,
    run: PipelineRun,
    stages: dict[str, PipelineStageExecution],
    error: PipelineFailure,
    failed_stage: str,
) -> None:
    db.rollback()
    run = db.get(PipelineRun, run.id)
    if run is None:
        return
    if not stages[failed_stage].requested:
        failed_stage = next(
            (
                name
                for name in STAGE_ORDER
                if stages[name].requested and stages[name].status in {"pending", "running"}
            ),
            next(name for name in reversed(STAGE_ORDER) if stages[name].requested),
        )
    stage = stages[failed_stage]
    stage.status = "failed"
    stage.error_summary = str(error)
    stage.started_at = stage.started_at or _now()
    stage.completed_at = _now()
    if failed_stage == "flows" and error.code == "flow_generation_failed":
        analysis = db.get(Analysis, run.analysis_id)
        if analysis is not None:
            analysis.flow_generation_status = "failed"
            analysis.flow_count = 0
            analysis.flow_error_message = "Flow generation did not complete."
            analysis.flows_generated_at = None
    failed_order = stage.execution_order
    for remaining in stages.values():
        if remaining.status == "pending" and remaining.execution_order > failed_order:
            remaining.status = "skipped"
            remaining.error_summary = "Skipped because an earlier prerequisite failed."
            remaining.completed_at = _now()
    run.status = "failed"
    run.failure_summary = f"{stage.stage}: {error}"
    run.completed_at = _now()
    db.commit()


def _selected_model(db: Session, model_id: int | None) -> AnomalyModel | None:
    if model_id is None:
        return None
    model = db.get(AnomalyModel, model_id)
    if model is None:
        raise PipelineFailure("model_not_found", "Selected model was not found.", 404)
    if model.status != "ready":
        raise PipelineFailure("model_not_ready", "Selected model is not ready for inference.")
    return model


def _selected_detection_run(
    db: Session, analysis_id: int, run_id: int | None
) -> DetectionRun | None:
    if run_id is None:
        return None
    run = db.get(DetectionRun, run_id)
    if run is None or run.analysis_id != analysis_id:
        raise PipelineFailure("detection_run_not_found", "Selected rule run was not found.", 404)
    if run.status != "completed":
        raise PipelineFailure("detection_run_not_ready", "Selected rule run is not completed.")
    return run


def _needs_flows(stages: list[str]) -> bool:
    return any(stage in stages for stage in ("detection", "inference", "hybrid"))


def _request_hash(
    stages: list[str], model: AnomalyModel | None, detection_run: DetectionRun | None
) -> str:
    value = {
        "pipeline_version": PIPELINE_VERSION,
        "stages": stages,
        "model_id": model.id if model else None,
        "model_version": model.model_version if model else None,
        "selected_detection_run_id": detection_run.id if detection_run else None,
        "detection_config_hash": (
            configuration_hash(settings.detection_config) if "detection" in stages else None
        ),
        "hybrid_config_hash": (
            scoring_config_hash(settings.hybrid_scoring_config) if "hybrid" in stages else None
        ),
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _inference_counts(db: Session, analysis_id: int, model_id: int) -> dict[str, int]:
    rows = db.execute(
        select(AnomalyResult.prediction, func.count(AnomalyResult.id))
        .where(AnomalyResult.analysis_id == analysis_id, AnomalyResult.model_id == model_id)
        .group_by(AnomalyResult.prediction)
    ).all()
    result = {"result_count": 0, "anomaly_count": 0, "normal_count": 0}
    for prediction, count in rows:
        result["result_count"] += count
        result[f"{prediction}_count"] = count
    return result


def _finding_count(db: Session, run_id: int) -> int:
    from app.models.detection import DetectionFinding

    return int(
        db.scalar(select(func.count(DetectionFinding.id)).where(DetectionFinding.run_id == run_id))
        or 0
    )


def _validate_completed_flows(db: Session, analysis: Analysis) -> None:
    actual_count = int(
        db.scalar(select(func.count(NetworkFlow.id)).where(NetworkFlow.analysis_id == analysis.id))
        or 0
    )
    if actual_count != analysis.flow_count:
        raise PipelineFailure(
            "flow_records_inconsistent", "Persisted flow records do not match the analysis count."
        )


def _load_run(db: Session, analysis_id: int, run_id: int) -> PipelineRun | None:
    return db.scalar(
        select(PipelineRun)
        .options(selectinload(PipelineRun.stages))
        .where(PipelineRun.analysis_id == analysis_id, PipelineRun.id == run_id)
    )


def _now() -> datetime:
    return datetime.now(UTC)
