from __future__ import annotations

import math
import platform
import resource
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import sklearn
from scapy.utils import PcapReader
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401 - import every mapped table into Base.metadata
from app.core.config import settings
from app.db.base import Base
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyModel, AnomalyResult
from app.models.detection import DetectionFinding, DetectionRun
from app.models.packet import PacketRecord
from app.services.detection.config import DetectionConfig, SeverityThresholds
from app.services.detection.runner import execute_run, start_or_reuse_run
from app.services.evaluation.dataset import (
    DATASET_VERSION,
    GENERATION_SEED,
    POSITIVE_LABEL,
    TEST_SAMPLES,
    TRAINING_SAMPLES,
    EvaluationSample,
    write_capture,
)
from app.services.evaluation.metrics import binary_metrics
from app.services.flow_generation import generate_flows
from app.services.hybrid.engine import execute_assessment
from app.services.ml.engine import (
    ALGORITHM_NAME,
    PREPROCESSING_CONFIG,
    collect_training_data,
    create_model_record,
    run_inference,
    train_pipeline,
)
from app.services.ml.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from app.services.packet_metadata import read_packet_metadata

EVALUATION_PIPELINE_VERSION = "evaluation-v1"
REPEAT_MAX = 5


def run_evaluation(*, random_seed: int, repeat_count: int) -> dict[str, Any]:
    if not 0 <= random_seed <= 2_147_483_647:
        raise ValueError("random_seed must be between 0 and 2147483647.")
    if not 1 <= repeat_count <= REPEAT_MAX:
        raise ValueError(f"repeat_count must be between 1 and {REPEAT_MAX}.")

    with TemporaryDirectory(prefix="sentinel-evaluation-") as temporary_root:
        root = Path(temporary_root)
        captures = _generate_captures(root / "pcaps")
        test_capture_bytes = sum(
            captures[sample.sample_id].stat().st_size for sample in TEST_SAMPLES
        )
        test_packet_count = sum(
            _packet_count(captures[sample.sample_id]) for sample in TEST_SAMPLES
        )
        training_packet_count = sum(
            _packet_count(captures[sample.sample_id]) for sample in TRAINING_SAMPLES
        )
        samples_by_repeat: list[list[dict[str, Any]]] = []
        metric_runs: list[dict[str, Any]] = []
        timings: dict[str, list[float]] = defaultdict(list)
        cpu_timings: dict[str, list[float]] = defaultdict(list)
        training_seconds: list[float] = []
        total_test_flows: int | None = None
        training_flow_count: int | None = None
        model_metadata: dict[str, Any] | None = None
        peak_memory_before = _peak_rss_bytes()
        peak_memory_during = peak_memory_before

        for repeat_index in range(repeat_count):
            engine = create_engine(
                "sqlite://",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
            _enable_sqlite_foreign_keys(engine)
            Base.metadata.create_all(engine)
            factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
            try:
                with factory() as db:
                    (
                        sample_results,
                        stage_times,
                        stage_cpu,
                        train_elapsed,
                        repeat_flows,
                        train_flows,
                        model_info,
                    ) = _evaluate_repeat(
                        db,
                        captures=captures,
                        model_storage=root / f"models-{repeat_index}",
                        random_seed=random_seed,
                    )
                samples_by_repeat.append(sample_results)
                metric_runs.append(_calculate_run_metrics(sample_results))
                for stage, seconds in stage_times.items():
                    timings[stage].extend(seconds)
                for stage, seconds in stage_cpu.items():
                    cpu_timings[stage].extend(seconds)
                training_seconds.append(train_elapsed)
                total_test_flows = repeat_flows
                training_flow_count = train_flows
                model_metadata = model_info
                peak_memory_during = max(peak_memory_during, _peak_rss_bytes())
            finally:
                engine.dispose()

        _require_repeatable_outputs(samples_by_repeat)
        first_samples = samples_by_repeat[0]
        final_metrics = metric_runs[0]
        return {
            "evaluation_version": EVALUATION_PIPELINE_VERSION,
            "dataset": {
                "version": DATASET_VERSION,
                "synthetic": True,
                "public_dataset": False,
                "generation_seed": GENERATION_SEED,
                "positive_label": POSITIVE_LABEL,
                "training_sample_count": len(TRAINING_SAMPLES),
                "test_sample_count": len(TEST_SAMPLES),
                "training_sample_ids": [sample.sample_id for sample in TRAINING_SAMPLES],
                "test_sample_ids": [sample.sample_id for sample in TEST_SAMPLES],
                "patterns": _pattern_counts(),
                "train_test_overlap": False,
                "ground_truth_method": "deterministic generator recipe, assigned before detection",
            },
            "methodology": {
                "evaluation_unit": "capture",
                "positive_definition": (
                    "sample recipe is labelled suspicious before engine execution"
                ),
                "negative_definition": "sample recipe is labelled benign before engine execution",
                "rule_only_decision": "at least one finding in the configured rule run",
                "ml_only_decision": "at least one flow receives the trained model's anomaly label",
                "hybrid_decision": (
                    "assessment risk score greater than zero; persisted evidence was scored, "
                    "not that compromise is probable"
                ),
                "hybrid_score_is_probability": False,
                "score_thresholds_tuned_on_test_set": False,
                "training_and_test_sample_ids_disjoint": True,
            },
            "configuration": {
                "configured_rule_detection": settings.detection_config.model_dump(mode="json"),
                "threshold_comparisons": [
                    {
                        "name": "configured",
                        "config": settings.detection_config.model_dump(mode="json"),
                    },
                    {
                        "name": "doubled_thresholds",
                        "description": (
                            "Each configured severity threshold increased twofold, bounded by "
                            "schema limits."
                        ),
                        "config": _stricter_config(settings.detection_config).model_dump(
                            mode="json"
                        ),
                    },
                ],
                "isolation_forest": {
                    "algorithm": ALGORITHM_NAME,
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                    "feature_names": list(FEATURE_NAMES),
                    "preprocessing": PREPROCESSING_CONFIG,
                    "n_estimators": 100,
                    "contamination": 0.1,
                    "max_samples": "auto",
                    "random_state": random_seed,
                    "training_population": "benign training partition only",
                    "fixed_score_thresholds": [0.0, 0.05, 0.1],
                },
                "hybrid_scoring": settings.hybrid_scoring_config.model_dump(mode="json"),
                "repeat_count": repeat_count,
                "evaluation_storage": (
                    "temporary isolated SQLite workspace; production analyses are not written"
                ),
            },
            "model": model_metadata,
            "metrics": final_metrics,
            "rule_category_metrics": _rule_category_results(first_samples),
            "threshold_comparison_metrics": metric_runs[0]["rule_thresholds"],
            "hybrid_severity_distribution": dict(
                sorted(Counter(sample["hybrid_severity"] for sample in first_samples).items())
            ),
            "hybrid_risk_score_distribution": _distribution(
                [sample["hybrid_risk_score"] for sample in first_samples]
            ),
            "anomaly_score_distribution": _anomaly_score_distributions(first_samples),
            "samples": first_samples,
            "performance": {
                "environment": {
                    "platform": platform.platform(),
                    "processor": platform.processor() or "not reported by operating system",
                    "logical_cpu_count": __import__("os").cpu_count(),
                    "python_version": platform.python_version(),
                    "scikit_learn_version": sklearn.__version__,
                    "database_used_for_engine_benchmark": "in-memory SQLite",
                    "production_persistence_database": "MySQL; persistence API time is excluded",
                },
                "training_packet_count": training_packet_count,
                "training_flow_count": training_flow_count,
                "test_packet_count": test_packet_count,
                "test_flow_count": total_test_flows,
                "test_capture_size_bytes": test_capture_bytes,
                "repeat_count": repeat_count,
                "stages": {
                    stage: _timing_summary(values, cpu_timings[stage])
                    for stage, values in sorted(timings.items())
                },
                "model_training_seconds": _timing_summary(training_seconds),
                "end_to_end_packets_per_second": _throughput(
                    test_packet_count * repeat_count, timings["end_to_end_capture_pipeline"]
                ),
                "end_to_end_flows_per_second": _throughput(
                    (total_test_flows or 0) * repeat_count,
                    timings["end_to_end_capture_pipeline"],
                ),
                "process_peak_rss_bytes_before": peak_memory_before,
                "process_peak_rss_bytes_during": peak_memory_during,
                "memory_measurement": (
                    "process maximum resident set size when the platform exposes it; this is a "
                    "process high-water mark, not incremental memory attributable only to "
                    "evaluation"
                    if peak_memory_during is not None
                    else "unavailable on this platform"
                ),
                "timing_scope": (
                    "Repeated end-to-end processing of generated test captures in an isolated "
                    "SQLite workspace. Capture generation, model training, and MySQL result "
                    "reported separately. These synthetic timings are not production benchmarks."
                ),
            },
        }


def _generate_captures(directory: Path) -> dict[str, Path]:
    captures: dict[str, Path] = {}
    for sample in (*TRAINING_SAMPLES, *TEST_SAMPLES):
        capture = directory / f"{sample.sample_id}.pcap"
        write_capture(sample, capture)
        captures[sample.sample_id] = capture
    return captures


def _evaluate_repeat(
    db: Session,
    *,
    captures: dict[str, Path],
    model_storage: Path,
    random_seed: int,
) -> tuple[
    list[dict[str, Any]],
    dict[str, list[float]],
    dict[str, list[float]],
    float,
    int,
    int,
    dict[str, Any],
]:
    wall: dict[str, list[float]] = defaultdict(list)
    cpu: dict[str, list[float]] = defaultdict(list)
    training_ids: list[int] = []
    training_flows: list[int] = []

    for sample in TRAINING_SAMPLES:
        analysis, _, packet_count = _ingest_sample(db, sample, captures[sample.sample_id])
        count, elapsed, cpu_elapsed = _timed(partial(generate_flows, db, analysis.id))
        _mark_flows_ready(db, analysis.id, count)
        wall["training_flow_generation"].append(elapsed)
        cpu["training_flow_generation"].append(cpu_elapsed)
        training_ids.append(analysis.id)
        training_flows.append(count)
        if packet_count == 0 or count == 0:
            raise RuntimeError(f"Training sample {sample.sample_id} produced no packets or flows.")

    training = collect_training_data(db, training_ids, sample_limit=10_000, random_seed=random_seed)
    train_start = time.perf_counter()
    pipeline, active_feature_names = train_pipeline(
        training.rows,
        n_estimators=100,
        contamination=0.1,
        max_samples="auto",
        random_seed=random_seed,
    )
    training_elapsed = time.perf_counter() - train_start
    model, _ = create_model_record(
        pipeline=pipeline,
        active_feature_names=active_feature_names,
        training_analysis_ids=training_ids,
        training_sample_count=training.sample_count,
        training_population_count=training.population_count,
        n_estimators=100,
        contamination=0.1,
        max_samples="auto",
        random_seed=random_seed,
        storage_dir=model_storage,
    )
    model.model_version = str(
        uuid5(
            NAMESPACE_URL,
            f"sentinel-evaluation:{DATASET_VERSION}:{random_seed}:{sklearn.__version__}",
        )
    )
    db.add(model)
    db.flush()
    model_metadata = {
        "model_version": model.model_version,
        "algorithm": model.algorithm,
        "scikit_learn_version": model.sklearn_version,
        "feature_schema_version": model.feature_schema_version,
        "active_feature_names": model.active_feature_names,
        "configuration": model.isolation_forest_config,
        "training_sample_count": model.training_sample_count,
        "training_population_count": model.training_population_count,
        "training_partition_ids": [sample.sample_id for sample in TRAINING_SAMPLES],
    }

    configured = settings.detection_config
    stricter = _stricter_config(configured)
    samples: list[dict[str, Any]] = []
    end_to_end_capture_seconds: list[float] = []
    end_to_end_capture_cpu: list[float] = []
    test_flow_total = 0

    for sample in TEST_SAMPLES:
        complete_start = time.perf_counter()
        complete_cpu_start = time.process_time()
        analysis, parse_seconds, _ = _ingest_sample(db, sample, captures[sample.sample_id])
        wall["packet_parse_and_metadata"].append(parse_seconds[0])
        cpu["packet_parse_and_metadata"].append(parse_seconds[1])

        flow_count, flow_seconds, flow_cpu = _timed(partial(generate_flows, db, analysis.id))
        _mark_flows_ready(db, analysis.id, flow_count)
        wall["flow_generation"].append(flow_seconds)
        cpu["flow_generation"].append(flow_cpu)
        test_flow_total += flow_count

        configured_run, rule_elapsed, rule_cpu = _run_rules(db, analysis.id, configured)
        wall["rule_detection"].append(rule_elapsed)
        cpu["rule_detection"].append(rule_cpu)
        strict_run, strict_elapsed, strict_cpu = _run_rules(db, analysis.id, stricter)
        wall["strict_rule_detection"].append(strict_elapsed)
        cpu["strict_rule_detection"].append(strict_cpu)

        inference_summary, inference_elapsed, inference_cpu = _timed(
            partial(run_inference, db, analysis_id=analysis.id, model=model, pipeline=pipeline)
        )
        db.commit()
        wall["ml_inference"].append(inference_elapsed)
        cpu["ml_inference"].append(inference_cpu)

        hybrid_start = time.perf_counter()
        hybrid_cpu_start = time.process_time()
        current_analysis = db.get(Analysis, analysis.id)
        current_run = db.get(DetectionRun, configured_run.id)
        current_model = db.get(AnomalyModel, model.id)
        if current_analysis is None or current_run is None or current_model is None:
            raise RuntimeError("Isolated evaluation source records were not available.")
        assessment_execution = execute_assessment(
            db,
            analysis=current_analysis,
            detection_run=current_run,
            model=current_model,
            config=settings.hybrid_scoring_config,
        )
        db.commit()
        hybrid_elapsed = time.perf_counter() - hybrid_start
        hybrid_cpu = time.process_time() - hybrid_cpu_start
        wall["hybrid_assessment"].append(hybrid_elapsed)
        cpu["hybrid_assessment"].append(hybrid_cpu)

        rule_ids = sorted(
            db.scalars(
                select(DetectionFinding.rule_id).where(DetectionFinding.run_id == configured_run.id)
            ).all()
        )
        strict_rule_ids = sorted(
            db.scalars(
                select(DetectionFinding.rule_id).where(DetectionFinding.run_id == strict_run.id)
            ).all()
        )
        anomaly_rows = db.scalars(
            select(AnomalyResult).where(AnomalyResult.analysis_id == analysis.id)
        ).all()
        anomalous_count = sum(result.prediction == "anomaly" for result in anomaly_rows)
        max_anomaly_score = max(float(result.anomaly_score) for result in anomaly_rows)
        assessment = assessment_execution.assessment
        risk_score = float(assessment.risk_score)
        samples.append(
            {
                "sample_id": sample.sample_id,
                "traffic_pattern": sample.pattern,
                "ground_truth": sample.ground_truth,
                "expected_rule_ids": list(sample.expected_rule_ids),
                "observed_rule_ids": rule_ids,
                "strict_observed_rule_ids": strict_rule_ids,
                "rule_only_prediction": bool(rule_ids),
                "ml_anomaly_flow_count": anomalous_count,
                "ml_flow_count": inference_summary.result_count,
                "ml_only_prediction": anomalous_count > 0,
                "maximum_flow_anomaly_score": max_anomaly_score,
                "hybrid_risk_score": risk_score,
                "hybrid_severity": assessment.severity,
                "hybrid_prediction": risk_score > 0,
                "hybrid_assessed_evidence_count": (
                    assessment.rule_evidence_count + assessment.ml_anomaly_count
                ),
                "synthetic": True,
            }
        )
        end_to_end_capture_seconds.append(time.perf_counter() - complete_start)
        end_to_end_capture_cpu.append(time.process_time() - complete_cpu_start)

    wall["end_to_end_capture_pipeline"].extend(end_to_end_capture_seconds)
    cpu["end_to_end_capture_pipeline"].extend(end_to_end_capture_cpu)

    return (
        samples,
        wall,
        cpu,
        training_elapsed,
        test_flow_total,
        sum(training_flows),
        model_metadata,
    )


def _ingest_sample(
    db: Session, sample: EvaluationSample, capture_path: Path
) -> tuple[Analysis, tuple[float, float], int]:
    analysis = Analysis(
        original_filename=f"SYNTHETIC-{sample.sample_id}.pcap",
        storage_key=f"evaluation-{sample.sample_id}",
        file_size_bytes=capture_path.stat().st_size,
        capture_format="pcap",
        status="completed",
        packet_count=0,
        completed_at=datetime.now(UTC),
        flow_generation_status="not_started",
        flow_count=0,
    )
    db.add(analysis)
    db.flush()
    parse_start = time.perf_counter()
    parse_cpu_start = time.process_time()
    metadata = list(read_packet_metadata(str(capture_path)))
    parse_elapsed = time.perf_counter() - parse_start
    parse_cpu = time.process_time() - parse_cpu_start
    analysis.packet_count = len(metadata)
    db.add_all(
        [
            PacketRecord(
                analysis_id=analysis.id,
                packet_index=row.packet_index,
                timestamp=row.timestamp,
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                source_port=row.source_port,
                destination_port=row.destination_port,
                network_protocol=row.network_protocol,
                transport_protocol=row.transport_protocol,
                ip_protocol_number=row.ip_protocol_number,
                packet_length=row.packet_length,
                tcp_flags=row.tcp_flags,
                icmp_type=row.icmp_type,
                icmp_code=row.icmp_code,
            )
            for row in metadata
        ]
    )
    db.commit()
    return analysis, (parse_elapsed, parse_cpu), len(metadata)


def _mark_flows_ready(db: Session, analysis_id: int, flow_count: int) -> None:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise RuntimeError("Evaluation analysis record disappeared.")
    analysis.flow_generation_status = "completed"
    analysis.flow_count = flow_count
    analysis.flows_generated_at = datetime.now(UTC)
    db.commit()


def _run_rules(
    db: Session, analysis_id: int, config: DetectionConfig
) -> tuple[DetectionRun, float, float]:
    run, should_execute = start_or_reuse_run(db, analysis_id, config)
    if not should_execute:
        raise RuntimeError("A new isolated evaluation rule run was unexpectedly reused.")
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    execute_run(db, run, config)
    db.commit()
    return run, time.perf_counter() - wall_start, time.process_time() - cpu_start


def _stricter_config(config: DetectionConfig) -> DetectionConfig:
    def doubled(thresholds: SeverityThresholds, maximum: int) -> SeverityThresholds:
        result: list[int] = []
        for index, original in enumerate((thresholds.low, thresholds.medium, thresholds.high)):
            remaining = 4 - index
            value = min(original * 2, maximum - (remaining - 1))
            if result:
                value = max(value, result[-1] + 1)
            result.append(value)
        result.append(min(maximum, max(thresholds.critical * 2, result[-1] + 1)))
        return SeverityThresholds(
            low=result[0], medium=result[1], high=result[2], critical=result[3]
        )

    return config.model_copy(
        update={
            "port_scan_thresholds": doubled(config.port_scan_thresholds, 65_535),
            "syn_flood_thresholds": doubled(config.syn_flood_thresholds, 1_000_000),
            "connection_attempts_thresholds": doubled(
                config.connection_attempts_thresholds, 1_000_000
            ),
        }
    )


def _calculate_run_metrics(samples: list[dict[str, Any]]) -> dict[str, Any]:
    actual = [sample["ground_truth"] == POSITIVE_LABEL for sample in samples]
    configured = {
        "rule_only": [sample["rule_only_prediction"] for sample in samples],
        "ml_only": [sample["ml_only_prediction"] for sample in samples],
        "hybrid": [sample["hybrid_prediction"] for sample in samples],
    }
    threshold_results = {}
    for name, key in (
        ("configured", "observed_rule_ids"),
        ("doubled_thresholds", "strict_observed_rule_ids"),
    ):
        threshold_results[name] = binary_metrics(actual, [bool(sample[key]) for sample in samples])
    ml_score_thresholds = {
        str(threshold): binary_metrics(
            actual,
            [sample["maximum_flow_anomaly_score"] > threshold for sample in samples],
        )
        for threshold in (0.0, 0.05, 0.1)
    }
    return {
        "rule_only": binary_metrics(actual, configured["rule_only"]),
        "ml_only": binary_metrics(actual, configured["ml_only"]),
        "hybrid": binary_metrics(actual, configured["hybrid"]),
        "rule_thresholds": threshold_results,
        "ml_score_thresholds": ml_score_thresholds,
    }


def _rule_category_results(samples: list[dict[str, Any]]) -> dict[str, Any]:
    rule_ids = sorted(
        {rule for sample in samples for rule in sample["expected_rule_ids"]}
        | {rule for sample in samples for rule in sample["observed_rule_ids"]}
        | {rule for sample in samples for rule in sample["strict_observed_rule_ids"]}
    )
    results: dict[str, Any] = {}
    for rule_id in rule_ids:
        actual = [rule_id in sample["expected_rule_ids"] for sample in samples]
        results[rule_id] = {
            "configured": binary_metrics(
                actual, [rule_id in sample["observed_rule_ids"] for sample in samples]
            ),
            "doubled_thresholds": binary_metrics(
                actual, [rule_id in sample["strict_observed_rule_ids"] for sample in samples]
            ),
        }
    return results


def _anomaly_score_distributions(samples: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for sample in samples:
        grouped[sample["ground_truth"]].append(sample["maximum_flow_anomaly_score"])
    return {
        "unit": "maximum raw flow anomaly score per capture",
        "probability": False,
        "by_ground_truth": {
            label: _distribution(values) for label, values in sorted(grouped.items())
        },
    }


def _distribution(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "minimum": None, "median": None, "p90": None, "maximum": None}
    ordered = sorted(float(value) for value in values)
    p90_index = max(0, math.ceil(0.9 * len(ordered)) - 1)
    return {
        "count": len(ordered),
        "minimum": ordered[0],
        "median": statistics.median(ordered),
        "p90": ordered[p90_index],
        "maximum": ordered[-1],
    }


def _timing_summary(
    values: list[float], cpu_values: list[float] | None = None
) -> dict[str, float | int | None]:
    if not values:
        return {"observations": 0, "mean_seconds": None, "median_seconds": None}
    result: dict[str, float | int | None] = {
        "observations": len(values),
        "mean_seconds": statistics.fmean(values),
        "median_seconds": statistics.median(values),
    }
    if cpu_values:
        result["mean_cpu_seconds"] = statistics.fmean(cpu_values)
        result["median_cpu_seconds"] = statistics.median(cpu_values)
    return result


def _throughput(items: int, elapsed_values: list[float]) -> float | None:
    elapsed = sum(elapsed_values)
    return items / elapsed if elapsed > 0 else None


def _pattern_counts() -> dict[str, int]:
    return dict(sorted(Counter(sample.pattern for sample in TEST_SAMPLES).items()))


def _require_repeatable_outputs(repetitions: list[list[dict[str, Any]]]) -> None:
    reference = repetitions[0]
    fields = (
        "sample_id",
        "ground_truth",
        "observed_rule_ids",
        "strict_observed_rule_ids",
        "rule_only_prediction",
        "ml_anomaly_flow_count",
        "ml_only_prediction",
        "maximum_flow_anomaly_score",
        "hybrid_risk_score",
        "hybrid_severity",
        "hybrid_prediction",
    )
    reference_values = [{key: row[key] for key in fields} for row in reference]
    for repetition in repetitions[1:]:
        if [{key: row[key] for key in fields} for row in repetition] != reference_values:
            raise RuntimeError("Repeated evaluation produced non-deterministic predictions.")


def _packet_count(path: Path) -> int:
    count = 0
    with PcapReader(str(path)) as reader:
        for _ in reader:
            count += 1
    return count


def _timed(callback):
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    value = callback()
    return value, time.perf_counter() - wall_start, time.process_time() - cpu_start


def _enable_sqlite_foreign_keys(engine: Engine) -> None:
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _set_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _peak_rss_bytes() -> int | None:
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (AttributeError, OSError):
        return None
    return int(usage if sys.platform == "darwin" else usage * 1024)
