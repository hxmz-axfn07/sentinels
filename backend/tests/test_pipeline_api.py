from collections.abc import Generator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyResult
from app.models.flow import NetworkFlow
from app.models.hybrid import HybridAssessment
from app.models.pipeline import PipelineRun, PipelineStageExecution


@pytest.fixture
def pipeline_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(settings, "model_storage_dir", tmp_path / "models")

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()


def test_pipeline_runs_requested_stages_and_reuses_completed_run(
    pipeline_client: TestClient,
) -> None:
    analysis_id = _add_analysis(pipeline_client, with_flow=True)

    response = pipeline_client.post(
        f"/api/v1/analyses/{analysis_id}/pipeline/runs",
        json={"stages": ["flows", "detection"]},
    )

    assert response.status_code == 201, response.text
    first = response.json()
    assert first["status"] == "completed"
    assert first["requested_stages"] == ["flows", "detection"]
    assert [stage["stage"] for stage in first["stages"]] == [
        "flows",
        "detection",
        "inference",
        "hybrid",
    ]
    assert [stage["status"] for stage in first["stages"]] == [
        "completed",
        "completed",
        "skipped",
        "skipped",
    ]
    assert first["stages"][0]["reused"] is True
    assert first["stages"][1]["result_summary"]["finding_count"] == 0

    repeated = pipeline_client.post(
        f"/api/v1/analyses/{analysis_id}/pipeline/runs",
        json={"stages": ["detection", "flows"]},
    )
    assert repeated.status_code == 201, repeated.text
    assert repeated.json()["id"] == first["id"]
    assert repeated.json()["reused_run"] is True
    assert _count_runs(pipeline_client, analysis_id) == 1

    detail = pipeline_client.get(
        f"/api/v1/analyses/{analysis_id}/pipeline/runs/{first['id']}/stages"
    )
    assert detail.status_code == 200
    assert [stage["execution_order"] for stage in detail.json()] == [1, 2, 3, 4]


def test_missing_flow_prerequisite_fails_requested_stage_and_skips_later_stages(
    pipeline_client: TestClient,
) -> None:
    analysis_id = _add_analysis(pipeline_client, with_flow=False)

    response = pipeline_client.post(
        f"/api/v1/analyses/{analysis_id}/pipeline/runs",
        json={"stages": ["detection"]},
    )

    assert response.status_code == 201, response.text
    result = response.json()
    assert result["status"] == "failed"
    assert result["failure_summary"].startswith("detection:")
    assert [stage["status"] for stage in result["stages"]] == [
        "skipped",
        "failed",
        "skipped",
        "skipped",
    ]
    assert result["stages"][1]["requested"] is True
    assert result["stages"][2]["error_summary"] is None
    assert _count_runs(pipeline_client, analysis_id) == 1


def test_model_is_required_and_analysis_isolation_is_enforced(
    pipeline_client: TestClient,
) -> None:
    analysis_id = _add_analysis(pipeline_client, with_flow=True)
    other_analysis_id = _add_analysis(pipeline_client, with_flow=True)

    missing_model = pipeline_client.post(
        f"/api/v1/analyses/{analysis_id}/pipeline/runs",
        json={"stages": ["inference"]},
    )
    assert missing_model.status_code == 422

    missing_analysis = pipeline_client.get(f"/api/v1/analyses/{analysis_id}/pipeline/runs/99999")
    assert missing_analysis.status_code == 404
    assert _count_runs(pipeline_client, analysis_id) == 0
    assert _count_runs(pipeline_client, other_analysis_id) == 0


def test_interrupted_run_is_recovered_before_retry(pipeline_client: TestClient) -> None:
    analysis_id = _add_analysis(pipeline_client, with_flow=True)
    db = _session(pipeline_client)
    try:
        run = PipelineRun(
            analysis_id=analysis_id,
            pipeline_version="pipeline-v1",
            request_hash="f" * 64,
            requested_stages=["flows", "detection"],
            status="running",
        )
        db.add(run)
        db.flush()
        db.add_all(
            [
                PipelineStageExecution(
                    run_id=run.id,
                    analysis_id=analysis_id,
                    stage=name,
                    execution_order=index,
                    requested=name in {"flows", "detection"},
                    status="running" if name == "flows" else "pending",
                    reused=False,
                )
                for index, name in enumerate(("flows", "detection", "inference", "hybrid"), 1)
            ]
        )
        db.commit()
        old_run_id = run.id
    finally:
        db.close()

    retry = pipeline_client.post(
        f"/api/v1/analyses/{analysis_id}/pipeline/runs",
        json={"stages": ["flows", "detection"]},
    )

    assert retry.status_code == 201, retry.text
    assert retry.json()["status"] == "completed"
    old_run = pipeline_client.get(
        f"/api/v1/analyses/{analysis_id}/pipeline/runs/{old_run_id}"
    ).json()
    assert old_run["status"] == "failed"
    assert old_run["stages"][0]["status"] == "failed"
    assert "ended before the stage completed" in old_run["stages"][0]["error_summary"]


def test_complete_pipeline_uses_an_explicit_trained_model_and_persists_each_stage(
    pipeline_client: TestClient,
) -> None:
    training_analysis_id = _add_analysis(pipeline_client, with_flow=True, flow_total=24)
    target_analysis_id = _add_analysis(pipeline_client, with_flow=True)
    training = pipeline_client.post(
        "/api/v1/ml/models/train",
        json={"analysis_ids": [training_analysis_id], "n_estimators": 50, "random_seed": 17},
    )
    assert training.status_code == 201, training.text
    model_id = training.json()["id"]

    response = pipeline_client.post(
        f"/api/v1/analyses/{target_analysis_id}/pipeline/runs",
        json={"stages": ["hybrid", "inference", "detection", "flows"], "model_id": model_id},
    )

    assert response.status_code == 201, response.text
    result = response.json()
    assert result["status"] == "completed"
    assert result["model_id"] == model_id
    assert result["model_version"] == training.json()["model_version"]
    assert result["detection_run_id"] is not None
    assert result["hybrid_assessment_id"] is not None
    assert result["risk_score"] is not None
    assert [stage["stage"] for stage in result["stages"]] == [
        "flows",
        "detection",
        "inference",
        "hybrid",
    ]
    assert [stage["status"] for stage in result["stages"]] == ["completed"] * 4
    assert result["stages"][2]["result_summary"]["model_id"] == model_id

    db = _session(pipeline_client)
    try:
        assert (
            db.scalar(
                select(func.count(AnomalyResult.id)).where(
                    AnomalyResult.analysis_id == target_analysis_id,
                    AnomalyResult.model_id == model_id,
                )
            )
            == 1
        )
        assessment = db.get(HybridAssessment, result["hybrid_assessment_id"])
        assert assessment is not None
        assert assessment.model_id == model_id
        assert assessment.detection_run_id == result["detection_run_id"]
    finally:
        db.close()


def _add_analysis(client: TestClient, *, with_flow: bool, flow_total: int = 1) -> int:
    db = _session(client)
    try:
        analysis = Analysis(
            original_filename="synthetic.pcap",
            storage_key=None,
            file_size_bytes=64,
            capture_format="pcap",
            status="completed",
            packet_count=1,
            flow_generation_status="completed" if with_flow else "not_started",
            flow_count=flow_total if with_flow else 0,
            created_at=datetime.now(UTC),
        )
        db.add(analysis)
        db.flush()
        if with_flow:
            for index in range(flow_total):
                db.add(_flow(analysis.id, index))
        db.commit()
        return analysis.id
    finally:
        db.close()


def _flow(analysis_id: int, index: int) -> NetworkFlow:
    flow_id = f"{analysis_id:032x}{index:032x}"
    packets = index + 1
    byte_count = packets * 60
    return NetworkFlow(
        analysis_id=analysis_id,
        flow_id=flow_id,
        ip_version=4,
        protocol_name="TCP",
        protocol_number=6,
        endpoint_a_ip="192.0.2.1",
        endpoint_a_port=50_000 + index,
        endpoint_b_ip="198.51.100.2",
        endpoint_b_port=443,
        first_packet_source_ip="192.0.2.1",
        first_packet_source_port=50_000 + index,
        first_packet_destination_ip="198.51.100.2",
        first_packet_destination_port=443,
        first_timestamp=Decimal(index),
        last_timestamp=Decimal(index) + Decimal("0.5"),
        duration_seconds=Decimal("0.5"),
        total_packets=packets,
        total_bytes=byte_count,
        forward_packets=packets,
        backward_packets=0,
        forward_bytes=byte_count,
        backward_bytes=0,
        packet_length_min=60,
        packet_length_max=60 + index,
        packet_length_mean=Decimal(60 + index),
        packet_length_stddev=Decimal(index) / Decimal(10),
        interarrival_min=Decimal("0.1"),
        interarrival_max=Decimal("0.2") + Decimal(index) / Decimal(100),
        interarrival_mean=Decimal("0.15"),
        interarrival_stddev=Decimal(index) / Decimal(100),
        syn_count=1,
        ack_count=index,
        fin_count=0,
        rst_count=0,
        psh_count=0,
        urg_count=0,
        forward_syn_only_count=1,
        backward_syn_only_count=0,
        forward_syn_ack_count=0,
        backward_syn_ack_count=0,
        packets_per_second=Decimal(packets) / Decimal("0.5"),
        bytes_per_second=Decimal(byte_count) / Decimal("0.5"),
    )


def _count_runs(client: TestClient, analysis_id: int) -> int:
    db = _session(client)
    try:
        return int(
            db.scalar(
                select(func.count(PipelineRun.id)).where(PipelineRun.analysis_id == analysis_id)
            )
            or 0
        )
    finally:
        db.close()


def _session(client: TestClient) -> Session:
    return next(app.dependency_overrides[get_db]())


def _enable_sqlite_foreign_keys(connection, _record) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
