from collections.abc import Generator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyResult
from app.models.flow import NetworkFlow


@pytest.fixture
def ml_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    import app.api.ml as ml_api

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    monkeypatch.setattr(ml_api.settings, "model_storage_dir", tmp_path / "models")
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()


def add_analysis(client: TestClient, name: str, flow_count: int) -> int:
    db = _session(client)
    try:
        analysis = Analysis(
            original_filename=name,
            storage_key=None,
            file_size_bytes=0,
            capture_format="pcap",
            status="completed",
            packet_count=flow_count,
            flow_generation_status="completed",
            flow_count=flow_count,
            created_at=datetime.now(UTC),
        )
        db.add(analysis)
        db.flush()
        for index in range(flow_count):
            db.add(make_flow(analysis.id, index))
        db.commit()
        return analysis.id
    finally:
        db.close()


def make_flow(analysis_id: int, index: int) -> NetworkFlow:
    return NetworkFlow(
        analysis_id=analysis_id,
        flow_id=f"{analysis_id:016x}{index:048x}",
        ip_version=4,
        protocol_name="TCP",
        protocol_number=6,
        endpoint_a_ip="192.0.2.1",
        endpoint_a_port=10_000 + index,
        endpoint_b_ip="198.51.100.2",
        endpoint_b_port=443,
        first_packet_source_ip="192.0.2.1",
        first_packet_source_port=10_000 + index,
        first_packet_destination_ip="198.51.100.2",
        first_packet_destination_port=443,
        first_timestamp=Decimal(index),
        last_timestamp=Decimal(index + 1),
        duration_seconds=Decimal("1") + Decimal(index) / Decimal(10),
        total_packets=2 + index,
        total_bytes=120 + index * 64,
        forward_packets=1 + index,
        backward_packets=1,
        forward_bytes=60 + index * 32,
        backward_bytes=60 + index * 32,
        packet_length_min=60,
        packet_length_max=60 + index,
        packet_length_mean=Decimal(60 + index) / 2 + 30,
        packet_length_stddev=Decimal(index) / 10,
        interarrival_min=Decimal("0.1") + Decimal(index) / Decimal(100),
        interarrival_max=Decimal("0.2") + Decimal(index) / Decimal(100),
        interarrival_mean=Decimal("0.15") + Decimal(index) / Decimal(100),
        interarrival_stddev=Decimal(index) / 100,
        syn_count=1,
        ack_count=1 + index,
        fin_count=0,
        rst_count=0,
        psh_count=0,
        urg_count=0,
        forward_syn_only_count=1,
        backward_syn_only_count=0,
        forward_syn_ack_count=0,
        backward_syn_ack_count=1,
        packets_per_second=Decimal(2 + index),
        bytes_per_second=Decimal(120 + index * 64),
    )


def train(client: TestClient, analysis_id: int) -> dict:
    response = client.post(
        "/api/v1/ml/models/train",
        json={"analysis_ids": [analysis_id], "n_estimators": 50, "random_seed": 17},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_training_versions_models_and_inference_is_idempotent_and_paginated(
    ml_client: TestClient,
) -> None:
    training_analysis = add_analysis(ml_client, "synthetic-training.pcap", 24)
    target_analysis = add_analysis(ml_client, "synthetic-target.pcap", 4)

    model = train(ml_client, training_analysis)
    model_detail = ml_client.get(f"/api/v1/ml/models/{model['id']}")
    models = ml_client.get("/api/v1/ml/models")
    first = ml_client.post(
        f"/api/v1/analyses/{target_analysis}/ml/inference", json={"model_id": model["id"]}
    )
    repeated = ml_client.post(
        f"/api/v1/analyses/{target_analysis}/ml/inference", json={"model_id": model["id"]}
    )
    summary = ml_client.get(f"/api/v1/analyses/{target_analysis}/ml/summary?model_id={model['id']}")
    page = ml_client.get(
        f"/api/v1/analyses/{target_analysis}/ml/results?model_id={model['id']}&limit=2"
    )

    assert model["algorithm"] == "IsolationForest"
    assert model["feature_schema_version"] == "flow-v1"
    assert "artifact_key" not in model
    assert model["training_analysis_ids"] == [training_analysis]
    assert model["training_sample_count"] == model["training_population_count"] == 24
    assert model_detail.status_code == 200
    assert models.json()["total"] == 1
    assert first.status_code == repeated.status_code == 200
    assert first.json()["result_count"] == 4
    assert first.json()["reused"] is False
    assert repeated.json()["reused"] is True
    assert first.json()["model_version"] == model["model_version"]
    assert summary.json()["anomaly_count"] + summary.json()["normal_count"] == 4
    assert page.status_code == 200
    assert page.json()["total"] == 4
    assert len(page.json()["items"]) == 2
    assert all(item["analysis_id"] == target_analysis for item in page.json()["items"])
    assert all(item["model_version"] == model["model_version"] for item in page.json()["items"])

    anomaly_page = ml_client.get(
        f"/api/v1/analyses/{target_analysis}/ml/results?model_id={model['id']}&prediction=anomaly"
    )
    assert anomaly_page.json()["total"] == summary.json()["anomaly_count"]
    result_id = page.json()["items"][0]["id"]
    detail = ml_client.get(
        f"/api/v1/analyses/{target_analysis}/ml/results/{result_id}?model_id={model['id']}"
    )
    assert detail.status_code == 200
    assert detail.json()["flow"]["total_bytes"] > 0

    db = _session(ml_client)
    try:
        assert db.scalar(select(func.count(AnomalyResult.id))) == 4
    finally:
        db.close()


def test_training_rejects_incomplete_and_insufficient_analyses(ml_client: TestClient) -> None:
    incomplete_id = add_analysis(ml_client, "incomplete.pcap", 20)
    db = _session(ml_client)
    try:
        incomplete = db.get(Analysis, incomplete_id)
        assert incomplete is not None
        incomplete.flow_generation_status = "not_started"
        db.commit()
    finally:
        db.close()
    insufficient = add_analysis(ml_client, "small.pcap", 4)

    assert (
        ml_client.post(
            "/api/v1/ml/models/train", json={"analysis_ids": [incomplete_id]}
        ).status_code
        == 409
    )
    response = ml_client.post("/api/v1/ml/models/train", json={"analysis_ids": [insufficient]})
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "insufficient_training_flows"
    assert (
        ml_client.post(
            "/api/v1/ml/models/train", json={"analysis_ids": [insufficient], "contamination": 0.8}
        ).status_code
        == 422
    )


def test_large_training_population_uses_repeatable_bounded_sampling(
    ml_client: TestClient,
) -> None:
    from app.services.ml.engine import collect_training_data

    analysis_id = add_analysis(ml_client, "sampling.pcap", 24)
    db = _session(ml_client)
    try:
        first = collect_training_data(db, [analysis_id], sample_limit=8, random_seed=73)
        second = collect_training_data(db, [analysis_id], sample_limit=8, random_seed=73)
    finally:
        db.close()

    assert first.population_count == 24
    assert first.sample_count == 8
    assert (first.rows == second.rows).all()


def test_retraining_creates_a_distinct_version_and_bad_ids_are_scoped(
    ml_client: TestClient,
) -> None:
    training_analysis = add_analysis(ml_client, "synthetic-training.pcap", 24)
    first = train(ml_client, training_analysis)
    second = train(ml_client, training_analysis)

    assert first["id"] != second["id"]
    assert first["model_version"] != second["model_version"]
    assert ml_client.get("/api/v1/ml/models/99999").status_code == 404
    assert ml_client.get("/api/v1/analyses/99999/ml/summary").status_code == 404
    assert ml_client.get("/api/v1/analyses/0/ml/results?model_id=1").status_code == 422


def test_failed_inference_rolls_back_all_result_rows(
    ml_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.ml as ml_api

    training_analysis = add_analysis(ml_client, "training.pcap", 24)
    target_analysis = add_analysis(ml_client, "target.pcap", 4)
    model = train(ml_client, training_analysis)
    real_inference = ml_api.run_inference

    def fail_after_flush(*args, **kwargs):
        real_inference(*args, **kwargs)
        raise RuntimeError("synthetic persistence failure")

    monkeypatch.setattr(ml_api, "run_inference", fail_after_flush)
    response = ml_client.post(
        f"/api/v1/analyses/{target_analysis}/ml/inference", json={"model_id": model["id"]}
    )
    assert response.status_code == 500

    db = _session(ml_client)
    try:
        assert db.scalar(select(func.count(AnomalyResult.id))) == 0
    finally:
        db.close()


def _session(client: TestClient) -> Session:
    return next(app.dependency_overrides[get_db]())
