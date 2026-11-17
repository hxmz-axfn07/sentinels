from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.services.evaluation.dataset import (
    SAMPLES,
    TEST_SAMPLES,
    TRAINING_SAMPLES,
    dataset_manifest,
    write_capture,
)
from app.services.evaluation.metrics import binary_metrics
from app.services.evaluation.runner import run_evaluation


@pytest.fixture
def evaluation_client() -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()


def test_dataset_labels_and_train_test_partition_are_stable(tmp_path: Path) -> None:
    manifest = dataset_manifest()
    assert manifest == dataset_manifest()
    assert len(SAMPLES) == 43
    assert len(TRAINING_SAMPLES) == 16
    assert len(TEST_SAMPLES) == 27
    assert not (
        {sample.sample_id for sample in TRAINING_SAMPLES}
        & {sample.sample_id for sample in TEST_SAMPLES}
    )
    assert all(sample.ground_truth in {"benign", "suspicious"} for sample in SAMPLES)
    assert all(
        sample.split == "train" and sample.ground_truth == "benign" for sample in TRAINING_SAMPLES
    )
    assert any(sample.pattern == "normal_icmp" for sample in TEST_SAMPLES)
    assert any(sample.pattern == "incomplete_metadata" for sample in TEST_SAMPLES)
    sample = TEST_SAMPLES[0]
    first = tmp_path / "first.pcap"
    second = tmp_path / "second.pcap"
    assert write_capture(sample, first) == write_capture(sample, second)
    assert first.read_bytes() == second.read_bytes()


def test_binary_metrics_and_undefined_denominators() -> None:
    result = binary_metrics([False, False, True, True], [False, True, True, False])
    assert result["confusion_matrix"] == [[1, 1], [1, 1]]
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1_score"] == 0.5
    assert result["false_positive_rate"] == 0.5
    empty = binary_metrics([False], [False])
    assert empty["precision"] is None
    assert empty["recall"] is None
    assert empty["f1_score"] is None


def test_real_engines_run_on_disjoint_synthetic_test_partition() -> None:
    result = run_evaluation(random_seed=1101, repeat_count=1)
    assert result["dataset"]["synthetic"] is True
    assert result["dataset"]["train_test_overlap"] is False
    assert result["dataset"]["test_sample_count"] == 27
    assert set(result["metrics"]) >= {"rule_only", "ml_only", "hybrid"}
    assert all(sample["synthetic"] for sample in result["samples"])
    assert result["methodology"]["hybrid_score_is_probability"] is False
    assert result["performance"]["stages"]["end_to_end_capture_pipeline"]["observations"] == len(
        TEST_SAMPLES
    )


def test_evaluation_api_persists_results_and_validates_requests(
    evaluation_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api import evaluations

    monkeypatch.setattr(
        evaluations,
        "run_evaluation",
        lambda **kwargs: {
            "dataset": {"synthetic": True},
            "metrics": {"rule_only": {"f1_score": 0.5}},
            "configuration": {"repeat_count": kwargs["repeat_count"]},
        },
    )
    invalid = evaluation_client.post(
        "/api/v1/evaluations", json={"random_seed": -1, "repeat_count": 8}
    )
    assert invalid.status_code == 422

    created = evaluation_client.post(
        "/api/v1/evaluations", json={"random_seed": 1101, "repeat_count": 2}
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["status"] == "completed"
    assert body["results"]["dataset"]["synthetic"] is True
    listed = evaluation_client.get("/api/v1/evaluations?offset=0&limit=10")
    assert listed.json()["total"] == 1
    assert "results" not in listed.json()["items"][0]
    detail = evaluation_client.get(f"/api/v1/evaluations/{body['id']}")
    assert detail.json()["results"] == body["results"]
    assert evaluation_client.get("/api/v1/evaluations/9999").status_code == 404

    monkeypatch.setattr(
        evaluations,
        "run_evaluation",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("private failure detail")),
    )
    failed = evaluation_client.post("/api/v1/evaluations", json={})
    assert failed.status_code == 201
    assert failed.json()["status"] == "failed"
    assert "private failure detail" not in failed.text
    assert failed.json()["failure_summary"] == ("Evaluation failed. Review server logs and retry.")


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
