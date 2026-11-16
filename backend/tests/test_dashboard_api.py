from collections.abc import Generator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.analysis import Analysis
from app.models.detection import DetectionFinding, DetectionRun


@pytest.fixture
def dashboard_client() -> Generator[TestClient, None, None]:
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


def test_overview_uses_real_counts_and_latest_completed_rule_run(
    dashboard_client: TestClient,
) -> None:
    db = _session(dashboard_client)
    try:
        completed = Analysis(
            original_filename="synthetic-completed.pcap",
            storage_key=None,
            file_size_bytes=128,
            capture_format="pcap",
            status="completed",
            packet_count=12,
            flow_generation_status="completed",
            flow_count=4,
            created_at=datetime(2026, 11, 15, tzinfo=UTC),
        )
        processing = Analysis(
            original_filename="synthetic-processing.pcapng",
            storage_key=None,
            file_size_bytes=64,
            capture_format="pcapng",
            status="processing",
            packet_count=0,
            flow_generation_status="not_started",
            flow_count=0,
            created_at=datetime(2026, 11, 16, tzinfo=UTC),
        )
        db.add_all([completed, processing])
        db.flush()
        old_run = DetectionRun(
            analysis_id=completed.id,
            config_hash="a" * 64,
            config_snapshot={},
            status="completed",
            finding_count=1,
        )
        db.add(old_run)
        db.flush()
        db.add(
            DetectionFinding(
                run_id=old_run.id,
                analysis_id=completed.id,
                finding_key="old",
                rule_id="PORT_SCAN",
                rule_name="Port scan",
                severity="critical",
                explanation="Synthetic test evidence.",
                evidence={"distinct_ports": 10},
                supporting_flow_count=1,
            )
        )
        latest_run = DetectionRun(
            analysis_id=completed.id,
            config_hash="b" * 64,
            config_snapshot={},
            status="completed",
            finding_count=2,
        )
        db.add(latest_run)
        db.flush()
        db.add(
            DetectionFinding(
                run_id=latest_run.id,
                analysis_id=completed.id,
                finding_key="latest",
                rule_id="SYN_ACTIVITY",
                rule_name="SYN activity",
                severity="high",
                explanation="Synthetic test evidence.",
                evidence={"syn_only": 8},
                supporting_flow_count=1,
            )
        )
        db.commit()
    finally:
        db.close()

    response = dashboard_client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200, response.text
    overview = response.json()
    assert overview["analysis_count"] == 2
    assert overview["completed_analysis_count"] == 1
    assert overview["packet_count"] == 12
    assert overview["flow_count"] == 4
    assert overview["rule_finding_count"] == 1
    assert overview["high_priority_finding_count"] == 1
    assert overview["recent_high_priority_findings"][0]["rule_id"] == "SYN_ACTIVITY"
    assert overview["severity_counts"]["critical"] == 0
    recent = {item["original_filename"]: item for item in overview["recent_analyses"]}
    assert recent["synthetic-completed.pcap"]["finding_count"] == 2
    assert recent["synthetic-processing.pcapng"]["status"] == "processing"

    history_response = dashboard_client.get("/api/v1/dashboard/analyses?offset=1&limit=1")
    assert history_response.status_code == 200, history_response.text
    history = history_response.json()
    assert (history["total"], history["offset"], history["limit"]) == (2, 1, 1)
    item = history["items"][0]
    assert item["original_filename"] == "synthetic-completed.pcap"
    assert item["file_size_bytes"] == 128
    assert item["detection_status"] == "completed"
    assert item["finding_count"] == 2
    assert item["ml_status"] == "not_started"
    assert item["hybrid_status"] == "not_started"


def test_empty_overview_returns_empty_persisted_totals(dashboard_client: TestClient) -> None:
    response = dashboard_client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    assert response.json()["analysis_count"] == 0
    assert response.json()["protocol_distribution"] == []
    assert response.json()["recent_high_priority_findings"] == []
    assert response.json()["severity_counts"] == {
        "informational": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }


def _session(client: TestClient) -> Session:
    override = app.dependency_overrides[get_db]
    generator = override()
    return next(generator)


def _enable_sqlite_foreign_keys(connection, _record) -> None:
    connection.execute("PRAGMA foreign_keys=ON")
