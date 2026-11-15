from collections.abc import Generator
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.analysis import Analysis
from app.models.detection import DetectionFinding, DetectionRun
from app.models.flow import NetworkFlow
from app.services.detection.config import DetectionConfig, SeverityThresholds


@pytest.fixture
def detection_client() -> Generator[TestClient, None, None]:
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

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()


def detection_config() -> DetectionConfig:
    return DetectionConfig(
        port_scan_thresholds=SeverityThresholds(low=3, medium=4, high=5, critical=6),
        syn_flood_thresholds=SeverityThresholds(low=20, medium=22, high=24, critical=28),
        connection_attempts_thresholds=SeverityThresholds(low=5, medium=6, high=7, critical=8),
    )


def seed_completed_analysis(client: TestClient, *, flow_count: int = 6) -> int:
    db = _session(client)
    try:
        analysis = Analysis(
            original_filename="synthetic-rules.pcap",
            storage_key=None,
            file_size_bytes=0,
            capture_format="pcap",
            status="completed",
            packet_count=0,
            flow_generation_status="completed",
            flow_count=flow_count,
            created_at=datetime.now(UTC),
        )
        db.add(analysis)
        db.flush()
        for index in range(flow_count):
            db.add(
                _network_flow(
                    analysis.id,
                    index,
                    destination_port=20_000 + index,
                    forward_syn_only_count=4,
                    backward_syn_only_count=0,
                    forward_syn_ack_count=0,
                    backward_syn_ack_count=1,
                )
            )
        db.commit()
        return analysis.id
    finally:
        db.close()


def _session(client: TestClient) -> Session:
    override = app.dependency_overrides[get_db]
    return next(override())


def _network_flow(
    analysis_id: int,
    index: int,
    *,
    destination_ip: str = "198.51.100.20",
    destination_port: int = 443,
    forward_syn_only_count: int | None = 1,
    backward_syn_only_count: int | None = 0,
    forward_syn_ack_count: int | None = 0,
    backward_syn_ack_count: int | None = 1,
) -> NetworkFlow:
    return NetworkFlow(
        analysis_id=analysis_id,
        flow_id=f"{index + 1:064x}",
        ip_version=4,
        protocol_name="TCP",
        protocol_number=6,
        endpoint_a_ip="192.0.2.10",
        endpoint_a_port=51_500 + index,
        endpoint_b_ip=destination_ip,
        endpoint_b_port=destination_port,
        first_packet_source_ip="192.0.2.10",
        first_packet_source_port=51_500 + index,
        first_packet_destination_ip=destination_ip,
        first_packet_destination_port=destination_port,
        first_timestamp=Decimal("1"),
        last_timestamp=Decimal("2"),
        duration_seconds=Decimal("1"),
        total_packets=2,
        total_bytes=120,
        forward_packets=1,
        backward_packets=1,
        forward_bytes=60,
        backward_bytes=60,
        packet_length_min=60,
        packet_length_max=60,
        packet_length_mean=Decimal("60"),
        packet_length_stddev=Decimal("0"),
        interarrival_min=Decimal("1"),
        interarrival_max=Decimal("1"),
        interarrival_mean=Decimal("1"),
        interarrival_stddev=Decimal("0"),
        syn_count=2,
        ack_count=2,
        fin_count=0,
        rst_count=0,
        psh_count=0,
        urg_count=0,
        forward_syn_only_count=forward_syn_only_count,
        backward_syn_only_count=backward_syn_only_count,
        forward_syn_ack_count=forward_syn_ack_count,
        backward_syn_ack_count=backward_syn_ack_count,
        packets_per_second=Decimal("2"),
        bytes_per_second=Decimal("120"),
    )


def test_detection_run_persists_findings_links_flows_and_is_idempotent(
    detection_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.detections as detection_api

    config = detection_config()
    monkeypatch.setattr(detection_api, "settings", SimpleNamespace(detection_config=config))
    analysis_id = seed_completed_analysis(detection_client)

    first = detection_client.post(f"/api/v1/analyses/{analysis_id}/detections/run")
    repeated = detection_client.post(f"/api/v1/analyses/{analysis_id}/detections/run")
    summary = detection_client.get(f"/api/v1/analyses/{analysis_id}/detection-summary")

    assert first.status_code == repeated.status_code == 200
    assert first.json()["finding_count"] == 3
    assert first.json()["reused"] is False
    assert repeated.json()["reused"] is True
    assert first.json()["id"] == repeated.json()["id"]
    assert summary.json()["finding_count"] == 3
    assert summary.json()["severity_counts"] == {
        "low": 0,
        "medium": 1,
        "high": 1,
        "critical": 1,
    }

    db = _session(detection_client)
    try:
        run_rows = db.scalars(select(DetectionRun)).all()
        finding_rows = db.scalars(select(DetectionFinding)).all()
        assert len(run_rows) == 1
        assert len(finding_rows) == 3
        assert all(row.analysis_id == analysis_id for row in finding_rows)
        assert all(row.supporting_flows for row in finding_rows)
    finally:
        db.close()


def test_findings_pagination_filters_and_detail_endpoint(
    detection_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.detections as detection_api

    monkeypatch.setattr(
        detection_api, "settings", SimpleNamespace(detection_config=detection_config())
    )
    analysis_id = seed_completed_analysis(detection_client)
    run_id = detection_client.post(f"/api/v1/analyses/{analysis_id}/detections/run").json()["id"]

    first_page = detection_client.get(f"/api/v1/analyses/{analysis_id}/findings?limit=1")
    port_scan = detection_client.get(
        f"/api/v1/analyses/{analysis_id}/findings?rule_id=port_scan&severity=critical"
    )
    detail = detection_client.get(
        f"/api/v1/analyses/{analysis_id}/findings/{port_scan.json()['items'][0]['id']}"
    )

    assert first_page.status_code == 200
    assert first_page.json()["total"] == 3
    assert len(first_page.json()["items"]) == 1
    assert first_page.json()["run_id"] == run_id
    assert port_scan.json()["total"] == 1
    finding = port_scan.json()["items"][0]
    assert finding["rule_id"] == "PORT_SCAN"
    assert finding["severity"] == "critical"
    assert finding["supporting_flow_count"] == 6
    assert len(finding["supporting_flows"]) == 6
    assert detail.json()["id"] == finding["id"]
    assert detail.json()["evidence"]["distinct_destination_port_count"] == 6


def test_configuration_change_creates_a_new_versioned_run(
    detection_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.detections as detection_api

    first_config = detection_config()
    monkeypatch.setattr(detection_api, "settings", SimpleNamespace(detection_config=first_config))
    analysis_id = seed_completed_analysis(detection_client)
    first = detection_client.post(f"/api/v1/analyses/{analysis_id}/detections/run").json()

    changed_config = DetectionConfig(
        port_scan_enabled=False,
        syn_flood_enabled=False,
        connection_attempts_enabled=False,
    )
    monkeypatch.setattr(detection_api, "settings", SimpleNamespace(detection_config=changed_config))
    second = detection_client.post(f"/api/v1/analyses/{analysis_id}/detections/run").json()
    latest = detection_client.get(f"/api/v1/analyses/{analysis_id}/detection-summary").json()
    historical = detection_client.get(
        f"/api/v1/analyses/{analysis_id}/findings?run_id={first['id']}"
    ).json()

    assert first["id"] != second["id"]
    assert first["config_hash"] != second["config_hash"]
    assert second["finding_count"] == 0
    assert latest["run_id"] == second["id"]
    assert historical["total"] == 3


def test_analysis_and_flow_readiness_are_validated(detection_client: TestClient) -> None:
    db = _session(detection_client)
    try:
        analysis = Analysis(
            original_filename="pending.pcap",
            file_size_bytes=0,
            capture_format="pcap",
            status="processing",
            packet_count=0,
            flow_generation_status="not_started",
            flow_count=0,
            created_at=datetime.now(UTC),
        )
        db.add(analysis)
        db.commit()
        analysis_id = analysis.id
    finally:
        db.close()

    not_completed = detection_client.post(f"/api/v1/analyses/{analysis_id}/detections/run")
    missing = detection_client.post("/api/v1/analyses/9999/detections/run")
    summary = detection_client.get("/api/v1/analyses/9999/detection-summary")

    assert not_completed.status_code == 409
    assert not_completed.json()["detail"]["code"] == "analysis_not_completed"
    assert missing.status_code == summary.status_code == 404


def test_findings_are_isolated_between_analyses(
    detection_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.detections as detection_api

    monkeypatch.setattr(
        detection_api, "settings", SimpleNamespace(detection_config=detection_config())
    )
    first_analysis = seed_completed_analysis(detection_client)
    second_analysis = seed_completed_analysis(detection_client, flow_count=1)

    first_run = detection_client.post(f"/api/v1/analyses/{first_analysis}/detections/run")
    second_run = detection_client.post(f"/api/v1/analyses/{second_analysis}/detections/run")
    first_findings = detection_client.get(f"/api/v1/analyses/{first_analysis}/findings").json()
    second_findings = detection_client.get(f"/api/v1/analyses/{second_analysis}/findings").json()

    assert first_run.json()["finding_count"] == 3
    assert second_run.json()["finding_count"] == 0
    assert first_findings["total"] == 3
    assert second_findings["total"] == 0


def test_detection_failure_rolls_back_findings_then_records_failure(
    detection_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.services.detection.runner as detection_runner
    from app.services.detection.rules import DetectionCandidate

    analysis_id = seed_completed_analysis(detection_client)

    def fail_after_finding(flows, config):
        del flows, config
        yield DetectionCandidate(
            rule_id="TEST",
            rule_name="Synthetic failure",
            severity="low",
            source_ip="192.0.2.1",
            destination_ip="198.51.100.1",
            protocol_name="TCP",
            explanation="Synthetic test candidate.",
            evidence={},
            supporting_flow_count=0,
            supporting_flow_ids=(),
            supporting_flow_sample_truncated=False,
            finding_key="a" * 64,
        )
        raise RuntimeError("synthetic persistence failure")

    monkeypatch.setattr(detection_runner, "evaluate_rules", fail_after_finding)
    response = detection_client.post(f"/api/v1/analyses/{analysis_id}/detections/run")
    summary = detection_client.get(f"/api/v1/analyses/{analysis_id}/detection-summary").json()
    findings = detection_client.get(f"/api/v1/analyses/{analysis_id}/findings")

    assert response.status_code == 500
    assert response.json()["detail"]["code"] == "detection_failed"
    assert summary["status"] == "failed"
    assert summary["error_message"] == "Detection did not complete."
    assert findings.status_code == 409

    db = _session(detection_client)
    try:
        assert db.scalars(select(DetectionFinding)).all() == []
    finally:
        db.close()


def test_missing_or_unready_runs_produce_consistent_finding_responses(
    detection_client: TestClient,
) -> None:
    analysis_id = seed_completed_analysis(detection_client, flow_count=0)
    summary = detection_client.get(f"/api/v1/analyses/{analysis_id}/detection-summary")
    findings = detection_client.get(f"/api/v1/analyses/{analysis_id}/findings")
    bad_limit = detection_client.get(f"/api/v1/analyses/{analysis_id}/findings?limit=201")
    bad_run = detection_client.get(f"/api/v1/analyses/{analysis_id}/findings?run_id=999")

    assert summary.json()["status"] == "not_started"
    assert findings.json()["items"] == []
    assert bad_limit.status_code == 422
    assert bad_run.status_code == 404


def test_empty_flow_analysis_completes_without_findings(detection_client: TestClient) -> None:
    analysis_id = seed_completed_analysis(detection_client, flow_count=0)

    run = detection_client.post(f"/api/v1/analyses/{analysis_id}/detections/run")
    summary = detection_client.get(f"/api/v1/analyses/{analysis_id}/detection-summary")
    findings = detection_client.get(f"/api/v1/analyses/{analysis_id}/findings")

    assert run.status_code == 200
    assert run.json()["status"] == "completed"
    assert run.json()["finding_count"] == 0
    assert summary.json()["status"] == "completed"
    assert findings.json()["items"] == []
