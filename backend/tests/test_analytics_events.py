from collections.abc import Generator
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyModel, AnomalyResult
from app.models.detection import DetectionFinding, DetectionRun
from app.models.flow import NetworkFlow
from app.models.hybrid import HybridAssessment
from app.models.packet import PacketRecord


@pytest.fixture
def analytics_client() -> Generator[TestClient, None, None]:
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


def test_traffic_analytics_uses_capture_timestamps_and_persisted_metadata(
    analytics_client: TestClient,
) -> None:
    analysis_id = _seed(analytics_client)
    response = analytics_client.get(f"/api/v1/analytics/traffic/{analysis_id}")
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["packet_count"] == 4
    assert result["total_bytes"] == 420
    assert result["flow_count"] == 2
    assert result["timestamped_packet_count"] == 3
    assert result["unavailable_timestamp_packet_count"] == 1
    assert result["packets_per_second"] is None
    assert result["bytes_per_second"] is None
    assert result["duration_seconds"] == 4
    assert sum(point["packet_count"] for point in result["timeline"]) == 3
    assert sum(item["packet_count"] for item in result["protocols"]) == 4
    protocol_counts = {item["protocol"]: item["packet_count"] for item in result["protocols"]}
    assert protocol_counts == {"TCP": 2, "UDP": 1, "ICMP": 1}
    assert result["forward_packets"] == 3
    assert result["backward_packets"] == 1
    assert result["top_flows_by_bytes"][0]["flow_id"] == "a" * 64


def test_identical_packet_timestamps_produce_one_observed_bucket(
    analytics_client: TestClient,
) -> None:
    analysis_id = _seed(analytics_client)
    db = _session(analytics_client)
    try:
        packets = db.query(PacketRecord).filter_by(analysis_id=analysis_id).all()
        for packet in packets:
            packet.timestamp = Decimal("200")
        db.commit()
    finally:
        db.close()
    result = analytics_client.get(f"/api/v1/analytics/traffic/{analysis_id}").json()
    assert result["duration_seconds"] == 0
    assert result["timeline_bucket_seconds"] == 1
    assert len(result["timeline"]) == 1
    assert result["packets_per_second"] is None


def test_event_feed_filters_pages_and_returns_source_evidence(analytics_client: TestClient) -> None:
    analysis_id = _seed(analytics_client)
    response = analytics_client.get("/api/v1/events?analysis_id=1&limit=2")
    assert response.status_code == 200, response.text
    page = response.json()
    assert page["total"] == 3
    assert len(page["items"]) == 2
    assert {event["event_type"] for event in page["items"]}.issubset(
        {"rule_finding", "ml_anomaly", "hybrid_assessment"}
    )
    rule = analytics_client.get("/api/v1/events/rule_finding:1")
    assert rule.status_code == 200, rule.text
    assert rule.json()["evidence"]["distinct_ports"] == 8
    assert rule.json()["related_flow_ids"] == ["a" * 64]
    ml = analytics_client.get("/api/v1/events/ml_anomaly:1")
    assert ml.status_code == 200
    assert ml.json()["event"]["severity"] is None
    assert ml.json()["evidence"]["anomaly_score"] == "0.250000000000"
    hybrid = analytics_client.get("/api/v1/events/hybrid_assessment:1")
    assert hybrid.status_code == 200
    assert hybrid.json()["event"]["risk_score"] == "61.00"
    assert hybrid.json()["evidence"]["detection_run_id"] == 1
    filtered = analytics_client.get("/api/v1/events?event_type=ml_anomaly&severity=high")
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 0
    rule_only = analytics_client.get(
        "/api/v1/events?event_type=rule_finding&severity=high&protocol=tcp&analysis_id=1"
    )
    assert rule_only.json()["total"] == 1
    assert analysis_id == 1


def test_comparison_keeps_missing_stage_data_null_and_isolates_analyses(
    analytics_client: TestClient,
) -> None:
    first_id = _seed(analytics_client)
    db = _session(analytics_client)
    try:
        second = Analysis(
            original_filename="SYNTHETIC-empty.pcapng",
            storage_key=None,
            file_size_bytes=0,
            capture_format="pcapng",
            status="completed",
            packet_count=0,
            flow_generation_status="not_started",
            flow_count=0,
            created_at=datetime(2026, 11, 16, tzinfo=UTC),
        )
        db.add(second)
        db.commit()
        second_id = second.id
    finally:
        db.close()
    response = analytics_client.get(
        f"/api/v1/analytics/comparison?analysis_ids={first_id}&analysis_ids={second_id}"
    )
    assert response.status_code == 200, response.text
    by_id = {item["analysis_id"]: item for item in response.json()["items"]}
    assert by_id[first_id]["packet_count"] == 4
    assert by_id[first_id]["ml_anomaly_count"] == 1
    assert by_id[first_id]["rule_findings_by_severity"] == {"high": 1}
    assert by_id[second_id]["packet_count"] == 0
    assert by_id[second_id]["flow_count"] is None
    assert by_id[second_id]["rule_findings_by_severity"] is None
    assert by_id[second_id]["ml_anomaly_count"] is None
    assert by_id[second_id]["hybrid_risk_score"] is None


def test_analytics_validation_and_empty_capture(analytics_client: TestClient) -> None:
    assert analytics_client.get("/api/v1/analytics/traffic/999").status_code == 404
    assert analytics_client.get("/api/v1/analytics/traffic/0").status_code == 422
    assert (
        analytics_client.get(
            "/api/v1/events?recorded_after=2026-02-01T00:00:00&recorded_before=2026-01-01T00:00:00"
        ).status_code
        == 422
    )
    assert analytics_client.get("/api/v1/analytics/comparison?analysis_ids=1").status_code == 422
    assert (
        analytics_client.get(
            "/api/v1/analytics/comparison?analysis_ids=1&analysis_ids=-1"
        ).status_code
        == 422
    )


def test_event_record_timestamp_boundaries_are_inclusive(analytics_client: TestClient) -> None:
    _seed(analytics_client)
    fixed_timestamp = datetime(2026, 11, 16, 12, 30, tzinfo=UTC)
    db = _session(analytics_client)
    try:
        finding = db.query(DetectionFinding).filter_by(id=1).one()
        finding.created_at = fixed_timestamp
        db.commit()
    finally:
        db.close()
    event_page = analytics_client.get("/api/v1/events?event_type=rule_finding&limit=1").json()
    recorded_at = event_page["items"][0]["recorded_at"]
    exact = analytics_client.get(
        "/api/v1/events",
        params={
            "event_type": "rule_finding",
            "recorded_after": recorded_at,
            "recorded_before": recorded_at,
        },
    )
    assert exact.status_code == 200
    assert exact.json()["total"] == 1
    assert (
        analytics_client.get("/api/v1/events", params={"recorded_before": recorded_at}).json()[
            "total"
        ]
        >= 1
    )
    assert (
        analytics_client.get(
            "/api/v1/events", params={"recorded_after": "2027-01-01T00:00:00+00:00"}
        ).json()["total"]
        == 0
    )


def test_comparison_rejects_incomplete_analyses(analytics_client: TestClient) -> None:
    completed_id = _seed(analytics_client)
    db = _session(analytics_client)
    try:
        pending = Analysis(
            original_filename="SYNTHETIC-processing.pcap",
            storage_key=None,
            file_size_bytes=0,
            capture_format="pcap",
            status="processing",
            packet_count=0,
            flow_generation_status="not_started",
            flow_count=0,
            created_at=datetime.now(UTC),
        )
        db.add(pending)
        db.commit()
        pending_id = pending.id
    finally:
        db.close()
    response = analytics_client.get(
        f"/api/v1/analytics/comparison?analysis_ids={completed_id}&analysis_ids={pending_id}"
    )
    assert response.status_code == 409


def _seed(client: TestClient) -> int:
    db = _session(client)
    try:
        analysis = Analysis(
            original_filename="SYNTHETIC-analytics.pcap",
            storage_key=None,
            file_size_bytes=300,
            capture_format="pcap",
            status="completed",
            packet_count=4,
            flow_generation_status="completed",
            flow_count=2,
            created_at=datetime(2026, 11, 15, tzinfo=UTC),
        )
        db.add(analysis)
        db.flush()
        flow = NetworkFlow(
            analysis_id=analysis.id,
            flow_id="a" * 64,
            protocol_name="TCP",
            endpoint_a_ip="192.0.2.10",
            endpoint_a_port=51500,
            endpoint_b_ip="198.51.100.20",
            endpoint_b_port=443,
            first_packet_source_ip="192.0.2.10",
            first_packet_source_port=51500,
            first_packet_destination_ip="198.51.100.20",
            first_packet_destination_port=443,
            first_timestamp=Decimal("100"),
            last_timestamp=Decimal("104"),
            duration_seconds=Decimal("4"),
            total_packets=3,
            total_bytes=300,
            forward_packets=2,
            backward_packets=1,
            forward_bytes=200,
            backward_bytes=100,
            packet_length_min=60,
            packet_length_max=140,
            packet_length_mean=Decimal("100"),
            packet_length_stddev=Decimal("40"),
            packets_per_second=Decimal("0.75"),
            bytes_per_second=Decimal("75"),
        )
        second_flow = NetworkFlow(
            **{
                **{
                    column.name: getattr(flow, column.name)
                    for column in NetworkFlow.__table__.columns
                    if column.name not in {"id", "flow_id"}
                },
                "flow_id": "b" * 64,
                "endpoint_b_port": 80,
                "total_packets": 1,
                "total_bytes": 120,
                "forward_packets": 1,
                "backward_packets": 0,
                "forward_bytes": 120,
                "backward_bytes": 0,
            }
        )
        db.add_all([flow, second_flow])
        db.flush()
        for index, (timestamp, protocol, length) in enumerate(
            [(100, "TCP", 100), (101, "TCP", 120), (104, "UDP", 80), (None, "ICMP", 120)]
        ):
            db.add(
                PacketRecord(
                    analysis_id=analysis.id,
                    packet_index=index,
                    flow_id=flow.flow_id if index < 3 else None,
                    flow_forward=True if index < 3 else None,
                    timestamp=Decimal(timestamp) if timestamp is not None else None,
                    source_ip="192.0.2.10",
                    destination_ip="198.51.100.20",
                    source_port=51500,
                    destination_port=443,
                    network_protocol=protocol,
                    transport_protocol=protocol if protocol in ("TCP", "UDP") else None,
                    packet_length=length,
                )
            )
        run = DetectionRun(
            analysis_id=analysis.id,
            config_hash="d" * 64,
            config_snapshot={},
            status="completed",
            finding_count=1,
        )
        model = AnomalyModel(
            model_version="synthetic-model-v1",
            algorithm="IsolationForest",
            feature_schema_version="flow-v1",
            feature_names=["total_packets"],
            active_feature_names=["total_packets"],
            preprocessing_config={},
            isolation_forest_config={},
            random_seed=7,
            training_analysis_ids=[analysis.id],
            training_sample_count=10,
            training_population_count=10,
            sklearn_version="1.5.0",
            artifact_key="synthetic-key",
            status="ready",
            trained_at=datetime(2026, 11, 15, tzinfo=UTC),
        )
        db.add_all([run, model])
        db.flush()
        finding = DetectionFinding(
            run_id=run.id,
            analysis_id=analysis.id,
            finding_key="synthetic-port-scan",
            rule_id="PORT_SCAN",
            rule_name="Multi-port probe indicator",
            severity="high",
            source_ip="192.0.2.10",
            destination_ip="198.51.100.20",
            protocol_name="TCP",
            explanation="Synthetic test evidence.",
            evidence={"distinct_ports": 8},
            supporting_flow_count=1,
        )
        finding.supporting_flows.append(flow)
        db.add(finding)
        db.add(
            AnomalyResult(
                model_id=model.id,
                model_version=model.model_version,
                analysis_id=analysis.id,
                flow_id=flow.flow_id,
                prediction="anomaly",
                anomaly_score=Decimal("0.25"),
            )
        )
        db.flush()
        db.add(
            HybridAssessment(
                analysis_id=analysis.id,
                detection_run_id=run.id,
                model_id=model.id,
                model_version=model.model_version,
                scoring_config_version="hybrid-v1",
                scoring_config_hash="e" * 64,
                scoring_config={},
                risk_score=Decimal("61.00"),
                severity="high",
                rule_evidence_count=1,
                ml_anomaly_count=1,
                correlated_evidence_count=2,
                risk_group_count=1,
                explanation="Synthetic combined evidence.",
            )
        )
        db.commit()
        return analysis.id
    finally:
        db.close()


def _session(client: TestClient) -> Session:
    return next(app.dependency_overrides[get_db]())


def _enable_sqlite_foreign_keys(connection, _record) -> None:
    connection.execute("PRAGMA foreign_keys=ON")
