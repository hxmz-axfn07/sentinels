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


@pytest.fixture
def incident_client() -> Generator[TestClient, None, None]:
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


def test_create_incident_from_multiple_findings_and_attach_idempotently(
    incident_client: TestClient,
) -> None:
    analysis_id = _seed(incident_client)
    created = incident_client.post(
        "/api/v1/incidents",
        json={
            "title": "Synthetic investigation",
            "description": "Review selected offline capture evidence.",
            "priority": "high",
            "event_ids": [
                "rule_finding:1",
                "ml_anomaly:1",
                "hybrid_assessment:1",
                "rule_finding:1",
            ],
        },
    )
    assert created.status_code == 201, created.text
    detail = created.json()
    assert detail["status"] == "open"
    assert detail["evidence_count"] == 3
    assert detail["analysis_ids"] == [analysis_id]
    assert {item["source_type"] for item in detail["evidence"]} == {
        "rule_finding",
        "ml_anomaly",
        "hybrid_assessment",
    }
    assert detail["created_by"] is None
    assert all(entry["actor"] is None for entry in detail["history"])
    assert [entry["action"] for entry in detail["history"][:2]] == [
        "incident_created",
        "evidence_attached",
    ]

    incident_id = detail["id"]
    attached = incident_client.post(
        f"/api/v1/incidents/{incident_id}/evidence",
        json={"event_ids": ["rule_finding:1", "ml_anomaly:1"]},
    )
    assert attached.status_code == 200, attached.text
    assert attached.json()["evidence_count"] == 3
    feed = incident_client.get("/api/v1/incidents?priority=high&search=Synthetic")
    assert feed.json()["total"] == 1
    assert feed.json()["items"][0]["analysis_ids"] == [analysis_id]
    summary = incident_client.get("/api/v1/incidents/summary").json()
    assert summary["total"] == 1
    assert summary["status_counts"] == {"open": 1}


def test_incident_status_lifecycle_notes_and_history(incident_client: TestClient) -> None:
    _seed(incident_client)
    created = incident_client.post(
        "/api/v1/incidents", json={"title": "Synthetic lifecycle", "priority": "medium"}
    ).json()
    incident_id = created["id"]

    for target in ("acknowledged", "investigating"):
        response = incident_client.patch(
            f"/api/v1/incidents/{incident_id}/status", json={"status": target}
        )
        assert response.status_code == 200, response.text
    note = incident_client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"body": "Synthetic review note; source evidence remains unchanged."},
    )
    assert note.status_code == 201
    assert note.json()["created_by"] is None

    missing_summary = incident_client.patch(
        f"/api/v1/incidents/{incident_id}/status", json={"status": "resolved"}
    )
    assert missing_summary.status_code == 409
    resolved = incident_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "resolved", "resolution_summary": "Synthetic review complete."},
    )
    assert resolved.status_code == 200
    assert resolved.json()["resolution_summary"] == "Synthetic review complete."
    closed = incident_client.patch(
        f"/api/v1/incidents/{incident_id}/status", json={"status": "closed"}
    )
    assert closed.status_code == 200
    reopened = incident_client.patch(
        f"/api/v1/incidents/{incident_id}/status", json={"status": "investigating"}
    )
    assert reopened.status_code == 200
    assert reopened.json()["resolution_summary"] is None
    assert reopened.json()["notes"][0]["body"].startswith("Synthetic review note")
    actions = [item["action"] for item in reopened.json()["history"]]
    assert actions == [
        "incident_created",
        "status_changed",
        "status_changed",
        "note_added",
        "incident_resolved",
        "incident_closed",
        "incident_reopened",
    ]


def test_incident_references_are_validated_and_transactional(incident_client: TestClient) -> None:
    _seed(incident_client)
    bad_create = incident_client.post(
        "/api/v1/incidents",
        json={"title": "Must roll back", "event_ids": ["rule_finding:1", "ml_anomaly:999"]},
    )
    assert bad_create.status_code == 404
    assert incident_client.get("/api/v1/incidents/summary").json()["total"] == 0

    invalid_syntax = incident_client.post(
        "/api/v1/incidents",
        json={"title": "Invalid event identifier", "event_ids": ["other:1"]},
    )
    assert invalid_syntax.status_code == 404
    invalid_priority = incident_client.post(
        "/api/v1/incidents", json={"title": "Invalid priority", "priority": "urgent"}
    )
    assert invalid_priority.status_code == 422
    invalid_status = incident_client.patch("/api/v1/incidents/1/status", json={"status": "triage"})
    assert invalid_status.status_code == 422
    assert incident_client.get("/api/v1/incidents/999").status_code == 404


def test_incident_titles_are_trimmed_and_cannot_be_blank(incident_client: TestClient) -> None:
    created = incident_client.post("/api/v1/incidents", json={"title": "  Review this  "})
    assert created.status_code == 201
    assert created.json()["title"] == "Review this"

    blank = incident_client.post("/api/v1/incidents", json={"title": "   "})
    assert blank.status_code == 422
    update = incident_client.patch(
        f"/api/v1/incidents/{created.json()['id']}", json={"title": " \n "}
    )
    assert update.status_code == 422


def test_cross_origin_state_changing_requests_are_rejected(incident_client: TestClient) -> None:
    blocked = incident_client.post(
        "/api/v1/incidents",
        json={"title": "Blocked synthetic incident"},
        headers={"Origin": "https://attacker.example"},
    )
    assert blocked.status_code == 403
    assert incident_client.get("/api/v1/incidents/summary").json()["total"] == 0

    allowed = incident_client.post(
        "/api/v1/incidents",
        json={"title": "Allowed local incident"},
        headers={"Origin": "http://localhost:5174"},
    )
    assert allowed.status_code == 201


def test_invalid_transitions_and_duplicate_relationship_removal(
    incident_client: TestClient,
) -> None:
    _seed(incident_client)
    created = incident_client.post(
        "/api/v1/incidents",
        json={"title": "Synthetic state", "event_ids": ["rule_finding:1"]},
    ).json()
    incident_id = created["id"]
    close_open = incident_client.patch(
        f"/api/v1/incidents/{incident_id}/status", json={"status": "closed"}
    )
    assert close_open.status_code == 409
    evidence_id = created["evidence"][0]["id"]
    assert (
        incident_client.delete(
            f"/api/v1/incidents/{incident_id}/evidence/{evidence_id}"
        ).status_code
        == 204
    )
    assert (
        incident_client.delete(
            f"/api/v1/incidents/{incident_id}/evidence/{evidence_id}"
        ).status_code
        == 404
    )
    refreshed = incident_client.get(f"/api/v1/incidents/{incident_id}").json()
    assert refreshed["evidence_count"] == 0
    assert refreshed["history"][-1]["action"] == "evidence_detached"


def _seed(client: TestClient) -> int:
    db = _session(client)
    try:
        analysis = Analysis(
            original_filename="SYNTHETIC-incident.pcap",
            storage_key=None,
            file_size_bytes=256,
            capture_format="pcap",
            status="completed",
            packet_count=1,
            flow_generation_status="completed",
            flow_count=1,
            created_at=datetime(2026, 11, 16, tzinfo=UTC),
        )
        db.add(analysis)
        db.flush()
        flow = NetworkFlow(
            analysis_id=analysis.id,
            flow_id="a" * 64,
            ip_version=4,
            protocol_name="TCP",
            protocol_number=6,
            endpoint_a_ip="192.0.2.11",
            endpoint_a_port=12345,
            endpoint_b_ip="198.51.100.22",
            endpoint_b_port=443,
            first_packet_source_ip="192.0.2.11",
            first_packet_source_port=12345,
            first_packet_destination_ip="198.51.100.22",
            first_packet_destination_port=443,
            first_timestamp=Decimal("100"),
            last_timestamp=Decimal("100"),
            duration_seconds=Decimal("0"),
            total_packets=1,
            total_bytes=128,
            forward_packets=1,
            backward_packets=0,
            forward_bytes=128,
            backward_bytes=0,
            packet_length_min=128,
            packet_length_max=128,
            packet_length_mean=Decimal("128"),
            packet_length_stddev=Decimal("0"),
            interarrival_min=None,
            interarrival_max=None,
            interarrival_mean=None,
            interarrival_stddev=None,
            syn_count=1,
            ack_count=0,
            fin_count=0,
            rst_count=0,
            psh_count=0,
            urg_count=0,
            forward_syn_only_count=1,
            backward_syn_only_count=0,
            forward_syn_ack_count=0,
            backward_syn_ack_count=0,
            packets_per_second=None,
            bytes_per_second=None,
        )
        run = DetectionRun(
            analysis_id=analysis.id,
            config_hash="d" * 64,
            config_snapshot={},
            status="completed",
            finding_count=1,
        )
        model = AnomalyModel(
            model_version="synthetic-incident-model",
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
            artifact_key="synthetic-incident-artifact",
            status="ready",
            trained_at=datetime(2026, 11, 15, tzinfo=UTC),
        )
        db.add_all([flow, run, model])
        db.flush()
        finding = DetectionFinding(
            run_id=run.id,
            analysis_id=analysis.id,
            finding_key="synthetic-finding",
            rule_id="PORT_SCAN",
            rule_name="Synthetic multi-port probing",
            severity="high",
            source_ip="192.0.2.11",
            destination_ip="198.51.100.22",
            protocol_name="TCP",
            explanation="Synthetic fixture finding.",
            evidence={"distinct_ports": 8},
            supporting_flow_count=1,
        )
        finding.supporting_flows.append(flow)
        anomaly = AnomalyResult(
            model_id=model.id,
            model_version=model.model_version,
            analysis_id=analysis.id,
            flow_id=flow.flow_id,
            prediction="anomaly",
            anomaly_score=Decimal("0.25"),
        )
        db.add_all([finding, anomaly])
        db.flush()
        assessment = HybridAssessment(
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
            risk_group_count=0,
            explanation="Synthetic hybrid assessment.",
        )
        db.add(assessment)
        db.commit()
        return analysis.id
    finally:
        db.close()


def _session(client: TestClient) -> Session:
    return next(app.dependency_overrides[get_db]())


def _enable_sqlite_foreign_keys(connection, _record) -> None:
    connection.execute("PRAGMA foreign_keys=ON")
