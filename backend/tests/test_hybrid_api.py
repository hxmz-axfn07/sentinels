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
from app.models.anomaly import AnomalyModel, AnomalyResult
from app.models.detection import DetectionFinding, DetectionRun
from app.models.flow import NetworkFlow
from app.models.hybrid import HybridAssessment, HybridEvidence, HybridRiskGroup
from app.services.hybrid.config import HybridScoringConfig


@pytest.fixture
def hybrid_client(
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

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    monkeypatch.setattr(settings, "hybrid_scoring_config", HybridScoringConfig())
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    engine.dispose()


def test_assessment_correlates_versions_scores_and_preserves_evidence(
    hybrid_client: TestClient,
) -> None:
    analysis_id, run_id, model_id, flow_ids = seed_sources(hybrid_client)

    first = run_assessment(hybrid_client, analysis_id, run_id, model_id)
    repeated = run_assessment(hybrid_client, analysis_id, run_id, model_id)

    assert first.status_code == 201, first.text
    assert repeated.status_code == 201, repeated.text
    result = first.json()
    assert result["risk_score"] == "90.25"
    assert result["severity"] == "critical"
    assert result["rule_evidence_count"] == 4
    assert result["ml_anomaly_count"] == 2
    assert result["correlated_evidence_count"] == 1
    assert result["risk_group_count"] == 2
    assert result["model_version"] == "synthetic-model-v1"
    assert result["scoring_config_version"] == "hybrid-v1"
    assert result["reused"] is False
    assert repeated.json()["id"] == result["id"]
    assert repeated.json()["reused"] is True

    groups = hybrid_client.get(
        f"/api/v1/analyses/{analysis_id}/hybrid/assessments/{result['id']}/groups"
    )
    assert groups.status_code == 200
    assert groups.json()["total"] == 2
    assert groups.json()["items"][0]["correlation_level"] == "exact_flow"
    exact = groups.json()["items"][0]
    assert exact["correlated_flow_count"] == 1
    assert exact["rule_component"] == "58.75"
    assert exact["ml_component"] == "40.00"
    assert exact["exact_flow_bonus"] == "15.00"
    assert exact["risk_score"] == "90.25"
    endpoint_only = next(
        item for item in groups.json()["items"] if item["correlation_level"] == "endpoint_pair"
    )
    assert endpoint_only["exact_flow_bonus"] == "0.00"
    assert endpoint_only["correlated_flow_count"] == 0

    evidence_page = hybrid_client.get(
        f"/api/v1/analyses/{analysis_id}/hybrid/assessments/{result['id']}"
        f"/groups/{exact['id']}/evidence?limit=2"
    )
    assert evidence_page.status_code == 200
    assert evidence_page.json()["total"] == 4
    assert len(evidence_page.json()["items"]) == 2
    source_ids = {item["source_id"] for item in evidence_page.json()["items"]}
    assert source_ids
    all_evidence = hybrid_client.get(
        f"/api/v1/analyses/{analysis_id}/hybrid/assessments/{result['id']}"
        f"/groups/{exact['id']}/evidence?limit=10"
    ).json()["items"]
    assert {item["flow_id"] for item in all_evidence if item["source"] == "ml"} == {flow_ids[0]}
    assert all("payload" not in item["evidence"] for item in all_evidence)

    db = _session(hybrid_client)
    try:
        assert db.scalar(select(func.count(HybridAssessment.id))) == 1
        assert db.scalar(select(func.count(HybridRiskGroup.id))) == 2
        assert db.scalar(select(func.count(HybridEvidence.id))) == 6
    finally:
        db.close()


def test_zero_findings_and_zero_anomalies_are_informational_not_safe(
    hybrid_client: TestClient,
) -> None:
    analysis_id, run_id, model_id, _ = seed_sources(
        hybrid_client, with_findings=False, all_normal=True
    )

    response = run_assessment(hybrid_client, analysis_id, run_id, model_id)

    assert response.status_code == 201, response.text
    result = response.json()
    assert result["risk_score"] == "0.00"
    assert result["severity"] == "informational"
    assert result["risk_group_count"] == 0
    assert result["rule_evidence_count"] == 0
    assert result["ml_anomaly_count"] == 0
    assert "does not establish that traffic was safe" in result["explanation"]


def test_missing_or_incomplete_prerequisites_are_rejected(hybrid_client: TestClient) -> None:
    analysis_id, run_id, model_id, _ = seed_sources(hybrid_client)
    db = _session(hybrid_client)
    try:
        second_result = db.scalar(
            select(AnomalyResult)
            .where(AnomalyResult.analysis_id == analysis_id)
            .order_by(AnomalyResult.id.desc())
        )
        assert second_result is not None
        db.delete(second_result)
        db.commit()
    finally:
        db.close()

    response = run_assessment(hybrid_client, analysis_id, run_id, model_id)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "inference_results_incomplete"
    assert (
        hybrid_client.get(f"/api/v1/analyses/{analysis_id}/hybrid/summary").json()["status"]
        == "not_started"
    )
    assert run_assessment(hybrid_client, analysis_id, 999, model_id).status_code == 404
    assert run_assessment(hybrid_client, 999, run_id, model_id).status_code == 404


def test_empty_analysis_is_not_misreported_as_a_zero_risk_assessment(
    hybrid_client: TestClient,
) -> None:
    analysis_id, run_id, model_id, _ = seed_sources(hybrid_client)
    db = _session(hybrid_client)
    try:
        analysis = db.get(Analysis, analysis_id)
        assert analysis is not None
        analysis.flow_count = 0
        db.commit()
    finally:
        db.close()

    response = run_assessment(hybrid_client, analysis_id, run_id, model_id)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "analysis_has_no_flows"


def test_scoring_configuration_change_creates_a_distinct_assessment(
    hybrid_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.hybrid as hybrid_api

    analysis_id, run_id, model_id, _ = seed_sources(hybrid_client)
    first = run_assessment(hybrid_client, analysis_id, run_id, model_id)
    monkeypatch.setattr(
        hybrid_api.settings,
        "hybrid_scoring_config",
        HybridScoringConfig(exact_flow_bonus=0, ml_base_weight=10, ml_rank_weight=10),
    )
    second = run_assessment(hybrid_client, analysis_id, run_id, model_id)

    assert first.status_code == second.status_code == 201
    assert first.json()["id"] != second.json()["id"]
    assert first.json()["scoring_config_hash"] != second.json()["scoring_config_hash"]
    assert second.json()["risk_score"] == "65.63"


def test_failed_assessment_rolls_back_parent_groups_and_evidence(
    hybrid_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.hybrid as hybrid_api

    analysis_id, run_id, model_id, _ = seed_sources(hybrid_client)
    actual = hybrid_api.execute_assessment

    def fail_after_write(*args, **kwargs):
        actual(*args, **kwargs)
        raise RuntimeError("synthetic rollback failure")

    monkeypatch.setattr(hybrid_api, "execute_assessment", fail_after_write)
    response = run_assessment(hybrid_client, analysis_id, run_id, model_id)
    assert response.status_code == 500

    db = _session(hybrid_client)
    try:
        assert db.scalar(select(func.count(HybridAssessment.id))) == 0
        assert db.scalar(select(func.count(HybridRiskGroup.id))) == 0
        assert db.scalar(select(func.count(HybridEvidence.id))) == 0
    finally:
        db.close()


def test_assessment_history_pagination_and_severity_filter(
    hybrid_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.hybrid as hybrid_api

    analysis_id, run_id, model_id, _ = seed_sources(hybrid_client)
    first = run_assessment(hybrid_client, analysis_id, run_id, model_id)
    monkeypatch.setattr(
        hybrid_api.settings,
        "hybrid_scoring_config",
        HybridScoringConfig(exact_flow_bonus=0, ml_base_weight=10, ml_rank_weight=10),
    )
    second = run_assessment(hybrid_client, analysis_id, run_id, model_id)
    assert first.status_code == second.status_code == 201

    page = hybrid_client.get(f"/api/v1/analyses/{analysis_id}/hybrid/assessments?offset=1&limit=1")
    critical = hybrid_client.get(
        f"/api/v1/analyses/{analysis_id}/hybrid/assessments?severity=critical"
    )
    groups = hybrid_client.get(
        f"/api/v1/analyses/{analysis_id}/hybrid/assessments/{first.json()['id']}"
        "/groups?severity=critical"
    )
    assert page.json()["total"] == 2
    assert len(page.json()["items"]) == 1
    assert critical.json()["total"] == 1
    assert groups.json()["total"] == 1


def seed_sources(
    client: TestClient, *, with_findings: bool = True, all_normal: bool = False
) -> tuple[int, int, int, list[str]]:
    db = _session(client)
    try:
        analysis = Analysis(
            original_filename="synthetic-day6.pcap",
            storage_key=None,
            file_size_bytes=0,
            capture_format="pcap",
            status="completed",
            packet_count=4,
            flow_generation_status="completed",
            flow_count=4,
            created_at=datetime.now(UTC),
        )
        db.add(analysis)
        db.flush()
        flows = [
            _flow(analysis.id, 1, "10.0.0.1", "10.0.0.2", "TCP"),
            _flow(analysis.id, 2, "10.0.0.1", "10.0.0.2", "TCP"),
            _flow(analysis.id, 3, "10.0.0.3", "10.0.0.4", "UDP"),
            _flow(analysis.id, 4, "10.0.0.3", "10.0.0.4", "UDP"),
        ]
        db.add_all(flows)
        db.flush()
        run = DetectionRun(
            analysis_id=analysis.id,
            config_hash="d" * 64,
            config_snapshot={"synthetic": True},
            status="completed",
            finding_count=4 if with_findings else 0,
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        db.add(run)
        db.flush()
        if with_findings:
            db.add_all(
                [
                    DetectionFinding(
                        run_id=run.id,
                        analysis_id=analysis.id,
                        finding_key="a" * 64,
                        rule_id="PORT_SCAN",
                        rule_name="Synthetic multi-port probe",
                        severity="high",
                        source_ip="10.0.0.1",
                        destination_ip="10.0.0.2",
                        protocol_name="TCP/UDP",
                        explanation="Synthetic rule indicator.",
                        evidence={"protocols": ["TCP"], "distinct_destination_port_count": 2},
                        supporting_flow_count=2,
                        supporting_flow_sample_truncated=False,
                        supporting_flows=flows[:2],
                    ),
                    DetectionFinding(
                        run_id=run.id,
                        analysis_id=analysis.id,
                        finding_key="b" * 64,
                        rule_id="SYN_FLOOD_LIKE",
                        rule_name="Synthetic SYN indicator",
                        severity="medium",
                        source_ip="10.0.0.1",
                        destination_ip="10.0.0.2",
                        protocol_name="TCP",
                        explanation="Synthetic SYN indicator.",
                        evidence={"syn_only_packet_count": 20},
                        supporting_flow_count=1,
                        supporting_flow_sample_truncated=False,
                        supporting_flows=[flows[0]],
                    ),
                    DetectionFinding(
                        run_id=run.id,
                        analysis_id=analysis.id,
                        finding_key="c" * 64,
                        rule_id="PORT_SCAN",
                        rule_name="Synthetic repeated port probe",
                        severity="low",
                        source_ip="10.0.0.1",
                        destination_ip="10.0.0.2",
                        protocol_name="TCP",
                        explanation="Repeated synthetic rule type.",
                        evidence={"distinct_destination_port_count": 2},
                        supporting_flow_count=1,
                        supporting_flow_sample_truncated=False,
                        supporting_flows=[flows[1]],
                    ),
                    DetectionFinding(
                        run_id=run.id,
                        analysis_id=analysis.id,
                        finding_key="d" * 64,
                        rule_id="EXCESSIVE_CONNECTION_ATTEMPTS",
                        rule_name="Synthetic connection attempts",
                        severity="low",
                        source_ip="10.0.0.3",
                        destination_ip="10.0.0.4",
                        protocol_name="UDP",
                        explanation="Synthetic endpoint-only correlation fixture.",
                        evidence={"supporting_flow_count": 1},
                        supporting_flow_count=1,
                        supporting_flow_sample_truncated=False,
                        supporting_flows=[flows[2]],
                    ),
                ]
            )
        model = AnomalyModel(
            model_version="synthetic-model-v1",
            algorithm="IsolationForest",
            feature_schema_version="flow-v1",
            feature_names=["total_packets"],
            active_feature_names=["log1p:total_packets"],
            preprocessing_config={},
            isolation_forest_config={"n_estimators": 50},
            random_seed=42,
            training_analysis_ids=[analysis.id],
            training_sample_count=20,
            training_population_count=20,
            sklearn_version="1.9.1",
            artifact_key="a" * 32 + ".joblib",
            status="ready",
            trained_at=datetime.now(UTC),
        )
        db.add(model)
        db.flush()
        predictions = (
            ["normal", "normal", "normal", "normal"]
            if all_normal
            else ["anomaly", "normal", "normal", "anomaly"]
        )
        scores = [Decimal("0.5"), Decimal("0.1"), Decimal("0.2"), Decimal("0.9")]
        for flow, prediction, score in zip(flows, predictions, scores, strict=True):
            db.add(
                AnomalyResult(
                    model_id=model.id,
                    model_version=model.model_version,
                    analysis_id=analysis.id,
                    flow_id=flow.flow_id,
                    prediction=prediction,
                    anomaly_score=score,
                )
            )
        db.commit()
        return analysis.id, run.id, model.id, [flow.flow_id for flow in flows]
    finally:
        db.close()


def _flow(
    analysis_id: int, number: int, endpoint_a: str, endpoint_b: str, protocol: str
) -> NetworkFlow:
    return NetworkFlow(
        analysis_id=analysis_id,
        flow_id=f"{number:064x}",
        ip_version=4,
        protocol_name=protocol,
        protocol_number=6 if protocol == "TCP" else 17,
        endpoint_a_ip=endpoint_a,
        endpoint_a_port=10_000 + number,
        endpoint_b_ip=endpoint_b,
        endpoint_b_port=443 if protocol == "TCP" else 53,
        total_packets=number + 1,
        total_bytes=120 + number,
        forward_packets=1,
        backward_packets=number,
        forward_bytes=60,
        backward_bytes=60 + number,
        packet_length_min=60,
        packet_length_max=60 + number,
        packet_length_mean=Decimal("61"),
        packet_length_stddev=Decimal("1"),
        duration_seconds=Decimal("1.0"),
        packets_per_second=Decimal("2.0"),
        bytes_per_second=Decimal("120.0"),
    )


def run_assessment(client: TestClient, analysis_id: int, detection_run_id: int, model_id: int):
    return client.post(
        f"/api/v1/analyses/{analysis_id}/hybrid/assessments",
        json={"detection_run_id": detection_run_id, "model_id": model_id},
    )


def _session(client: TestClient) -> Session:
    return next(app.dependency_overrides[get_db]())


def _enable_sqlite_foreign_keys(connection, _record) -> None:
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
