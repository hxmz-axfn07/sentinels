from collections.abc import Generator
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.analysis import Analysis
from app.models.flow import NetworkFlow
from app.models.packet import PacketRecord


@pytest.fixture
def flow_client() -> Generator[TestClient, None, None]:
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


def add_analysis(client: TestClient, *, status: str = "completed") -> int:
    override = app.dependency_overrides[get_db]
    with next(override()) as db:
        analysis = Analysis(
            original_filename="synthetic.pcap",
            storage_key=None,
            file_size_bytes=0,
            capture_format="pcap",
            status=status,
            packet_count=0,
            created_at=datetime.now(UTC),
        )
        db.add(analysis)
        db.commit()
        return analysis.id


def add_packet(
    client: TestClient,
    analysis_id: int,
    index: int,
    *,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    timestamp: Decimal,
    length: int,
    flags: int,
) -> None:
    override = app.dependency_overrides[get_db]
    with next(override()) as db:
        db.add(
            PacketRecord(
                analysis_id=analysis_id,
                packet_index=index,
                timestamp=timestamp,
                source_ip=source,
                destination_ip=destination,
                source_port=source_port,
                destination_port=destination_port,
                network_protocol="IPv4",
                transport_protocol="TCP",
                ip_protocol_number=6,
                packet_length=length,
                tcp_flags=flags,
                icmp_type=None,
                icmp_code=None,
            )
        )
        analysis = db.get(Analysis, analysis_id)
        assert analysis is not None
        analysis.packet_count += 1
        db.commit()


def seed_bidirectional_capture(client: TestClient) -> int:
    analysis_id = add_analysis(client)
    add_packet(
        client,
        analysis_id,
        1,
        source="192.0.2.10",
        destination="198.51.100.20",
        source_port=51500,
        destination_port=443,
        timestamp=Decimal("1"),
        length=100,
        flags=0x02,
    )
    add_packet(
        client,
        analysis_id,
        2,
        source="198.51.100.20",
        destination="192.0.2.10",
        source_port=443,
        destination_port=51500,
        timestamp=Decimal("2"),
        length=200,
        flags=0x12,
    )
    add_packet(
        client,
        analysis_id,
        3,
        source="192.0.2.10",
        destination="198.51.100.20",
        source_port=51500,
        destination_port=443,
        timestamp=Decimal("4"),
        length=300,
        flags=0x10,
    )
    add_packet(
        client,
        analysis_id,
        4,
        source="192.0.2.10",
        destination="198.51.100.20",
        source_port=51501,
        destination_port=443,
        timestamp=Decimal("5"),
        length=80,
        flags=0x02,
    )
    return analysis_id


def test_generates_and_persists_bidirectional_flows_and_is_idempotent(
    flow_client: TestClient,
) -> None:
    analysis_id = seed_bidirectional_capture(flow_client)

    generated = flow_client.post(f"/api/v1/analyses/{analysis_id}/flows/generate")
    repeated = flow_client.post(f"/api/v1/analyses/{analysis_id}/flows/generate")
    analysis = flow_client.get(f"/api/v1/analyses/{analysis_id}").json()
    flow_page = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows?limit=10").json()

    assert generated.status_code == 200
    assert generated.json()["generated"] is True
    assert generated.json()["flow_count"] == 2
    assert repeated.status_code == 200
    assert repeated.json()["generated"] is False
    assert repeated.json()["flow_count"] == 2
    assert analysis["flow_generation_status"] == "completed"
    assert analysis["flow_count"] == 2
    assert flow_page["total"] == 2

    main_flow = next(item for item in flow_page["items"] if item["total_packets"] == 3)
    assert main_flow["forward_packets"] == 2
    assert main_flow["backward_packets"] == 1
    assert main_flow["forward_bytes"] == 400
    assert main_flow["backward_bytes"] == 200
    assert main_flow["duration_seconds"] == "3.000000000"

    override = app.dependency_overrides[get_db]
    with next(override()) as db:
        persisted = db.scalars(
            select(NetworkFlow).where(NetworkFlow.analysis_id == analysis_id)
        ).all()
    assert len(persisted) == 2


def test_flow_list_paginates_filters_protocol_and_endpoint(flow_client: TestClient) -> None:
    analysis_id = seed_bidirectional_capture(flow_client)
    flow_client.post(f"/api/v1/analyses/{analysis_id}/flows/generate")

    first = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows?offset=0&limit=1")
    second = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows?offset=1&limit=1")
    by_protocol = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows?protocol=tcp&limit=10")
    by_endpoint = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows?endpoint=198.51.100.20")

    assert first.status_code == second.status_code == 200
    assert len(first.json()["items"]) == len(second.json()["items"]) == 1
    assert first.json()["items"][0]["flow_id"] != second.json()["items"][0]["flow_id"]
    assert by_protocol.json()["total"] == 2
    assert by_endpoint.json()["total"] == 2


def test_generation_streams_across_database_batch_boundaries(
    flow_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    analysis_id = seed_bidirectional_capture(flow_client)
    monkeypatch.setattr("app.services.flow_generation.BATCH_SIZE", 2)

    generated = flow_client.post(f"/api/v1/analyses/{analysis_id}/flows/generate")
    flows = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows?limit=10")

    assert generated.status_code == 200
    assert generated.json()["flow_count"] == 2
    assert sorted(item["total_packets"] for item in flows.json()["items"]) == [1, 3]


def test_get_individual_flow_and_validate_identifiers(flow_client: TestClient) -> None:
    analysis_id = seed_bidirectional_capture(flow_client)
    flow_client.post(f"/api/v1/analyses/{analysis_id}/flows/generate")
    flow_id = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows").json()["items"][0]["flow_id"]

    response = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows/{flow_id}")

    assert response.status_code == 200
    assert response.json()["flow_id"] == flow_id
    assert flow_client.get(f"/api/v1/analyses/{analysis_id}/flows/not-a-key").status_code == 422
    assert flow_client.get("/api/v1/analyses/9999/flows").status_code == 404
    assert flow_client.post("/api/v1/analyses/0/flows/generate").status_code == 422
    assert flow_client.get(f"/api/v1/analyses/{analysis_id}/flows?limit=201").status_code == 422
    assert (
        flow_client.get(f"/api/v1/analyses/{analysis_id}/flows?endpoint=not-an-ip").status_code
        == 422
    )


def test_generation_requires_completed_analysis_and_flows_to_be_generated(
    flow_client: TestClient,
) -> None:
    analysis_id = add_analysis(flow_client, status="failed")

    response = flow_client.post(f"/api/v1/analyses/{analysis_id}/flows/generate")
    not_ready = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows")
    missing = flow_client.post("/api/v1/analyses/9999/flows/generate")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "analysis_not_completed"
    assert not_ready.status_code == 409
    assert missing.status_code == 404


def test_flow_generation_failure_is_recorded_without_partial_rows(
    flow_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    analysis_id = seed_bidirectional_capture(flow_client)

    def fail_generation(_db: Session, _analysis_id: int) -> int:
        raise RuntimeError("synthetic generator failure")

    monkeypatch.setattr("app.api.flows.generate_flows", fail_generation)
    response = flow_client.post(f"/api/v1/analyses/{analysis_id}/flows/generate")
    analysis = flow_client.get(f"/api/v1/analyses/{analysis_id}").json()
    flows = flow_client.get(f"/api/v1/analyses/{analysis_id}/flows")

    assert response.status_code == 500
    assert response.json()["detail"]["code"] == "flow_generation_failed"
    assert analysis["flow_generation_status"] == "failed"
    assert analysis["flow_error_message"] == "Flow generation did not complete."
    assert analysis["flow_count"] == 0
    assert flows.status_code == 409

    override = app.dependency_overrides[get_db]
    with next(override()) as db:
        assert db.scalars(select(NetworkFlow)).all() == []


def test_partial_flow_failure_rolls_back_flows_and_packet_assignments(
    flow_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    analysis_id = seed_bidirectional_capture(flow_client)
    from app.services.flow_generation import _append_flow as append_flow

    def flush_then_fail(db: Session, aggregate, pending) -> None:
        append_flow(db, aggregate, pending)
        db.add_all(pending)
        db.flush()
        pending.clear()
        raise RuntimeError("synthetic failure after a flow flush")

    monkeypatch.setattr("app.services.flow_generation._append_flow", flush_then_fail)
    response = flow_client.post(f"/api/v1/analyses/{analysis_id}/flows/generate")
    override = app.dependency_overrides[get_db]
    with next(override()) as db:
        stored_flows = db.scalars(
            select(NetworkFlow).where(NetworkFlow.analysis_id == analysis_id)
        ).all()
        packets = db.scalars(
            select(PacketRecord).where(PacketRecord.analysis_id == analysis_id)
        ).all()

    assert response.status_code == 500
    assert stored_flows == []
    assert all(packet.flow_id is None and packet.flow_forward is None for packet in packets)
