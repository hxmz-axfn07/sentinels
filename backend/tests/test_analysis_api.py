from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap, wrpcapng
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.analysis import Analysis
from app.models.packet import PacketRecord


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db() -> Generator[Session, None, None]:
        with test_session() as session:
            yield session

    storage_dir = tmp_path / "managed-captures"
    monkeypatch.setattr(settings, "upload_storage_dir", storage_dir)
    monkeypatch.setattr(settings, "max_upload_size_bytes", 1_000_000)
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    engine.dispose()


def synthetic_packets() -> list[Ether]:
    tcp = (
        Ether()
        / IP(src="192.0.2.1", dst="198.51.100.2")
        / TCP(sport=12345, dport=443, flags="S")
        / Raw(load=b"payload must not be stored")
    )
    tcp.time = 1_700_000_000.123456
    udp = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5353, dport=53)
    udp.time = 1_700_000_001.123456
    arp = Ether() / ARP()
    arp.time = 1_700_000_002.123456
    return [tcp, udp, arp]


def capture_bytes(tmp_path: Path, *, pcapng: bool = False) -> bytes:
    path = tmp_path / ("synthetic.pcapng" if pcapng else "synthetic.pcap")
    if pcapng:
        wrpcapng(str(path), synthetic_packets())
    else:
        wrpcap(str(path), synthetic_packets())
    return path.read_bytes()


def test_upload_persists_analysis_and_metadata_without_payload(
    client: TestClient, tmp_path: Path
) -> None:
    response = client.post(
        "/api/v1/analyses/upload",
        files={"file": ("../../capture.txt", capture_bytes(tmp_path), "text/plain")},
    )

    assert response.status_code == 201
    analysis = response.json()
    assert analysis["original_filename"] == "capture.txt"
    assert analysis["capture_format"] == "pcap"
    assert analysis["status"] == "completed"
    assert analysis["packet_count"] == 3
    assert analysis["storage_key"].endswith(".pcap")
    assert str(tmp_path) not in response.text

    stored_path = settings.upload_storage_dir / analysis["storage_key"]
    assert stored_path.is_file()
    assert not list(settings.upload_storage_dir.glob("*.part"))

    packets = client.get(f"/api/v1/analyses/{analysis['id']}/packets?limit=10").json()
    assert packets["total"] == 3
    assert [packet["packet_index"] for packet in packets["items"]] == [1, 2, 3]
    first, second, third = packets["items"]
    assert (first["source_ip"], first["destination_ip"]) == ("192.0.2.1", "198.51.100.2")
    assert (first["source_port"], first["destination_port"], first["tcp_flags"]) == (
        12345,
        443,
        2,
    )
    assert (second["network_protocol"], second["transport_protocol"]) == ("IPv6", "UDP")
    assert (second["source_port"], second["destination_port"]) == (5353, 53)
    assert third["network_protocol"] == "ARP"
    assert third["source_port"] is None
    assert "payload" not in response.text
    assert "payload" not in str(packets)


def test_upload_accepts_pcapng_content_even_with_pcap_extension(
    client: TestClient, tmp_path: Path
) -> None:
    response = client.post(
        "/api/v1/analyses/upload",
        files={
            "file": (
                "network.pcap",
                capture_bytes(tmp_path, pcapng=True),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 201
    assert response.json()["capture_format"] == "pcapng"
    assert response.json()["storage_key"].endswith(".pcapng")


@pytest.mark.parametrize(
    ("filename", "data", "status", "code"),
    [
        ("empty.pcap", b"", 422, "empty_file"),
        ("bad.pcap", b"not a capture", 422, "unsupported_capture"),
        ("truncated.pcap", b"\xd4\xc3\xb2\xa1", 422, "malformed_capture"),
    ],
)
def test_rejects_invalid_uploads_and_cleans_temporary_files(
    client: TestClient,
    tmp_path: Path,
    filename: str,
    data: bytes,
    status: int,
    code: str,
) -> None:
    response = client.post("/api/v1/analyses/upload", files={"file": (filename, data)})

    assert response.status_code == status
    assert response.json()["detail"]["code"] == code
    assert not list(settings.upload_storage_dir.glob(".upload-*.part"))
    assert client.get("/api/v1/analyses").json()["total"] == 0


def test_rejects_oversized_upload_and_cleans_temporary_file(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "max_upload_size_bytes", 64)

    response = client.post(
        "/api/v1/analyses/upload",
        files={"file": ("large.pcap", capture_bytes(tmp_path), "application/octet-stream")},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "upload_too_large"
    assert not list(settings.upload_storage_dir.glob(".upload-*.part"))


def test_request_limit_stops_large_multipart_bodies_before_file_staging(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "max_upload_size_bytes", 1024)

    response = client.post(
        "/api/v1/analyses/upload",
        files={"file": ("large.pcap", b"x" * 70_000, "application/octet-stream")},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "upload_too_large"
    assert not settings.upload_storage_dir.exists()


def test_analysis_list_detail_and_packet_pagination(client: TestClient, tmp_path: Path) -> None:
    upload = client.post(
        "/api/v1/analyses/upload",
        files={"file": ("page.pcap", capture_bytes(tmp_path), "application/octet-stream")},
    )
    analysis_id = upload.json()["id"]

    first_page = client.get(f"/api/v1/analyses/{analysis_id}/packets?offset=0&limit=2")
    second_page = client.get(f"/api/v1/analyses/{analysis_id}/packets?offset=2&limit=2")
    listing = client.get("/api/v1/analyses?offset=0&limit=1")

    assert first_page.status_code == second_page.status_code == 200
    assert [packet["packet_index"] for packet in first_page.json()["items"]] == [1, 2]
    assert [packet["packet_index"] for packet in second_page.json()["items"]] == [3]
    assert first_page.json()["total"] == 3
    assert listing.json()["total"] == 1
    assert client.get(f"/api/v1/analyses/{analysis_id}").json()["id"] == analysis_id
    assert client.get("/api/v1/analyses/9999").status_code == 404
    assert client.get(f"/api/v1/analyses/{analysis_id}/packets?limit=201").status_code == 422


def test_processing_failure_is_recorded_and_file_remains_linked(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def partial_reader(_path: str):
        from app.services.packet_metadata import extract_packet_metadata

        yield extract_packet_metadata(synthetic_packets()[0], 1)
        raise RuntimeError("processing failed after one committed batch")

    monkeypatch.setattr("app.services.analysis.BATCH_SIZE", 1)
    monkeypatch.setattr("app.services.analysis.read_packet_metadata", partial_reader)
    response = client.post(
        "/api/v1/analyses/upload",
        files={"file": ("valid.pcap", capture_bytes(tmp_path), "application/octet-stream")},
    )

    analysis = response.json()
    assert response.status_code == 201
    assert analysis["status"] == "failed"
    assert analysis["packet_count"] == 0
    assert analysis["error_message"] == "Packet processing did not complete."
    assert str(tmp_path) not in response.text
    assert (settings.upload_storage_dir / analysis["storage_key"]).is_file()
    assert not list(settings.upload_storage_dir.glob(".upload-*.part"))
    assert client.get(f"/api/v1/analyses/{analysis['id']}/packets").json()["total"] == 0


def test_packet_metadata_rows_belong_to_analysis(client: TestClient, tmp_path: Path) -> None:
    response = client.post(
        "/api/v1/analyses/upload",
        files={"file": ("linked.pcap", capture_bytes(tmp_path), "application/octet-stream")},
    )
    analysis_id = response.json()["id"]

    db_override = app.dependency_overrides[get_db]
    with next(db_override()) as db:
        rows = db.scalars(select(PacketRecord).where(PacketRecord.analysis_id == analysis_id)).all()
        analysis = db.get(Analysis, analysis_id)

    assert analysis is not None
    assert analysis.packet_count == len(rows) == 3


def test_upload_limit_endpoint_reports_server_configuration(client: TestClient) -> None:
    response = client.get("/api/v1/analyses/limits")

    assert response.status_code == 200
    assert response.json() == {"max_upload_size_bytes": 1_000_000}
