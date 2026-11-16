from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, text

from alembic import command
from app.core.config import settings


def test_migration_0005_preserves_day4_analysis_and_flow_rows(tmp_path: Path, monkeypatch) -> None:
    database_path = tmp_path / "ml-migration.sqlite3"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "0004_rule_based_detection")
    engine = create_engine(database_url)
    flow_key = "c" * 64
    with engine.begin() as connection:
        analysis_id = connection.execute(
            text(
                "INSERT INTO analyses "
                "(original_filename, file_size_bytes, capture_format, status, packet_count, "
                "flow_generation_status, flow_count) "
                "VALUES ('synthetic.pcap', 64, 'pcap', 'completed', 1, 'completed', 1)"
            )
        ).lastrowid
        connection.execute(
            text(
                "INSERT INTO network_flows "
                "(analysis_id, flow_id, protocol_name, total_packets, total_bytes, "
                "forward_packets, backward_packets, forward_bytes, backward_bytes, "
                "packet_length_min, packet_length_max, packet_length_mean, packet_length_stddev) "
                "VALUES (:analysis, :flow, 'TCP', 1, 60, 1, 0, 60, 0, 60, 60, 60, 0)"
            ),
            {"analysis": analysis_id, "flow": flow_key},
        )

    command.upgrade(config, "0005_isolation_forest")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM analyses")) == 1
        assert connection.scalar(text("SELECT COUNT(*) FROM network_flows")) == 1
        assert connection.scalar(text("SELECT COUNT(*) FROM anomaly_models")) == 0
        assert connection.scalar(text("SELECT COUNT(*) FROM ml_inference_results")) == 0
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
        assert revision == "0005_isolation_forest"
    engine.dispose()
