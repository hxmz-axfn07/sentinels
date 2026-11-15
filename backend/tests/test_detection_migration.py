from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, text

from alembic import command
from app.core.config import settings


def test_migration_preserves_day3_rows_and_backfills_directional_syn_counts(
    tmp_path: Path, monkeypatch
) -> None:
    database_path = tmp_path / "migration.sqlite3"
    database_url = f"sqlite:///{database_path}"
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))

    command.upgrade(config, "0003_bidirectional_flows")
    engine = create_engine(database_url)
    flow_id = "a" * 64
    with engine.begin() as connection:
        analysis_id = connection.execute(
            text(
                "INSERT INTO analyses "
                "(original_filename, file_size_bytes, capture_format, status, packet_count) "
                "VALUES ('synthetic.pcap', 64, 'pcap', 'completed', 2)"
            )
        ).lastrowid
        connection.execute(
            text(
                "INSERT INTO packet_metadata "
                "(analysis_id, packet_index, flow_id, flow_forward, network_protocol, "
                "packet_length, tcp_flags) VALUES "
                "(:analysis, 1, :flow, 1, 'IPv4', 60, 2), "
                "(:analysis, 2, :flow, 0, 'IPv4', 60, 18)"
            ),
            {"analysis": analysis_id, "flow": flow_id},
        )
        connection.execute(
            text(
                "INSERT INTO network_flows "
                "(analysis_id, flow_id, protocol_name, total_packets, total_bytes, "
                "forward_packets, backward_packets, forward_bytes, backward_bytes, "
                "packet_length_min, packet_length_max, packet_length_mean, packet_length_stddev) "
                "VALUES (:analysis, :flow, 'TCP', 2, 120, 1, 1, 60, 60, 60, 60, 60, 0)"
            ),
            {"analysis": analysis_id, "flow": flow_id},
        )

    command.upgrade(config, "head")
    with engine.connect() as connection:
        migrated = connection.execute(
            text(
                "SELECT forward_syn_only_count, backward_syn_only_count, "
                "forward_syn_ack_count, backward_syn_ack_count "
                "FROM network_flows WHERE analysis_id = :analysis"
            ),
            {"analysis": analysis_id},
        ).one()
        assert tuple(migrated) == (1, 0, 0, 1)
        assert connection.scalar(text("SELECT COUNT(*) FROM analyses")) == 1
        assert connection.scalar(text("SELECT COUNT(*) FROM packet_metadata")) == 2
        assert connection.scalar(text("SELECT COUNT(*) FROM network_flows")) == 1
        assert connection.scalar(text("SELECT status FROM detection_runs LIMIT 1")) is None
    engine.dispose()
