from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from alembic import command
from app.core.config import settings


def test_incident_migration_preserves_sources_and_downgrades_additively(
    tmp_path: Path, monkeypatch
) -> None:
    database_url = f"sqlite:///{tmp_path / 'incident-migration.sqlite3'}"
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "0007_pipeline_runs")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        analysis_id = connection.execute(
            text(
                "INSERT INTO analyses "
                "(original_filename, file_size_bytes, capture_format, status, packet_count, "
                "flow_generation_status, flow_count) "
                "VALUES ('SYNTHETIC-retained.pcap', 64, 'pcap', 'completed', 0, 'completed', 0)"
            )
        ).lastrowid
        assert analysis_id is not None

    command.upgrade(config, "head")
    with engine.begin() as connection:
        incident_id = connection.execute(
            text(
                "INSERT INTO incidents (title, description, status, priority) "
                "VALUES ('Synthetic migration record', '', 'open', 'low')"
            )
        ).lastrowid
        assert incident_id is not None
        assert connection.scalar(text("SELECT COUNT(*) FROM analyses")) == 1
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0009_evaluation_runs"
        )

    command.downgrade(config, "0007_pipeline_runs")
    inspector = inspect(engine)
    assert "incidents" not in inspector.get_table_names()
    assert "evaluation_runs" not in inspector.get_table_names()
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM analyses")) == 1
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0007_pipeline_runs"
        )
    engine.dispose()
