from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, text

from alembic import command
from app.core.config import settings


def test_migration_0007_preserves_analysis_and_prior_stage_tables(
    tmp_path: Path, monkeypatch
) -> None:
    database_url = f"sqlite:///{tmp_path / 'pipeline-migration.sqlite3'}"
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "0006_hybrid_assessments")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        analysis_id = connection.execute(
            text(
                "INSERT INTO analyses "
                "(original_filename, file_size_bytes, capture_format, status, packet_count, "
                "flow_generation_status, flow_count) "
                "VALUES ('synthetic.pcap', 64, 'pcap', 'completed', 0, 'completed', 0)"
            )
        ).lastrowid

    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM analyses")) == 1
        assert connection.scalar(text("SELECT COUNT(*) FROM network_flows")) == 0
        assert connection.scalar(text("SELECT COUNT(*) FROM detection_runs")) == 0
        assert connection.scalar(text("SELECT COUNT(*) FROM anomaly_models")) == 0
        assert connection.scalar(text("SELECT COUNT(*) FROM hybrid_assessments")) == 0
        assert connection.scalar(text("SELECT analysis_id FROM pipeline_runs LIMIT 1")) is None
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0008_incident_investigation"
        )
        assert analysis_id == connection.scalar(text("SELECT id FROM analyses"))
    engine.dispose()
