from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from alembic import command
from app.core.config import settings


def test_evaluation_migration_is_additive_and_reversible(tmp_path: Path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'evaluation.sqlite3'}"
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "0008_incident_investigation")
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO incidents (title, description, status, priority) "
                "VALUES ('Synthetic retained incident', '', 'open', 'low')"
            )
        )
    command.upgrade(config, "head")
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO evaluation_runs "
                "(dataset_version, random_seed, repeat_count, status) "
                "VALUES ('synthetic-test', 1101, 1, 'completed')"
            )
        )
        assert connection.scalar(text("SELECT COUNT(*) FROM incidents")) == 1
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0009_evaluation_runs"
        )
    command.downgrade(config, "0008_incident_investigation")
    assert "evaluation_runs" not in inspect(engine).get_table_names()
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM incidents")) == 1
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0008_incident_investigation"
        )
    engine.dispose()
