from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, text

from alembic import command
from app.core.config import settings


def test_migration_0006_preserves_day4_and_day5_sources(tmp_path: Path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'hybrid-migration.sqlite3'}"
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "0005_isolation_forest")
    engine = create_engine(database_url)
    flow_key = "e" * 64
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
        run_id = connection.execute(
            text(
                "INSERT INTO detection_runs "
                "(analysis_id, config_hash, config_snapshot, status, finding_count) "
                "VALUES (:analysis, :hash, '{}', 'completed', 1)"
            ),
            {"analysis": analysis_id, "hash": "d" * 64},
        ).lastrowid
        connection.execute(
            text(
                "INSERT INTO detection_findings "
                "(run_id, analysis_id, finding_key, rule_id, rule_name, severity, explanation, "
                "evidence, supporting_flow_count, supporting_flow_sample_truncated) "
                "VALUES (:run, :analysis, :key, 'PORT_SCAN', 'Synthetic rule', 'low', 'synthetic', "
                "'{}', 1, 0)"
            ),
            {"run": run_id, "analysis": analysis_id, "key": "a" * 64},
        )
        model_version = "synthetic-model-v1"
        model_id = connection.execute(
            text(
                "INSERT INTO anomaly_models "
                "(model_version, algorithm, feature_schema_version, feature_names, "
                "active_feature_names, preprocessing_config, isolation_forest_config, random_seed, "
                "training_analysis_ids, training_sample_count, training_population_count, "
                "sklearn_version, artifact_key, status, trained_at) VALUES "
                "(:version, 'IsolationForest', 'flow-v1', '[]', '[]', '{}', '{}', 42, '[]', "
                "20, 20, '1.9.1', :artifact, 'ready', CURRENT_TIMESTAMP)"
            ),
            {"version": model_version, "artifact": "a" * 32 + ".joblib"},
        ).lastrowid
        connection.execute(
            text(
                "INSERT INTO ml_inference_results "
                "(model_id, model_version, analysis_id, flow_id, prediction, anomaly_score) "
                "VALUES (:model, :version, :analysis, :flow, 'anomaly', 0.25)"
            ),
            {
                "model": model_id,
                "version": model_version,
                "analysis": analysis_id,
                "flow": flow_key,
            },
        )

    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM analyses")) == 1
        assert connection.scalar(text("SELECT COUNT(*) FROM detection_findings")) == 1
        assert connection.scalar(text("SELECT COUNT(*) FROM ml_inference_results")) == 1
        assert connection.scalar(text("SELECT COUNT(*) FROM hybrid_assessments")) == 0
        assert connection.scalar(text("SELECT COUNT(*) FROM hybrid_risk_groups")) == 0
        assert connection.scalar(text("SELECT COUNT(*) FROM hybrid_evidence")) == 0
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0006_hybrid_assessments"
        )
    engine.dispose()
