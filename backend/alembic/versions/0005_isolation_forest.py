"""Persist Isolation Forest model metadata and per-flow inference results.

Downgrade is data-destructive: it removes trained model metadata and all
associated inference results. Application-generated artifacts are not removed.

Revision ID: 0005_isolation_forest
Revises: 0004_rule_based_detection
"""

import sqlalchemy as sa

from alembic import op

revision = "0005_isolation_forest"
down_revision = "0004_rule_based_detection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "anomaly_models",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("model_version", sa.String(36), nullable=False),
        sa.Column("algorithm", sa.String(40), nullable=False),
        sa.Column("feature_schema_version", sa.String(32), nullable=False),
        sa.Column("feature_names", sa.JSON(), nullable=False),
        sa.Column("active_feature_names", sa.JSON(), nullable=False),
        sa.Column("preprocessing_config", sa.JSON(), nullable=False),
        sa.Column("isolation_forest_config", sa.JSON(), nullable=False),
        sa.Column("random_seed", sa.Integer(), nullable=False),
        sa.Column("training_analysis_ids", sa.JSON(), nullable=False),
        sa.Column("training_sample_count", sa.BigInteger(), nullable=False),
        sa.Column("training_population_count", sa.BigInteger(), nullable=False),
        sa.Column("sklearn_version", sa.String(32), nullable=False),
        sa.Column("artifact_key", sa.String(80), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("trained_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("model_version", name="uq_anomaly_model_version"),
        sa.UniqueConstraint("id", "model_version", name="uq_anomaly_model_id_version"),
        sa.UniqueConstraint("artifact_key", name="uq_anomaly_models_artifact_key"),
        sa.CheckConstraint("status IN ('ready')", name="ck_anomaly_model_status"),
    )
    op.create_index("ix_anomaly_models_created", "anomaly_models", ["created_at"])

    op.create_table(
        "ml_inference_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("model_id", sa.Integer(), nullable=False),
        sa.Column("model_version", sa.String(36), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("prediction", sa.String(16), nullable=False),
        sa.Column("anomaly_score", sa.Numeric(24, 12), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["model_id", "model_version"],
            ["anomaly_models.id", "anomaly_models.model_version"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_id", "flow_id"],
            ["network_flows.analysis_id", "network_flows.flow_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "analysis_id", "model_id", "flow_id", name="uq_ml_result_analysis_model_flow"
        ),
        sa.CheckConstraint("prediction IN ('normal', 'anomaly')", name="ck_ml_result_prediction"),
    )
    op.create_index(
        "ix_ml_results_analysis_prediction", "ml_inference_results", ["analysis_id", "prediction"]
    )
    op.create_index(
        "ix_ml_results_model_analysis", "ml_inference_results", ["model_id", "analysis_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_ml_results_model_analysis", table_name="ml_inference_results")
    op.drop_index("ix_ml_results_analysis_prediction", table_name="ml_inference_results")
    op.drop_table("ml_inference_results")
    op.drop_index("ix_anomaly_models_created", table_name="anomaly_models")
    op.drop_table("anomaly_models")
