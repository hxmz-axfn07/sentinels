"""Persist versioned hybrid assessments and source evidence.

Downgrade deletes Day 6 assessment, group, and evidence rows. Day 4 findings and
Day 5 inference results remain intact.

Revision ID: 0006_hybrid_assessments
Revises: 0005_isolation_forest
"""

import sqlalchemy as sa

from alembic import op

revision = "0006_hybrid_assessments"
down_revision = "0005_isolation_forest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Unique indexes make source references enforceable as composite foreign keys
    # on MySQL and SQLite without rebuilding the existing tables.
    op.create_index(
        "uq_detection_finding_source",
        "detection_findings",
        ["id", "run_id", "analysis_id"],
        unique=True,
    )
    op.create_index(
        "uq_ml_result_source",
        "ml_inference_results",
        ["id", "analysis_id", "model_id", "model_version"],
        unique=True,
    )
    op.create_table(
        "hybrid_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("detection_run_id", sa.Integer(), nullable=False),
        sa.Column("model_id", sa.Integer(), nullable=False),
        sa.Column("model_version", sa.String(36), nullable=False),
        sa.Column("scoring_config_version", sa.String(32), nullable=False),
        sa.Column("scoring_config_hash", sa.String(64), nullable=False),
        sa.Column("scoring_config", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("rule_evidence_count", sa.BigInteger(), nullable=False),
        sa.Column("ml_anomaly_count", sa.BigInteger(), nullable=False),
        sa.Column("correlated_evidence_count", sa.BigInteger(), nullable=False),
        sa.Column("risk_group_count", sa.BigInteger(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["detection_run_id", "analysis_id"],
            ["detection_runs.id", "detection_runs.analysis_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["model_id", "model_version"],
            ["anomaly_models.id", "anomaly_models.model_version"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "analysis_id",
            "detection_run_id",
            "model_id",
            "scoring_config_hash",
            name="uq_hybrid_assessment_inputs",
        ),
        sa.UniqueConstraint(
            "id",
            "analysis_id",
            "detection_run_id",
            "model_id",
            "model_version",
            name="uq_hybrid_assessment_context",
        ),
        sa.UniqueConstraint("id", "analysis_id", name="uq_hybrid_assessment_analysis"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_hybrid_score_range"),
        sa.CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_hybrid_assessment_severity",
        ),
    )
    op.create_index(
        "ix_hybrid_assessments_analysis_created",
        "hybrid_assessments",
        ["analysis_id", "created_at"],
    )
    op.create_table(
        "hybrid_risk_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("group_key", sa.String(64), nullable=False),
        sa.Column("correlation_level", sa.String(24), nullable=False),
        sa.Column("endpoint_a_ip", sa.String(45)),
        sa.Column("endpoint_b_ip", sa.String(45)),
        sa.Column("protocol_name", sa.String(32)),
        sa.Column("risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("rule_component", sa.Numeric(5, 2), nullable=False),
        sa.Column("ml_component", sa.Numeric(5, 2), nullable=False),
        sa.Column("exact_flow_bonus", sa.Numeric(5, 2), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("rule_evidence_count", sa.BigInteger(), nullable=False),
        sa.Column("ml_anomaly_count", sa.BigInteger(), nullable=False),
        sa.Column("correlated_flow_count", sa.BigInteger(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id", "analysis_id"],
            ["hybrid_assessments.id", "hybrid_assessments.analysis_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("assessment_id", "group_key", name="uq_hybrid_group_key"),
        sa.UniqueConstraint("id", "assessment_id", "analysis_id", name="uq_hybrid_group_context"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_hybrid_group_score"),
        sa.CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_hybrid_group_severity",
        ),
        sa.CheckConstraint(
            "correlation_level IN ('exact_flow', 'endpoint_pair', 'rule_only', "
            "'ml_only', 'flow_only')",
            name="ck_hybrid_correlation_level",
        ),
    )
    op.create_index(
        "ix_hybrid_groups_assessment_severity", "hybrid_risk_groups", ["assessment_id", "severity"]
    )
    op.create_table(
        "hybrid_evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("assessment_id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("detection_run_id", sa.Integer(), nullable=False),
        sa.Column("model_id", sa.Integer(), nullable=False),
        sa.Column("model_version", sa.String(36), nullable=False),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("detection_finding_id", sa.Integer()),
        sa.Column("anomaly_result_id", sa.Integer()),
        sa.Column("flow_id", sa.String(64)),
        sa.Column("rule_id", sa.String(64)),
        sa.Column("rule_name", sa.String(120)),
        sa.Column("original_severity", sa.String(16)),
        sa.Column("prediction", sa.String(16)),
        sa.Column("anomaly_score", sa.Numeric(24, 12)),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["group_id", "assessment_id", "analysis_id"],
            [
                "hybrid_risk_groups.id",
                "hybrid_risk_groups.assessment_id",
                "hybrid_risk_groups.analysis_id",
            ],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id", "analysis_id", "detection_run_id", "model_id", "model_version"],
            [
                "hybrid_assessments.id",
                "hybrid_assessments.analysis_id",
                "hybrid_assessments.detection_run_id",
                "hybrid_assessments.model_id",
                "hybrid_assessments.model_version",
            ],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["detection_finding_id", "detection_run_id", "analysis_id"],
            [
                "detection_findings.id",
                "detection_findings.run_id",
                "detection_findings.analysis_id",
            ],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["anomaly_result_id", "analysis_id", "model_id", "model_version"],
            [
                "ml_inference_results.id",
                "ml_inference_results.analysis_id",
                "ml_inference_results.model_id",
                "ml_inference_results.model_version",
            ],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("group_id", "source", "source_id", name="uq_hybrid_evidence_source"),
        sa.CheckConstraint(
            "(source = 'rule' AND detection_finding_id IS NOT NULL AND anomaly_result_id IS NULL "
            "AND source_id = detection_finding_id) OR (source = 'ml' "
            "AND anomaly_result_id IS NOT NULL AND detection_finding_id IS NULL "
            "AND source_id = anomaly_result_id)",
            name="ck_hybrid_evidence_source_ref",
        ),
    )
    op.create_index(
        "ix_hybrid_evidence_assessment_source", "hybrid_evidence", ["assessment_id", "source"]
    )


def downgrade() -> None:
    op.drop_index("ix_hybrid_evidence_assessment_source", table_name="hybrid_evidence")
    op.drop_table("hybrid_evidence")
    op.drop_index("ix_hybrid_groups_assessment_severity", table_name="hybrid_risk_groups")
    op.drop_table("hybrid_risk_groups")
    op.drop_index("ix_hybrid_assessments_analysis_created", table_name="hybrid_assessments")
    op.drop_table("hybrid_assessments")
    op.drop_index("uq_ml_result_source", table_name="ml_inference_results")
    op.drop_index("uq_detection_finding_source", table_name="detection_findings")
