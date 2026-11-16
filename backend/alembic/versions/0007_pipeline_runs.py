"""Persist pipeline run and stage execution state.

Downgrade deletes pipeline orchestration history, but leaves analyses, flows,
rule findings, ML results, and hybrid assessments intact.

Revision ID: 0007_pipeline_runs
Revises: 0006_hybrid_assessments
"""

import sqlalchemy as sa

from alembic import op

revision = "0007_pipeline_runs"
down_revision = "0006_hybrid_assessments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pipeline_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("pipeline_version", sa.String(32), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("requested_stages", sa.JSON(), nullable=False),
        sa.Column("model_id", sa.Integer()),
        sa.Column("model_version", sa.String(36)),
        sa.Column("detection_run_id", sa.Integer()),
        sa.Column("hybrid_assessment_id", sa.Integer()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("failure_summary", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["model_id", "model_version"],
            ["anomaly_models.id", "anomaly_models.model_version"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["detection_run_id", "analysis_id"],
            ["detection_runs.id", "detection_runs.analysis_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["hybrid_assessment_id", "analysis_id"],
            ["hybrid_assessments.id", "hybrid_assessments.analysis_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("id", "analysis_id", name="uq_pipeline_run_analysis"),
        sa.CheckConstraint("status IN ('running', 'completed', 'failed')", name="ck_pipeline_run_status"),
    )
    op.create_index("ix_pipeline_runs_analysis_created", "pipeline_runs", ["analysis_id", "created_at"])
    op.create_index("ix_pipeline_runs_analysis_status", "pipeline_runs", ["analysis_id", "status"])
    op.create_table(
        "pipeline_stage_executions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("stage", sa.String(16), nullable=False),
        sa.Column("execution_order", sa.Integer(), nullable=False),
        sa.Column("requested", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reused", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("result_summary", sa.JSON()),
        sa.Column("error_summary", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["run_id", "analysis_id"],
            ["pipeline_runs.id", "pipeline_runs.analysis_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("run_id", "stage", name="uq_pipeline_run_stage"),
        sa.UniqueConstraint("run_id", "execution_order", name="uq_pipeline_stage_order"),
        sa.CheckConstraint(
            "stage IN ('flows', 'detection', 'inference', 'hybrid')", name="ck_pipeline_stage_name"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'skipped', 'failed')",
            name="ck_pipeline_stage_status",
        ),
    )
    op.create_index(
        "ix_pipeline_stages_analysis_status", "pipeline_stage_executions", ["analysis_id", "status"]
    )


def downgrade() -> None:
    op.drop_index("ix_pipeline_stages_analysis_status", table_name="pipeline_stage_executions")
    op.drop_table("pipeline_stage_executions")
    op.drop_index("ix_pipeline_runs_analysis_status", table_name="pipeline_runs")
    op.drop_index("ix_pipeline_runs_analysis_created", table_name="pipeline_runs")
    op.drop_table("pipeline_runs")
