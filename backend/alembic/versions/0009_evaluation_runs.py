"""Persist reproducible evaluation run metadata and results.

Revision ID: 0009_evaluation_runs
Revises: 0008_incident_investigation
"""

import sqlalchemy as sa

from alembic import op

revision = "0009_evaluation_runs"
down_revision = "0008_incident_investigation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("dataset_version", sa.String(64), nullable=False),
        sa.Column("random_seed", sa.Integer(), nullable=False),
        sa.Column("repeat_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("failure_summary", sa.Text()),
        sa.Column("results", sa.JSON()),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed')", name="ck_evaluation_run_status"
        ),
    )
    op.create_index(
        "ix_evaluation_runs_status_created", "evaluation_runs", ["status", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_evaluation_runs_status_created", table_name="evaluation_runs")
    op.drop_table("evaluation_runs")
