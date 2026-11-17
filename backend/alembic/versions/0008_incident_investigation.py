"""Add analyst-managed incident investigation records.

This revision adds incident records, source references, append-only notes, and
history. Downgrade removes these incident-specific records and is destructive
to investigation data; detection source records are not modified.

Revision ID: 0008_incident_investigation
Revises: 0007_pipeline_runs
"""

import sqlalchemy as sa

from alembic import op

revision = "0008_incident_investigation"
down_revision = "0007_pipeline_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(100)),
        sa.Column("assigned_to", sa.String(100)),
        sa.Column("resolution_summary", sa.Text()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged', 'investigating', 'resolved', 'closed')",
            name="ck_incident_status",
        ),
        sa.CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="ck_incident_priority",
        ),
    )
    op.create_index("ix_incidents_status_updated", "incidents", ["status", "updated_at"])
    op.create_index("ix_incidents_priority_updated", "incidents", ["priority", "updated_at"])

    op.create_table(
        "incident_evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("source_type", sa.String(24), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("detection_finding_id", sa.Integer()),
        sa.Column("detection_run_id", sa.Integer()),
        sa.Column("anomaly_result_id", sa.Integer()),
        sa.Column("model_id", sa.Integer()),
        sa.Column("model_version", sa.String(36)),
        sa.Column("hybrid_assessment_id", sa.Integer()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["detection_finding_id", "detection_run_id", "analysis_id"],
            [
                "detection_findings.id",
                "detection_findings.run_id",
                "detection_findings.analysis_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["anomaly_result_id", "analysis_id", "model_id", "model_version"],
            [
                "ml_inference_results.id",
                "ml_inference_results.analysis_id",
                "ml_inference_results.model_id",
                "ml_inference_results.model_version",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["hybrid_assessment_id", "analysis_id"],
            ["hybrid_assessments.id", "hybrid_assessments.analysis_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "incident_id", "source_type", "source_id", name="uq_incident_evidence_source"
        ),
        sa.UniqueConstraint("id", "analysis_id", name="uq_incident_evidence_analysis"),
        sa.CheckConstraint(
            "(source_type = 'rule_finding' AND detection_finding_id IS NOT NULL "
            "AND detection_run_id IS NOT NULL AND anomaly_result_id IS NULL "
            "AND hybrid_assessment_id IS NULL AND model_id IS NULL AND model_version IS NULL "
            "AND source_id = detection_finding_id) OR "
            "(source_type = 'ml_anomaly' AND anomaly_result_id IS NOT NULL "
            "AND model_id IS NOT NULL AND model_version IS NOT NULL "
            "AND detection_finding_id IS NULL AND detection_run_id IS NULL "
            "AND hybrid_assessment_id IS NULL AND source_id = anomaly_result_id) OR "
            "(source_type = 'hybrid_assessment' AND hybrid_assessment_id IS NOT NULL "
            "AND detection_finding_id IS NULL AND detection_run_id IS NULL "
            "AND anomaly_result_id IS NULL AND model_id IS NULL AND model_version IS NULL "
            "AND source_id = hybrid_assessment_id)",
            name="ck_incident_evidence_source_ref",
        ),
    )
    op.create_index("ix_incident_evidence_analysis", "incident_evidence", ["analysis_id"])

    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(100)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_incident_notes_incident_created", "incident_notes", ["incident_id", "created_at"]
    )

    op.create_table(
        "incident_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("actor", sa.String(100)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_incident_history_incident_created", "incident_history", ["incident_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_incident_history_incident_created", table_name="incident_history")
    op.drop_table("incident_history")
    op.drop_index("ix_incident_notes_incident_created", table_name="incident_notes")
    op.drop_table("incident_notes")
    op.drop_index("ix_incident_evidence_analysis", table_name="incident_evidence")
    op.drop_table("incident_evidence")
    op.drop_index("ix_incidents_priority_updated", table_name="incidents")
    op.drop_index("ix_incidents_status_updated", table_name="incidents")
    op.drop_table("incidents")
