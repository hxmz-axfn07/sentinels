"""Add directional TCP handshake metadata and rule-based findings.

Downgrade is data-destructive: it drops detection runs/findings and removes the
directional TCP flag counts added to flow records.

Revision ID: 0004_rule_based_detection
Revises: 0003_bidirectional_flows
"""

import sqlalchemy as sa

from alembic import op

revision = "0004_rule_based_detection"
down_revision = "0003_bidirectional_flows"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for column in (
        "forward_syn_only_count",
        "backward_syn_only_count",
        "forward_syn_ack_count",
        "backward_syn_ack_count",
    ):
        op.add_column("network_flows", sa.Column(column, sa.BigInteger(), nullable=True))

    _backfill_directional_tcp_flags()

    op.create_table(
        "detection_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Integer(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("config_snapshot", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("finding_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("analysis_id", "config_hash", name="uq_detection_analysis_config"),
        sa.UniqueConstraint("id", "analysis_id", name="uq_detection_run_analysis"),
        sa.CheckConstraint(
            "status IN ('processing', 'completed', 'failed')", name="ck_detection_run_status"
        ),
    )
    op.create_index(
        "ix_detection_runs_analysis_created", "detection_runs", ["analysis_id", "created_at"]
    )

    op.create_table(
        "detection_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("finding_key", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("rule_name", sa.String(120), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("protocol_name", sa.String(32), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("supporting_flow_count", sa.BigInteger(), nullable=False),
        sa.Column(
            "supporting_flow_sample_truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "analysis_id"],
            ["detection_runs.id", "detection_runs.analysis_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("run_id", "finding_key", name="uq_detection_finding_key"),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_detection_finding_severity",
        ),
    )
    op.create_index(
        "ix_findings_analysis_severity", "detection_findings", ["analysis_id", "severity"]
    )
    op.create_index("ix_findings_analysis_rule", "detection_findings", ["analysis_id", "rule_id"])
    op.create_index("ix_findings_run", "detection_findings", ["run_id"])

    op.create_table(
        "detection_finding_flows",
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("detection_findings.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "flow_id",
            sa.Integer(),
            sa.ForeignKey("network_flows.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )


def _backfill_directional_tcp_flags() -> None:
    bind = op.get_bind()
    aggregate = """
        SELECT analysis_id, flow_id,
            CASE WHEN SUM(CASE WHEN flow_forward = 1 AND tcp_flags IS NOT NULL
                               THEN 1 ELSE 0 END) = 0
                 THEN NULL ELSE SUM(CASE WHEN flow_forward = 1 AND tcp_flags IS NOT NULL
                     AND (tcp_flags & 2) != 0 AND (tcp_flags & 16) = 0 THEN 1 ELSE 0 END) END
                 AS forward_syn_only_count,
            CASE WHEN SUM(CASE WHEN flow_forward = 0 AND tcp_flags IS NOT NULL
                               THEN 1 ELSE 0 END) = 0
                 THEN NULL ELSE SUM(CASE WHEN flow_forward = 0 AND tcp_flags IS NOT NULL
                     AND (tcp_flags & 2) != 0 AND (tcp_flags & 16) = 0 THEN 1 ELSE 0 END) END
                 AS backward_syn_only_count,
            CASE WHEN SUM(CASE WHEN flow_forward = 1 AND tcp_flags IS NOT NULL
                               THEN 1 ELSE 0 END) = 0
                 THEN NULL ELSE SUM(CASE WHEN flow_forward = 1 AND tcp_flags IS NOT NULL
                     AND (tcp_flags & 18) = 18 THEN 1 ELSE 0 END) END
                 AS forward_syn_ack_count,
            CASE WHEN SUM(CASE WHEN flow_forward = 0 AND tcp_flags IS NOT NULL
                               THEN 1 ELSE 0 END) = 0
                 THEN NULL ELSE SUM(CASE WHEN flow_forward = 0 AND tcp_flags IS NOT NULL
                     AND (tcp_flags & 18) = 18 THEN 1 ELSE 0 END) END
                 AS backward_syn_ack_count
        FROM packet_metadata
        WHERE flow_id IS NOT NULL AND flow_forward IS NOT NULL
        GROUP BY analysis_id, flow_id
    """
    if bind.dialect.name == "mysql":
        op.execute(
            sa.text(
                "UPDATE network_flows AS f JOIN (" + aggregate + ") AS p "
                "ON f.analysis_id = p.analysis_id AND f.flow_id = p.flow_id "
                "SET f.forward_syn_only_count = p.forward_syn_only_count, "
                "f.backward_syn_only_count = p.backward_syn_only_count, "
                "f.forward_syn_ack_count = p.forward_syn_ack_count, "
                "f.backward_syn_ack_count = p.backward_syn_ack_count"
            )
        )
    else:
        op.execute(
            sa.text(
                "UPDATE network_flows AS f SET "
                "forward_syn_only_count = p.forward_syn_only_count, "
                "backward_syn_only_count = p.backward_syn_only_count, "
                "forward_syn_ack_count = p.forward_syn_ack_count, "
                "backward_syn_ack_count = p.backward_syn_ack_count FROM ("
                + aggregate
                + ") AS p WHERE f.analysis_id = p.analysis_id AND f.flow_id = p.flow_id"
            )
        )


def downgrade() -> None:
    op.drop_table("detection_finding_flows")
    op.drop_index("ix_findings_run", table_name="detection_findings")
    op.drop_index("ix_findings_analysis_rule", table_name="detection_findings")
    op.drop_index("ix_findings_analysis_severity", table_name="detection_findings")
    op.drop_table("detection_findings")
    op.drop_index("ix_detection_runs_analysis_created", table_name="detection_runs")
    op.drop_table("detection_runs")
    for column in (
        "forward_syn_only_count",
        "backward_syn_only_count",
        "forward_syn_ack_count",
        "backward_syn_ack_count",
    ):
        op.drop_column("network_flows", column)
