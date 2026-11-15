"""Persist bidirectional network flows.

Downgrade is data-destructive: it removes generated flow rows and packet flow
assignments, then drops flow-generation state from analyses.

Revision ID: 0003_bidirectional_flows
Revises: 0002_capture_metadata
"""

import sqlalchemy as sa

from alembic import op

revision = "0003_bidirectional_flows"
down_revision = "0002_capture_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analyses",
        sa.Column(
            "flow_generation_status",
            sa.String(20),
            server_default="not_started",
            nullable=False,
        ),
    )
    op.add_column(
        "analyses",
        sa.Column("flow_count", sa.BigInteger(), server_default="0", nullable=False),
    )
    op.add_column("analyses", sa.Column("flow_error_message", sa.Text(), nullable=True))
    op.add_column(
        "analyses", sa.Column("flows_generated_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index(
        "ix_packet_analysis_timestamp",
        "packet_metadata",
        ["analysis_id", "timestamp", "packet_index"],
    )
    op.add_column("packet_metadata", sa.Column("flow_id", sa.String(64), nullable=True))
    op.add_column("packet_metadata", sa.Column("flow_forward", sa.Boolean(), nullable=True))
    op.create_index(
        "ix_packet_analysis_flow_timestamp",
        "packet_metadata",
        ["analysis_id", "flow_id", "timestamp", "packet_index"],
    )
    op.create_table(
        "network_flows",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Integer(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("ip_version", sa.SmallInteger(), nullable=True),
        sa.Column("protocol_name", sa.String(32), nullable=False),
        sa.Column("protocol_number", sa.Integer(), nullable=True),
        sa.Column("endpoint_a_ip", sa.String(45), nullable=True),
        sa.Column("endpoint_a_port", sa.Integer(), nullable=True),
        sa.Column("endpoint_b_ip", sa.String(45), nullable=True),
        sa.Column("endpoint_b_port", sa.Integer(), nullable=True),
        sa.Column("first_packet_source_ip", sa.String(45), nullable=True),
        sa.Column("first_packet_source_port", sa.Integer(), nullable=True),
        sa.Column("first_packet_destination_ip", sa.String(45), nullable=True),
        sa.Column("first_packet_destination_port", sa.Integer(), nullable=True),
        sa.Column("first_timestamp", sa.Numeric(20, 9), nullable=True),
        sa.Column("last_timestamp", sa.Numeric(20, 9), nullable=True),
        sa.Column("duration_seconds", sa.Numeric(24, 9), nullable=True),
        sa.Column("total_packets", sa.BigInteger(), nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("forward_packets", sa.BigInteger(), nullable=False),
        sa.Column("backward_packets", sa.BigInteger(), nullable=False),
        sa.Column("forward_bytes", sa.BigInteger(), nullable=False),
        sa.Column("backward_bytes", sa.BigInteger(), nullable=False),
        sa.Column("packet_length_min", sa.Integer(), nullable=False),
        sa.Column("packet_length_max", sa.Integer(), nullable=False),
        sa.Column("packet_length_mean", sa.Numeric(24, 9), nullable=False),
        sa.Column("packet_length_stddev", sa.Numeric(24, 9), nullable=False),
        sa.Column("interarrival_min", sa.Numeric(24, 9), nullable=True),
        sa.Column("interarrival_max", sa.Numeric(24, 9), nullable=True),
        sa.Column("interarrival_mean", sa.Numeric(24, 9), nullable=True),
        sa.Column("interarrival_stddev", sa.Numeric(24, 9), nullable=True),
        sa.Column("syn_count", sa.BigInteger(), nullable=True),
        sa.Column("ack_count", sa.BigInteger(), nullable=True),
        sa.Column("fin_count", sa.BigInteger(), nullable=True),
        sa.Column("rst_count", sa.BigInteger(), nullable=True),
        sa.Column("psh_count", sa.BigInteger(), nullable=True),
        sa.Column("urg_count", sa.BigInteger(), nullable=True),
        sa.Column("packets_per_second", sa.Numeric(24, 9), nullable=True),
        sa.Column("bytes_per_second", sa.Numeric(24, 9), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("analysis_id", "flow_id", name="uq_flow_analysis_id"),
    )
    op.create_index("ix_flows_analysis_protocol", "network_flows", ["analysis_id", "protocol_name"])
    op.create_index(
        "ix_flows_analysis_endpoint_a", "network_flows", ["analysis_id", "endpoint_a_ip"]
    )
    op.create_index(
        "ix_flows_analysis_endpoint_b", "network_flows", ["analysis_id", "endpoint_b_ip"]
    )


def downgrade() -> None:
    op.drop_table("network_flows")
    op.drop_index("ix_packet_analysis_flow_timestamp", table_name="packet_metadata")
    op.drop_column("packet_metadata", "flow_forward")
    op.drop_column("packet_metadata", "flow_id")
    op.drop_index("ix_packet_analysis_timestamp", table_name="packet_metadata")
    op.drop_column("analyses", "flows_generated_at")
    op.drop_column("analyses", "flow_error_message")
    op.drop_column("analyses", "flow_count")
    op.drop_column("analyses", "flow_generation_status")
