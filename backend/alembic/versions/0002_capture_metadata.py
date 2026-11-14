"""Add capture metadata and packet metadata.

Revision ID: 0002_capture_metadata
Revises: 0001_create_analyses
"""

import sqlalchemy as sa

from alembic import op

revision = "0002_capture_metadata"
down_revision = "0001_create_analyses"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analyses", sa.Column("original_filename", sa.String(255), nullable=True))
    op.add_column("analyses", sa.Column("storage_key", sa.String(80), nullable=True))
    op.add_column("analyses", sa.Column("file_size_bytes", sa.BigInteger(), nullable=True))
    op.add_column("analyses", sa.Column("capture_format", sa.String(16), nullable=True))
    op.add_column("analyses", sa.Column("status", sa.String(20), nullable=True))
    op.add_column("analyses", sa.Column("packet_count", sa.BigInteger(), nullable=True))
    op.add_column("analyses", sa.Column("error_message", sa.Text(), nullable=True))
    op.add_column("analyses", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(
        "UPDATE analyses SET original_filename = 'legacy-analysis', "
        "file_size_bytes = 0, capture_format = 'unknown', status = 'completed', packet_count = 0 "
        "WHERE original_filename IS NULL"
    )
    with op.batch_alter_table("analyses") as batch_op:
        batch_op.alter_column("original_filename", existing_type=sa.String(255), nullable=False)
        batch_op.alter_column("file_size_bytes", existing_type=sa.BigInteger(), nullable=False)
        batch_op.alter_column("capture_format", existing_type=sa.String(16), nullable=False)
        batch_op.alter_column("status", existing_type=sa.String(20), nullable=False)
        batch_op.alter_column("packet_count", existing_type=sa.BigInteger(), nullable=False)
    op.create_index("uq_analyses_storage_key", "analyses", ["storage_key"], unique=True)
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])
    op.create_table(
        "packet_metadata",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Integer(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("packet_index", sa.BigInteger(), nullable=False),
        sa.Column("timestamp", sa.Numeric(20, 9), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("network_protocol", sa.String(16), nullable=False),
        sa.Column("transport_protocol", sa.String(16), nullable=True),
        sa.Column("ip_protocol_number", sa.Integer(), nullable=True),
        sa.Column("packet_length", sa.Integer(), nullable=False),
        sa.Column("tcp_flags", sa.Integer(), nullable=True),
        sa.Column("icmp_type", sa.Integer(), nullable=True),
        sa.Column("icmp_code", sa.Integer(), nullable=True),
        sa.UniqueConstraint("analysis_id", "packet_index", name="uq_packet_analysis_index"),
    )


def downgrade() -> None:
    op.drop_table("packet_metadata")
    op.drop_index("ix_analyses_created_at", table_name="analyses")
    op.drop_index("uq_analyses_storage_key", table_name="analyses")
    with op.batch_alter_table("analyses") as batch_op:
        batch_op.drop_column("completed_at")
        batch_op.drop_column("error_message")
        batch_op.drop_column("packet_count")
        batch_op.drop_column("status")
        batch_op.drop_column("capture_format")
        batch_op.drop_column("file_size_bytes")
        batch_op.drop_column("storage_key")
        batch_op.drop_column("original_filename")
