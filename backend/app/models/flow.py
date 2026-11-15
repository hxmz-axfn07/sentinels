from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.analysis import Analysis


class NetworkFlow(Base):
    __tablename__ = "network_flows"
    __table_args__ = (
        UniqueConstraint("analysis_id", "flow_id", name="uq_flow_analysis_id"),
        Index("ix_flows_analysis_protocol", "analysis_id", "protocol_name"),
        Index("ix_flows_analysis_endpoint_a", "analysis_id", "endpoint_a_ip"),
        Index("ix_flows_analysis_endpoint_b", "analysis_id", "endpoint_b_ip"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    flow_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_version: Mapped[int | None] = mapped_column(SmallInteger)
    protocol_name: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol_number: Mapped[int | None] = mapped_column(Integer)
    endpoint_a_ip: Mapped[str | None] = mapped_column(String(45))
    endpoint_a_port: Mapped[int | None] = mapped_column(Integer)
    endpoint_b_ip: Mapped[str | None] = mapped_column(String(45))
    endpoint_b_port: Mapped[int | None] = mapped_column(Integer)
    first_packet_source_ip: Mapped[str | None] = mapped_column(String(45))
    first_packet_source_port: Mapped[int | None] = mapped_column(Integer)
    first_packet_destination_ip: Mapped[str | None] = mapped_column(String(45))
    first_packet_destination_port: Mapped[int | None] = mapped_column(Integer)

    first_timestamp: Mapped[Decimal | None] = mapped_column(Numeric(20, 9))
    last_timestamp: Mapped[Decimal | None] = mapped_column(Numeric(20, 9))
    duration_seconds: Mapped[Decimal | None] = mapped_column(Numeric(24, 9))
    total_packets: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    forward_packets: Mapped[int] = mapped_column(BigInteger, nullable=False)
    backward_packets: Mapped[int] = mapped_column(BigInteger, nullable=False)
    forward_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    backward_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    packet_length_min: Mapped[int] = mapped_column(Integer, nullable=False)
    packet_length_max: Mapped[int] = mapped_column(Integer, nullable=False)
    packet_length_mean: Mapped[Decimal] = mapped_column(Numeric(24, 9), nullable=False)
    packet_length_stddev: Mapped[Decimal] = mapped_column(Numeric(24, 9), nullable=False)
    interarrival_min: Mapped[Decimal | None] = mapped_column(Numeric(24, 9))
    interarrival_max: Mapped[Decimal | None] = mapped_column(Numeric(24, 9))
    interarrival_mean: Mapped[Decimal | None] = mapped_column(Numeric(24, 9))
    interarrival_stddev: Mapped[Decimal | None] = mapped_column(Numeric(24, 9))

    syn_count: Mapped[int | None] = mapped_column(BigInteger)
    ack_count: Mapped[int | None] = mapped_column(BigInteger)
    fin_count: Mapped[int | None] = mapped_column(BigInteger)
    rst_count: Mapped[int | None] = mapped_column(BigInteger)
    psh_count: Mapped[int | None] = mapped_column(BigInteger)
    urg_count: Mapped[int | None] = mapped_column(BigInteger)
    forward_syn_only_count: Mapped[int | None] = mapped_column(BigInteger)
    backward_syn_only_count: Mapped[int | None] = mapped_column(BigInteger)
    forward_syn_ack_count: Mapped[int | None] = mapped_column(BigInteger)
    backward_syn_ack_count: Mapped[int | None] = mapped_column(BigInteger)
    packets_per_second: Mapped[Decimal | None] = mapped_column(Numeric(24, 9))
    bytes_per_second: Mapped[Decimal | None] = mapped_column(Numeric(24, 9))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    analysis: Mapped["Analysis"] = relationship(back_populates="flows")
