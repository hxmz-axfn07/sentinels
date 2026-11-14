from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, ForeignKey, Index, Integer, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.analysis import Analysis


class PacketRecord(Base):
    __tablename__ = "packet_metadata"
    __table_args__ = (
        Index("uq_packet_analysis_index", "analysis_id", "packet_index", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    packet_index: Mapped[int] = mapped_column(BigInteger, nullable=False)
    timestamp: Mapped[Decimal | None] = mapped_column(Numeric(20, 9))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    network_protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    transport_protocol: Mapped[str | None] = mapped_column(String(16))
    ip_protocol_number: Mapped[int | None] = mapped_column(Integer)
    packet_length: Mapped[int] = mapped_column(Integer, nullable=False)
    tcp_flags: Mapped[int | None] = mapped_column(Integer)
    icmp_type: Mapped[int | None] = mapped_column(Integer)
    icmp_code: Mapped[int | None] = mapped_column(Integer)

    analysis: Mapped["Analysis"] = relationship(back_populates="packets")
