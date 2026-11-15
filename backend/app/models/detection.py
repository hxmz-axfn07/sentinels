from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.analysis import Analysis
    from app.models.flow import NetworkFlow


detection_finding_flows = Table(
    "detection_finding_flows",
    Base.metadata,
    Column(
        "finding_id",
        ForeignKey("detection_findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "flow_id",
        ForeignKey("network_flows.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class DetectionRun(Base):
    __tablename__ = "detection_runs"
    __table_args__ = (
        UniqueConstraint("analysis_id", "config_hash", name="uq_detection_analysis_config"),
        UniqueConstraint("id", "analysis_id", name="uq_detection_run_analysis"),
        Index("ix_detection_runs_analysis_created", "analysis_id", "created_at"),
        CheckConstraint(
            "status IN ('processing', 'completed', 'failed')", name="ck_detection_run_status"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    finding_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    analysis: Mapped["Analysis"] = relationship()
    findings: Mapped[list["DetectionFinding"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", passive_deletes=True
    )


class DetectionFinding(Base):
    __tablename__ = "detection_findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "analysis_id"],
            ["detection_runs.id", "detection_runs.analysis_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("run_id", "finding_key", name="uq_detection_finding_key"),
        Index("ix_findings_analysis_severity", "analysis_id", "severity"),
        Index("ix_findings_analysis_rule", "analysis_id", "rule_id"),
        Index("ix_findings_run", "run_id"),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_detection_finding_severity",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(nullable=False)
    analysis_id: Mapped[int] = mapped_column(nullable=False)
    finding_key: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(120), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    protocol_name: Mapped[str | None] = mapped_column(String(32))
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    supporting_flow_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    supporting_flow_sample_truncated: Mapped[bool] = mapped_column(nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    run: Mapped[DetectionRun] = relationship(back_populates="findings")
    supporting_flows: Mapped[list["NetworkFlow"]] = relationship(
        secondary=detection_finding_flows, lazy="selectin"
    )
