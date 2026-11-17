from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'investigating', 'resolved', 'closed')",
            name="ck_incident_status",
        ),
        CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="ck_incident_priority",
        ),
        Index("ix_incidents_status_updated", "status", "updated_at"),
        Index("ix_incidents_priority_updated", "priority", "updated_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    created_by: Mapped[str | None] = mapped_column(String(100))
    assigned_to: Mapped[str | None] = mapped_column(String(100))
    resolution_summary: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    evidence: Mapped[list["IncidentEvidence"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    notes: Mapped[list["IncidentNote"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    history: Mapped[list["IncidentHistory"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["detection_finding_id", "detection_run_id", "analysis_id"],
            [
                "detection_findings.id",
                "detection_findings.run_id",
                "detection_findings.analysis_id",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["anomaly_result_id", "analysis_id", "model_id", "model_version"],
            [
                "ml_inference_results.id",
                "ml_inference_results.analysis_id",
                "ml_inference_results.model_id",
                "ml_inference_results.model_version",
            ],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["hybrid_assessment_id", "analysis_id"],
            ["hybrid_assessments.id", "hybrid_assessments.analysis_id"],
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "incident_id", "source_type", "source_id", name="uq_incident_evidence_source"
        ),
        UniqueConstraint("id", "analysis_id", name="uq_incident_evidence_analysis"),
        CheckConstraint(
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
        Index("ix_incident_evidence_analysis", "analysis_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="RESTRICT"), nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(24), nullable=False)
    source_id: Mapped[int] = mapped_column(Integer, nullable=False)
    detection_finding_id: Mapped[int | None] = mapped_column(Integer)
    detection_run_id: Mapped[int | None] = mapped_column(Integer)
    anomaly_result_id: Mapped[int | None] = mapped_column(Integer)
    model_id: Mapped[int | None] = mapped_column(Integer)
    model_version: Mapped[str | None] = mapped_column(String(36))
    hybrid_assessment_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    incident: Mapped[Incident] = relationship(back_populates="evidence")


class IncidentNote(Base):
    __tablename__ = "incident_notes"
    __table_args__ = (Index("ix_incident_notes_incident_created", "incident_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    incident: Mapped[Incident] = relationship(back_populates="notes")


class IncidentHistory(Base):
    __tablename__ = "incident_history"
    __table_args__ = (Index("ix_incident_history_incident_created", "incident_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    actor: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    incident: Mapped[Incident] = relationship(back_populates="history")
