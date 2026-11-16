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


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["model_id", "model_version"],
            ["anomaly_models.id", "anomaly_models.model_version"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["detection_run_id", "analysis_id"],
            ["detection_runs.id", "detection_runs.analysis_id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["hybrid_assessment_id", "analysis_id"],
            ["hybrid_assessments.id", "hybrid_assessments.analysis_id"],
            ondelete="RESTRICT",
        ),
        UniqueConstraint("id", "analysis_id", name="uq_pipeline_run_analysis"),
        Index("ix_pipeline_runs_analysis_created", "analysis_id", "created_at"),
        Index("ix_pipeline_runs_analysis_status", "analysis_id", "status"),
        CheckConstraint(
            "status IN ('running', 'completed', 'failed')", name="ck_pipeline_run_status"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    pipeline_version: Mapped[str] = mapped_column(String(32), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_stages: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    model_id: Mapped[int | None] = mapped_column(Integer)
    model_version: Mapped[str | None] = mapped_column(String(36))
    detection_run_id: Mapped[int | None] = mapped_column(Integer)
    hybrid_assessment_id: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    failure_summary: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    stages: Mapped[list["PipelineStageExecution"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="PipelineStageExecution.execution_order",
    )


class PipelineStageExecution(Base):
    __tablename__ = "pipeline_stage_executions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "analysis_id"],
            ["pipeline_runs.id", "pipeline_runs.analysis_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("run_id", "stage", name="uq_pipeline_run_stage"),
        UniqueConstraint("run_id", "execution_order", name="uq_pipeline_stage_order"),
        Index("ix_pipeline_stages_analysis_status", "analysis_id", "status"),
        CheckConstraint(
            "stage IN ('flows', 'detection', 'inference', 'hybrid')", name="ck_pipeline_stage_name"
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'skipped', 'failed')",
            name="ck_pipeline_stage_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(Integer, nullable=False)
    analysis_id: Mapped[int] = mapped_column(Integer, nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    execution_order: Mapped[int] = mapped_column(Integer, nullable=False)
    requested: Mapped[bool] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    reused: Mapped[bool] = mapped_column(nullable=False, default=False)
    result_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error_summary: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    run: Mapped[PipelineRun] = relationship(back_populates="stages")
