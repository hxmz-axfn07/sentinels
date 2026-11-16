from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class HybridAssessment(Base):
    __tablename__ = "hybrid_assessments"
    __table_args__ = (
        ForeignKeyConstraint(
            ["detection_run_id", "analysis_id"],
            ["detection_runs.id", "detection_runs.analysis_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["model_id", "model_version"],
            ["anomaly_models.id", "anomaly_models.model_version"],
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "analysis_id",
            "detection_run_id",
            "model_id",
            "scoring_config_hash",
            name="uq_hybrid_assessment_inputs",
        ),
        UniqueConstraint(
            "id",
            "analysis_id",
            "detection_run_id",
            "model_id",
            "model_version",
            name="uq_hybrid_assessment_context",
        ),
        UniqueConstraint("id", "analysis_id", name="uq_hybrid_assessment_analysis"),
        Index("ix_hybrid_assessments_analysis_created", "analysis_id", "created_at"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_hybrid_score_range"),
        CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_hybrid_assessment_severity",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(Integer, nullable=False)
    detection_run_id: Mapped[int] = mapped_column(Integer, nullable=False)
    model_id: Mapped[int] = mapped_column(Integer, nullable=False)
    model_version: Mapped[str] = mapped_column(String(36), nullable=False)
    scoring_config_version: Mapped[str] = mapped_column(String(32), nullable=False)
    scoring_config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scoring_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    rule_evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ml_anomaly_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    correlated_evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    risk_group_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    groups: Mapped[list["HybridRiskGroup"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", passive_deletes=True
    )


class HybridRiskGroup(Base):
    __tablename__ = "hybrid_risk_groups"
    __table_args__ = (
        ForeignKeyConstraint(
            ["assessment_id", "analysis_id"],
            ["hybrid_assessments.id", "hybrid_assessments.analysis_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("assessment_id", "group_key", name="uq_hybrid_group_key"),
        UniqueConstraint("id", "assessment_id", "analysis_id", name="uq_hybrid_group_context"),
        Index("ix_hybrid_groups_assessment_severity", "assessment_id", "severity"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_hybrid_group_score"),
        CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_hybrid_group_severity",
        ),
        CheckConstraint(
            "correlation_level IN ('exact_flow', 'endpoint_pair', 'rule_only', "
            "'ml_only', 'flow_only')",
            name="ck_hybrid_correlation_level",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(Integer, nullable=False)
    analysis_id: Mapped[int] = mapped_column(Integer, nullable=False)
    group_key: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_level: Mapped[str] = mapped_column(String(24), nullable=False)
    endpoint_a_ip: Mapped[str | None] = mapped_column(String(45))
    endpoint_b_ip: Mapped[str | None] = mapped_column(String(45))
    protocol_name: Mapped[str | None] = mapped_column(String(32))
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    rule_component: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    ml_component: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    exact_flow_bonus: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    rule_evidence_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ml_anomaly_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    correlated_flow_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    assessment: Mapped[HybridAssessment] = relationship(back_populates="groups")
    evidence_items: Mapped[list["HybridEvidence"]] = relationship(
        back_populates="group", cascade="all, delete-orphan", passive_deletes=True
    )


class HybridEvidence(Base):
    __tablename__ = "hybrid_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["group_id", "assessment_id", "analysis_id"],
            [
                "hybrid_risk_groups.id",
                "hybrid_risk_groups.assessment_id",
                "hybrid_risk_groups.analysis_id",
            ],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["assessment_id", "analysis_id", "detection_run_id", "model_id", "model_version"],
            [
                "hybrid_assessments.id",
                "hybrid_assessments.analysis_id",
                "hybrid_assessments.detection_run_id",
                "hybrid_assessments.model_id",
                "hybrid_assessments.model_version",
            ],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["detection_finding_id", "detection_run_id", "analysis_id"],
            [
                "detection_findings.id",
                "detection_findings.run_id",
                "detection_findings.analysis_id",
            ],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["anomaly_result_id", "analysis_id", "model_id", "model_version"],
            [
                "ml_inference_results.id",
                "ml_inference_results.analysis_id",
                "ml_inference_results.model_id",
                "ml_inference_results.model_version",
            ],
            ondelete="CASCADE",
        ),
        UniqueConstraint("group_id", "source", "source_id", name="uq_hybrid_evidence_source"),
        Index("ix_hybrid_evidence_assessment_source", "assessment_id", "source"),
        CheckConstraint(
            "(source = 'rule' AND detection_finding_id IS NOT NULL AND anomaly_result_id IS NULL "
            "AND source_id = detection_finding_id) OR (source = 'ml' "
            "AND anomaly_result_id IS NOT NULL AND detection_finding_id IS NULL "
            "AND source_id = anomaly_result_id)",
            name="ck_hybrid_evidence_source_ref",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(Integer, nullable=False)
    assessment_id: Mapped[int] = mapped_column(Integer, nullable=False)
    analysis_id: Mapped[int] = mapped_column(Integer, nullable=False)
    detection_run_id: Mapped[int] = mapped_column(Integer, nullable=False)
    model_id: Mapped[int] = mapped_column(Integer, nullable=False)
    model_version: Mapped[str] = mapped_column(String(36), nullable=False)
    source: Mapped[str] = mapped_column(String(8), nullable=False)
    source_id: Mapped[int] = mapped_column(Integer, nullable=False)
    detection_finding_id: Mapped[int | None] = mapped_column(Integer)
    anomaly_result_id: Mapped[int | None] = mapped_column(Integer)
    flow_id: Mapped[str | None] = mapped_column(String(64))
    rule_id: Mapped[str | None] = mapped_column(String(64))
    rule_name: Mapped[str | None] = mapped_column(String(120))
    original_severity: Mapped[str | None] = mapped_column(String(16))
    prediction: Mapped[str | None] = mapped_column(String(16))
    anomaly_score: Mapped[Decimal | None] = mapped_column(Numeric(24, 12))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    group: Mapped[HybridRiskGroup] = relationship(back_populates="evidence_items")
