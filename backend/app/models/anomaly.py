from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AnomalyModel(Base):
    __tablename__ = "anomaly_models"
    __table_args__ = (
        UniqueConstraint("model_version", name="uq_anomaly_model_version"),
        UniqueConstraint("id", "model_version", name="uq_anomaly_model_id_version"),
        UniqueConstraint("artifact_key", name="uq_anomaly_models_artifact_key"),
        CheckConstraint("status IN ('ready')", name="ck_anomaly_model_status"),
        Index("ix_anomaly_models_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    model_version: Mapped[str] = mapped_column(String(36), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(40), nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    feature_names: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    active_feature_names: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    preprocessing_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    isolation_forest_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    random_seed: Mapped[int] = mapped_column(Integer, nullable=False)
    training_analysis_ids: Mapped[list[int]] = mapped_column(JSON, nullable=False)
    training_sample_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    training_population_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sklearn_version: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact_key: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ready")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AnomalyResult(Base):
    __tablename__ = "ml_inference_results"
    __table_args__ = (
        ForeignKeyConstraint(
            ["model_id", "model_version"],
            ["anomaly_models.id", "anomaly_models.model_version"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["analysis_id", "flow_id"],
            ["network_flows.analysis_id", "network_flows.flow_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "analysis_id", "model_id", "flow_id", name="uq_ml_result_analysis_model_flow"
        ),
        CheckConstraint("prediction IN ('normal', 'anomaly')", name="ck_ml_result_prediction"),
        Index("ix_ml_results_analysis_prediction", "analysis_id", "prediction"),
        Index("ix_ml_results_model_analysis", "model_id", "analysis_id"),
        Index(
            "uq_ml_result_source",
            "id",
            "analysis_id",
            "model_id",
            "model_version",
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    model_id: Mapped[int] = mapped_column(Integer, nullable=False)
    model_version: Mapped[str] = mapped_column(String(36), nullable=False)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    flow_id: Mapped[str] = mapped_column(String(64), nullable=False)
    prediction: Mapped[str] = mapped_column(String(16), nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Numeric(24, 12), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
