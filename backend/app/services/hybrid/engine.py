from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from sqlalchemy import exists, func, select
from sqlalchemy.orm import Session, selectinload

from app.models.analysis import Analysis
from app.models.anomaly import AnomalyModel, AnomalyResult
from app.models.detection import DetectionFinding, DetectionRun, detection_finding_flows
from app.models.flow import NetworkFlow
from app.models.hybrid import HybridAssessment, HybridEvidence, HybridRiskGroup
from app.services.hybrid.config import HybridScoringConfig

EVIDENCE_BATCH_SIZE = 500
MAX_HYBRID_EVIDENCE_ITEMS = 5_000


class HybridInputError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(slots=True)
class _Evidence:
    source: str
    source_id: int
    flow_id: str | None
    detection_finding_id: int | None
    anomaly_result_id: int | None
    rule_id: str | None
    rule_name: str | None
    original_severity: str | None
    prediction: str | None
    anomaly_score: Decimal | None
    contribution: float
    payload: dict[str, Any]


@dataclass(slots=True)
class _Group:
    group_key: str
    correlation_level: str
    endpoint_a_ip: str | None
    endpoint_b_ip: str | None
    protocol_name: str | None
    rules: dict[int, str] = field(default_factory=dict)
    rule_weights: dict[str, int] = field(default_factory=dict)
    ml_weights: list[float] = field(default_factory=list)
    evidence: dict[tuple[str, int], _Evidence] = field(default_factory=dict)
    correlated_flow_ids: set[str] = field(default_factory=set)
    _rule_component: float = 0.0
    _ml_component: float = 0.0
    _exact_bonus: float = 0.0
    _risk_score: float = 0.0
    _severity: str = "informational"

    def add_rule(self, evidence: _Evidence, severity_weight: int) -> None:
        self.evidence[(evidence.source, evidence.source_id)] = evidence
        self.rules[evidence.source_id] = evidence.rule_id or "UNKNOWN"
        rule_id = evidence.rule_id or "UNKNOWN"
        self.rule_weights[rule_id] = max(self.rule_weights.get(rule_id, 0), severity_weight)

    def add_ml(self, evidence: _Evidence) -> None:
        self.evidence[(evidence.source, evidence.source_id)] = evidence
        self.ml_weights.append(evidence.contribution)


@dataclass(frozen=True, slots=True)
class AssessmentExecution:
    assessment: HybridAssessment
    reused: bool


def execute_assessment(
    db: Session,
    *,
    analysis: Analysis,
    detection_run: DetectionRun,
    model: AnomalyModel,
    config: HybridScoringConfig,
) -> AssessmentExecution:
    counts = _validate_sources(db, analysis, detection_run, model)
    rule_count, _, anomaly_count = counts
    if rule_count + anomaly_count > MAX_HYBRID_EVIDENCE_ITEMS:
        raise HybridInputError(
            "hybrid_evidence_limit_exceeded",
            f"Hybrid assessment supports at most {MAX_HYBRID_EVIDENCE_ITEMS} contributing "
            "findings and anomalies. Reduce the analysis scope or select smaller inputs.",
            status_code=413,
        )

    config_data = config.model_dump(mode="json")
    config_hash = scoring_config_hash(config)
    existing = db.scalar(
        select(HybridAssessment).where(
            HybridAssessment.analysis_id == analysis.id,
            HybridAssessment.detection_run_id == detection_run.id,
            HybridAssessment.model_id == model.id,
            HybridAssessment.scoring_config_hash == config_hash,
        )
    )
    if existing is not None:
        return AssessmentExecution(existing, reused=True)

    groups = _collect_rule_evidence(db, analysis, detection_run, config)
    correlated_flows = _collect_ml_evidence(db, analysis, detection_run, model, config, groups)
    _score_groups(groups, config)

    ordered_groups = sorted(groups.values(), key=lambda item: item.group_key)
    top_score = max((group._risk_score for group in ordered_groups), default=0.0)
    top_score = round(top_score, 2)
    assessment = HybridAssessment(
        analysis_id=analysis.id,
        detection_run_id=detection_run.id,
        model_id=model.id,
        model_version=model.model_version,
        scoring_config_version=config.version,
        scoring_config_hash=config_hash,
        scoring_config=config_data,
        risk_score=Decimal(f"{top_score:.2f}"),
        severity=config.classify(top_score),
        rule_evidence_count=rule_count,
        ml_anomaly_count=anomaly_count,
        correlated_evidence_count=len(correlated_flows),
        risk_group_count=len(ordered_groups),
        explanation=_assessment_explanation(top_score, len(ordered_groups)),
    )
    db.add(assessment)
    db.flush()

    for bucket in ordered_groups:
        risk_group = _persist_group(assessment, bucket)
        db.add(risk_group)
        for item in bucket.evidence.values():
            db.add(
                HybridEvidence(
                    group=risk_group,
                    assessment_id=assessment.id,
                    analysis_id=analysis.id,
                    detection_run_id=detection_run.id,
                    model_id=model.id,
                    model_version=model.model_version,
                    source=item.source,
                    source_id=item.source_id,
                    detection_finding_id=item.detection_finding_id,
                    anomaly_result_id=item.anomaly_result_id,
                    flow_id=item.flow_id,
                    rule_id=item.rule_id,
                    rule_name=item.rule_name,
                    original_severity=item.original_severity,
                    prediction=item.prediction,
                    anomaly_score=item.anomaly_score,
                    evidence=item.payload,
                )
            )
    db.flush()
    return AssessmentExecution(assessment, reused=False)


def _validate_sources(
    db: Session,
    analysis: Analysis,
    detection_run: DetectionRun,
    model: AnomalyModel,
) -> tuple[int, int, int]:
    if analysis.status != "completed" or analysis.flow_generation_status != "completed":
        raise HybridInputError(
            "analysis_not_ready", "Complete analysis and flow generation before hybrid assessment."
        )
    if analysis.flow_count <= 0:
        raise HybridInputError(
            "analysis_has_no_flows", "Hybrid assessment requires at least one generated flow."
        )
    if detection_run.analysis_id != analysis.id or detection_run.status != "completed":
        raise HybridInputError(
            "detection_run_not_ready",
            "Select a completed rule detection run for this analysis.",
        )
    if model.status != "ready":
        raise HybridInputError("model_not_ready", "Select a ready Isolation Forest model.")

    rule_count = int(
        db.scalar(
            select(func.count(DetectionFinding.id)).where(
                DetectionFinding.analysis_id == analysis.id,
                DetectionFinding.run_id == detection_run.id,
            )
        )
        or 0
    )
    result_count = int(
        db.scalar(
            select(func.count(AnomalyResult.id)).where(
                AnomalyResult.analysis_id == analysis.id,
                AnomalyResult.model_id == model.id,
                AnomalyResult.model_version == model.model_version,
            )
        )
        or 0
    )
    anomaly_count = int(
        db.scalar(
            select(func.count(AnomalyResult.id)).where(
                AnomalyResult.analysis_id == analysis.id,
                AnomalyResult.model_id == model.id,
                AnomalyResult.model_version == model.model_version,
                AnomalyResult.prediction == "anomaly",
            )
        )
        or 0
    )
    if rule_count != detection_run.finding_count:
        raise HybridInputError(
            "detection_results_inconsistent", "The selected rule run has incomplete findings."
        )
    if result_count != analysis.flow_count:
        raise HybridInputError(
            "inference_results_incomplete",
            "Run inference for every flow with the selected model before hybrid assessment.",
        )
    return rule_count, result_count, anomaly_count


def _collect_rule_evidence(
    db: Session,
    analysis: Analysis,
    detection_run: DetectionRun,
    config: HybridScoringConfig,
) -> dict[str, _Group]:
    groups: dict[str, _Group] = {}
    last_id = 0
    while True:
        findings = db.scalars(
            select(DetectionFinding)
            .options(selectinload(DetectionFinding.supporting_flows))
            .where(DetectionFinding.run_id == detection_run.id, DetectionFinding.id > last_id)
            .order_by(DetectionFinding.id)
            .limit(EVIDENCE_BATCH_SIZE)
        ).all()
        if not findings:
            break
        for finding in findings:
            support = sorted(finding.supporting_flows, key=lambda flow: flow.flow_id)
            support_snapshot = [
                {
                    "flow_id": flow.flow_id,
                    "protocol_name": flow.protocol_name,
                    "endpoint_a_ip": flow.endpoint_a_ip,
                    "endpoint_a_port": flow.endpoint_a_port,
                    "endpoint_b_ip": flow.endpoint_b_ip,
                    "endpoint_b_port": flow.endpoint_b_port,
                }
                for flow in support
            ]
            protocols = _finding_protocols(finding)
            for protocol in protocols:
                bucket = _endpoint_group(
                    groups,
                    finding.source_ip,
                    finding.destination_ip,
                    protocol,
                    fallback=f"rule:{finding.id}:{protocol}",
                )
                payload = {
                    "source": "rule",
                    "finding_id": finding.id,
                    "analysis_id": analysis.id,
                    "detection_run_id": detection_run.id,
                    "rule_id": finding.rule_id,
                    "rule_name": finding.rule_name,
                    "severity": finding.severity,
                    "source_ip": finding.source_ip,
                    "destination_ip": finding.destination_ip,
                    "protocol_name": finding.protocol_name,
                    "explanation": finding.explanation,
                    "evidence": finding.evidence,
                    "supporting_flow_count": finding.supporting_flow_count,
                    "supporting_flow_sample_truncated": finding.supporting_flow_sample_truncated,
                    "supporting_flows": support_snapshot,
                }
                item = _Evidence(
                    source="rule",
                    source_id=finding.id,
                    flow_id=None,
                    detection_finding_id=finding.id,
                    anomaly_result_id=None,
                    rule_id=finding.rule_id,
                    rule_name=finding.rule_name,
                    original_severity=finding.severity,
                    prediction=None,
                    anomaly_score=None,
                    contribution=float(config.rule_weight(finding.severity)),
                    payload=payload,
                )
                bucket.add_rule(item, config.rule_weight(finding.severity))
            last_id = findings[-1].id
    return groups


def _collect_ml_evidence(
    db: Session,
    analysis: Analysis,
    detection_run: DetectionRun,
    model: AnomalyModel,
    config: HybridScoringConfig,
    groups: dict[str, _Group],
) -> set[str]:
    ranking = (
        select(
            AnomalyResult.id.label("result_id"),
            func.percent_rank()
            .over(order_by=AnomalyResult.anomaly_score.asc())
            .label("score_percentile"),
        )
        .where(
            AnomalyResult.analysis_id == analysis.id,
            AnomalyResult.model_id == model.id,
            AnomalyResult.model_version == model.model_version,
        )
        .subquery()
    )
    exact_rule_flow = exists(
        select(1)
        .select_from(detection_finding_flows)
        .join(DetectionFinding, DetectionFinding.id == detection_finding_flows.c.finding_id)
        .where(
            DetectionFinding.run_id == detection_run.id,
            detection_finding_flows.c.flow_id == NetworkFlow.id,
        )
    )
    last_id = 0
    correlated_flows: set[str] = set()
    while True:
        rows = db.execute(
            select(AnomalyResult, NetworkFlow, ranking.c.score_percentile, exact_rule_flow)
            .join(
                NetworkFlow,
                (NetworkFlow.analysis_id == AnomalyResult.analysis_id)
                & (NetworkFlow.flow_id == AnomalyResult.flow_id),
            )
            .join(ranking, ranking.c.result_id == AnomalyResult.id)
            .where(
                AnomalyResult.analysis_id == analysis.id,
                AnomalyResult.model_id == model.id,
                AnomalyResult.model_version == model.model_version,
                AnomalyResult.prediction == "anomaly",
                AnomalyResult.id > last_id,
            )
            .order_by(AnomalyResult.id)
            .limit(EVIDENCE_BATCH_SIZE)
        ).all()
        if not rows:
            break
        for result, flow, percentile, shares_supported_flow in rows:
            if not math.isfinite(float(result.anomaly_score)):
                raise HybridInputError(
                    "invalid_anomaly_score",
                    "Selected inference results contain a non-finite score.",
                )
            protocol = flow.protocol_name or "UNKNOWN"
            bucket = _endpoint_group(
                groups,
                flow.endpoint_a_ip,
                flow.endpoint_b_ip,
                protocol,
                fallback=f"flow:{flow.flow_id}",
            )
            percentile_value = min(1.0, max(0.0, float(percentile or 0.0)))
            contribution = config.ml_base_weight + config.ml_rank_weight * percentile_value
            payload = {
                "source": "ml",
                "result_id": result.id,
                "analysis_id": analysis.id,
                "model_id": model.id,
                "model_version": model.model_version,
                "prediction": result.prediction,
                "anomaly_score": str(result.anomaly_score),
                "score_normalization": {
                    "method": "percent_rank within selected analysis and model",
                    "percentile": percentile_value,
                    "interpretation": "relative ranking, not probability",
                },
                "flow": {
                    "flow_id": flow.flow_id,
                    "protocol_name": flow.protocol_name,
                    "endpoint_a_ip": flow.endpoint_a_ip,
                    "endpoint_a_port": flow.endpoint_a_port,
                    "endpoint_b_ip": flow.endpoint_b_ip,
                    "endpoint_b_port": flow.endpoint_b_port,
                    "duration_seconds": _decimal_text(flow.duration_seconds),
                    "total_packets": flow.total_packets,
                    "total_bytes": flow.total_bytes,
                    "packets_per_second": _decimal_text(flow.packets_per_second),
                    "bytes_per_second": _decimal_text(flow.bytes_per_second),
                },
            }
            item = _Evidence(
                source="ml",
                source_id=result.id,
                flow_id=flow.flow_id,
                detection_finding_id=None,
                anomaly_result_id=result.id,
                rule_id=None,
                rule_name=None,
                original_severity=None,
                prediction=result.prediction,
                anomaly_score=Decimal(str(result.anomaly_score)),
                contribution=contribution,
                payload=payload,
            )
            bucket.add_ml(item)
            if shares_supported_flow and bucket.rules:
                bucket.correlated_flow_ids.add(flow.flow_id)
                correlated_flows.add(flow.flow_id)
        last_id = rows[-1][0].id
    return correlated_flows


def _finding_protocols(finding: DetectionFinding) -> tuple[str, ...]:
    observed = finding.evidence.get("protocols") if isinstance(finding.evidence, dict) else None
    if finding.protocol_name == "TCP/UDP" and isinstance(observed, list):
        supported = sorted({str(value).upper() for value in observed if value in {"TCP", "UDP"}})
        if supported:
            return tuple(supported)
    return ((finding.protocol_name or "UNKNOWN").upper(),)


def _endpoint_group(
    groups: dict[str, _Group],
    source_ip: str | None,
    destination_ip: str | None,
    protocol_name: str | None,
    *,
    fallback: str,
) -> _Group:
    protocol = (protocol_name or "UNKNOWN").upper()
    if source_ip and destination_ip:
        endpoint_a, endpoint_b = sorted((source_ip, destination_ip))
        identity = {"type": "endpoint_pair", "a": endpoint_a, "b": endpoint_b, "protocol": protocol}
        correlation_level = "endpoint_pair"
    else:
        endpoint_a = endpoint_b = None
        identity = {"type": fallback, "protocol": protocol}
        correlation_level = "flow_only" if fallback.startswith("flow:") else "rule_only"
    group_key = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return groups.setdefault(
        group_key,
        _Group(
            group_key=group_key,
            correlation_level=correlation_level,
            endpoint_a_ip=endpoint_a,
            endpoint_b_ip=endpoint_b,
            protocol_name=protocol,
        ),
    )


def _score_groups(groups: dict[str, _Group], config: HybridScoringConfig) -> None:
    for group in groups.values():
        residual = 1.0
        for weight in group.rule_weights.values():
            residual *= 1.0 - weight / 100.0
        rule_component = 100.0 * (1.0 - residual)
        ml_component = max(group.ml_weights, default=0.0)
        exact_bonus = (
            float(config.exact_flow_bonus)
            if group.rules and group.ml_weights and group.correlated_flow_ids
            else 0.0
        )
        combined = 100.0 * (1.0 - (1.0 - rule_component / 100.0) * (1.0 - ml_component / 100.0))
        group._rule_component = round(rule_component, 2)
        group._ml_component = round(ml_component, 2)
        group._exact_bonus = exact_bonus
        group._risk_score = round(min(100.0, combined + exact_bonus), 2)
        if group.rules and group.ml_weights:
            group.correlation_level = "exact_flow" if group.correlated_flow_ids else "endpoint_pair"
        elif group.rules:
            group.correlation_level = "rule_only"
        elif group.ml_weights and group.endpoint_a_ip and group.endpoint_b_ip:
            group.correlation_level = "ml_only"
        else:
            group.correlation_level = "flow_only"
        group._severity = config.classify(group._risk_score)


def _persist_group(assessment: HybridAssessment, group: _Group) -> HybridRiskGroup:
    if group.rules and group.ml_weights:
        if group.correlated_flow_ids:
            explanation = (
                f"Rule and ML evidence share {len(group.correlated_flow_ids)} exact flow(s); "
                "the configured corroboration bonus applies."
            )
        else:
            explanation = (
                "Rule and ML evidence concern the same endpoint pair and protocol, but do not "
                "share a linked flow. Endpoint overlap is weaker contextual evidence."
            )
    elif group.rules:
        explanation = "This group contains rule evidence only; no ML anomaly corroborated it."
    else:
        explanation = (
            "This group contains ML anomaly evidence only; no rule finding corroborated it."
        )
    return HybridRiskGroup(
        assessment_id=assessment.id,
        analysis_id=assessment.analysis_id,
        group_key=group.group_key,
        correlation_level=group.correlation_level,
        endpoint_a_ip=group.endpoint_a_ip,
        endpoint_b_ip=group.endpoint_b_ip,
        protocol_name=group.protocol_name,
        risk_score=Decimal(f"{group._risk_score:.2f}"),
        rule_component=Decimal(f"{group._rule_component:.2f}"),
        ml_component=Decimal(f"{group._ml_component:.2f}"),
        exact_flow_bonus=Decimal(f"{group._exact_bonus:.2f}"),
        severity=group._severity,
        rule_evidence_count=len(group.rules),
        ml_anomaly_count=len(group.ml_weights),
        correlated_flow_count=len(group.correlated_flow_ids),
        explanation=explanation,
    )


def _assessment_explanation(score: float, group_count: int) -> str:
    if not group_count:
        return (
            "No rule findings or ML anomaly predictions were present in the selected completed "
            "runs. This describes only the analyzed capture and does not establish that traffic "
            "was safe."
        )
    return (
        f"The analysis score is the highest group score ({score:.2f}) across {group_count} "
        "correlated risk group(s). This is an investigation priority, not a probability or "
        "confirmation of compromise."
    )


def scoring_config_hash(config: HybridScoringConfig) -> str:
    encoded = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _decimal_text(value: Decimal | None) -> str | None:
    return str(value) if value is not None else None
