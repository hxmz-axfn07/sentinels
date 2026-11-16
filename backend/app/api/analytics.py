from datetime import UTC, datetime
from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.anomaly import AnomalyResult
from app.models.detection import DetectionFinding, DetectionRun
from app.models.flow import NetworkFlow
from app.models.hybrid import HybridAssessment
from app.models.packet import PacketRecord
from app.schemas.analytics import (
    AnalysisComparison,
    AnalysisComparisonItem,
    EndpointTraffic,
    PacketLengthBucket,
    ProtocolTraffic,
    TopFlow,
    TrafficAnalytics,
    TrafficPoint,
)

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])


@router.get("/traffic/{analysis_id}", response_model=TrafficAnalytics)
def get_traffic_analytics(
    analysis_id: int = Path(ge=1),
    db: Session = Depends(get_db),  # noqa: B008
) -> TrafficAnalytics:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    packet_scope = PacketRecord.analysis_id == analysis_id
    protocol_label = func.coalesce(PacketRecord.transport_protocol, PacketRecord.network_protocol)
    protocol_rows = db.execute(
        select(
            protocol_label,
            func.count(PacketRecord.id),
            func.coalesce(func.sum(PacketRecord.packet_length), 0),
        )
        .where(packet_scope)
        .group_by(protocol_label)
        .order_by(func.count(PacketRecord.id).desc(), protocol_label)
    ).all()
    total_packets = sum(int(row[1]) for row in protocol_rows)
    total_bytes = sum(int(row[2]) for row in protocol_rows)
    flow_protocol_rows = db.execute(
        select(NetworkFlow.protocol_name, func.count(NetworkFlow.id))
        .where(NetworkFlow.analysis_id == analysis_id)
        .group_by(NetworkFlow.protocol_name)
    ).all()
    flow_counts = {str(name): int(count) for name, count in flow_protocol_rows}
    protocols = [
        ProtocolTraffic(
            protocol=str(name),
            packet_count=int(packets),
            packet_percentage=(int(packets) / total_packets * 100 if total_packets else 0.0),
            total_bytes=int(byte_count),
            byte_percentage=(int(byte_count) / total_bytes * 100 if total_bytes else None),
            flow_count=flow_counts.get(str(name)),
        )
        for name, packets, byte_count in protocol_rows
    ]

    timestamp_stats = db.execute(
        select(
            func.min(PacketRecord.timestamp),
            func.max(PacketRecord.timestamp),
            func.count(PacketRecord.timestamp),
        ).where(packet_scope)
    ).one()
    first_ts, last_ts, timestamped_count = timestamp_stats
    duration = float(last_ts - first_ts) if first_ts is not None and last_ts is not None else None
    timeline: list[TrafficPoint] = []
    bucket_seconds: float | None = None
    if first_ts is not None and last_ts is not None:
        bucket_seconds = max(1.0, float(ceil(max(duration or 0.0, 1.0) / 60)))
        bucket_index = func.floor((PacketRecord.timestamp - first_ts) / bucket_seconds)
        timeline_rows = db.execute(
            select(
                bucket_index.label("bucket_index"),
                func.count(PacketRecord.id),
                func.coalesce(func.sum(PacketRecord.packet_length), 0),
            )
            .where(packet_scope, PacketRecord.timestamp.is_not(None))
            .group_by(bucket_index)
            .order_by(bucket_index)
        ).all()
        timeline = [
            TrafficPoint(
                bucket_start_epoch=float(first_ts) + int(index) * bucket_seconds,
                packet_count=int(count),
                total_bytes=int(byte_count),
            )
            for index, count, byte_count in timeline_rows
        ]

    length_case = case(
        (PacketRecord.packet_length < 64, "<64 B"),
        (PacketRecord.packet_length < 128, "64–127 B"),
        (PacketRecord.packet_length < 512, "128–511 B"),
        (PacketRecord.packet_length < 1500, "512–1499 B"),
        else_="≥1500 B",
    )
    length_rows = db.execute(
        select(length_case.label("bucket"), func.count(PacketRecord.id))
        .where(packet_scope)
        .group_by(length_case)
    ).all()
    bucket_order = {"<64 B": 0, "64–127 B": 1, "128–511 B": 2, "512–1499 B": 3, "≥1500 B": 4}
    packet_lengths = [
        PacketLengthBucket(bucket=str(name), packet_count=int(count))
        for name, count in sorted(length_rows, key=lambda row: bucket_order[str(row[0])])
    ]

    source_rows = _top_endpoints(db, analysis_id, source=True)
    destination_rows = _top_endpoints(db, analysis_id, source=False)
    flows = db.scalars(
        select(NetworkFlow)
        .where(NetworkFlow.analysis_id == analysis_id)
        .order_by(NetworkFlow.total_bytes.desc(), NetworkFlow.flow_id)
        .limit(10)
    ).all()
    top_bytes = [_flow_summary(flow) for flow in flows]
    flows_by_packets = db.scalars(
        select(NetworkFlow)
        .where(NetworkFlow.analysis_id == analysis_id)
        .order_by(NetworkFlow.total_packets.desc(), NetworkFlow.flow_id)
        .limit(10)
    ).all()
    directional = db.execute(
        select(
            func.sum(NetworkFlow.forward_packets),
            func.sum(NetworkFlow.backward_packets),
            func.sum(NetworkFlow.forward_bytes),
            func.sum(NetworkFlow.backward_bytes),
        ).where(NetworkFlow.analysis_id == analysis_id)
    ).one()
    has_flows = analysis.flow_generation_status == "completed"
    persisted_flow_count = db.scalar(
        select(func.count(NetworkFlow.id)).where(NetworkFlow.analysis_id == analysis_id)
    )
    timestamped = int(timestamped_count or 0)
    complete_timestamps = timestamped == total_packets
    rates_valid = duration is not None and duration > 0 and complete_timestamps

    return TrafficAnalytics(
        analysis_id=analysis.id,
        original_filename=analysis.original_filename,
        packet_count=total_packets,
        total_bytes=total_bytes,
        flow_count=int(persisted_flow_count or 0) if has_flows else None,
        flow_generation_status=analysis.flow_generation_status,
        first_packet_timestamp=_epoch_datetime(first_ts),
        last_packet_timestamp=_epoch_datetime(last_ts),
        duration_seconds=duration,
        timestamped_packet_count=timestamped,
        unavailable_timestamp_packet_count=max(0, total_packets - timestamped),
        packets_per_second=(total_packets / duration if rates_valid else None),
        bytes_per_second=(total_bytes / duration if rates_valid else None),
        forward_packets=int(directional[0] or 0) if has_flows else None,
        backward_packets=int(directional[1] or 0) if has_flows else None,
        forward_bytes=int(directional[2] or 0) if has_flows else None,
        backward_bytes=int(directional[3] or 0) if has_flows else None,
        protocols=protocols,
        packet_length_distribution=packet_lengths,
        timeline_bucket_seconds=bucket_seconds,
        timeline=timeline,
        top_source_endpoints=source_rows,
        top_destination_endpoints=destination_rows,
        top_flows_by_bytes=top_bytes,
        top_flows_by_packets=[_flow_summary(flow) for flow in flows_by_packets],
    )


@router.get("/comparison", response_model=AnalysisComparison)
def compare_analyses(
    analysis_ids: list[int] = Query(min_length=2, max_length=5),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
) -> AnalysisComparison:
    if len(set(analysis_ids)) != len(analysis_ids):
        raise HTTPException(status_code=422, detail="Analysis IDs must be unique.")
    if any(analysis_id < 1 for analysis_id in analysis_ids):
        raise HTTPException(status_code=422, detail="Analysis IDs must be positive.")
    analyses = db.scalars(select(Analysis).where(Analysis.id.in_(analysis_ids))).all()
    by_id = {item.id: item for item in analyses}
    missing = [item for item in analysis_ids if item not in by_id]
    if missing:
        raise HTTPException(status_code=404, detail="One or more analyses were not found.")
    if any(by_id[analysis_id].status != "completed" for analysis_id in analysis_ids):
        raise HTTPException(
            status_code=409,
            detail="Only completed analyses can be compared.",
        )

    items = []
    limitations = [
        "Packet protocol counts use packet data; flow protocol counts require generated flows.",
        "Rule, ML, and hybrid values are null if that stage has no completed result.",
    ]
    for analysis_id in analysis_ids:
        analysis = by_id[analysis_id]
        protocol_label = func.coalesce(
            PacketRecord.transport_protocol, PacketRecord.network_protocol
        )
        packet_rows = db.execute(
            select(
                protocol_label,
                func.count(PacketRecord.id),
                func.coalesce(func.sum(PacketRecord.packet_length), 0),
            )
            .where(PacketRecord.analysis_id == analysis_id)
            .group_by(protocol_label)
        ).all()
        packet_count = sum(int(row[1]) for row in packet_rows)
        total_bytes = sum(int(row[2]) for row in packet_rows)
        flow_count = (
            db.scalar(
                select(func.count(NetworkFlow.id)).where(NetworkFlow.analysis_id == analysis_id)
            )
            if analysis.flow_generation_status == "completed"
            else None
        )
        protocol_flow_counts = dict(
            db.execute(
                select(NetworkFlow.protocol_name, func.count(NetworkFlow.id))
                .where(NetworkFlow.analysis_id == analysis_id)
                .group_by(NetworkFlow.protocol_name)
            ).all()
        )
        protocols = [
            ProtocolTraffic(
                protocol=str(name),
                packet_count=int(count),
                packet_percentage=(int(count) / packet_count * 100 if packet_count else 0.0),
                total_bytes=int(byte_count),
                byte_percentage=(int(byte_count) / total_bytes * 100 if total_bytes else None),
                flow_count=int(protocol_flow_counts[name])
                if name in protocol_flow_counts
                else None,
            )
            for name, count, byte_count in packet_rows
        ]

        latest_run = db.scalar(
            select(DetectionRun)
            .where(DetectionRun.analysis_id == analysis_id, DetectionRun.status == "completed")
            .order_by(DetectionRun.id.desc())
            .limit(1)
        )
        rule_counts = None
        if latest_run:
            rows = db.execute(
                select(DetectionFinding.severity, func.count(DetectionFinding.id))
                .where(DetectionFinding.run_id == latest_run.id)
                .group_by(DetectionFinding.severity)
            ).all()
            rule_counts = {str(name): int(count) for name, count in rows}

        latest_result_id = db.scalar(
            select(func.max(AnomalyResult.id)).where(AnomalyResult.analysis_id == analysis_id)
        )
        selected_model_id = (
            db.scalar(select(AnomalyResult.model_id).where(AnomalyResult.id == latest_result_id))
            if latest_result_id
            else None
        )
        anomaly_count = (
            db.scalar(
                select(func.count(AnomalyResult.id)).where(
                    AnomalyResult.analysis_id == analysis_id,
                    AnomalyResult.model_id == selected_model_id,
                    AnomalyResult.prediction == "anomaly",
                )
            )
            if selected_model_id is not None
            else None
        )
        assessment = db.scalar(
            select(HybridAssessment)
            .where(HybridAssessment.analysis_id == analysis_id)
            .order_by(HybridAssessment.id.desc())
            .limit(1)
        )
        items.append(
            AnalysisComparisonItem(
                analysis_id=analysis.id,
                original_filename=analysis.original_filename,
                capture_format=analysis.capture_format,
                created_at=analysis.created_at,
                packet_count=packet_count,
                total_bytes=total_bytes,
                flow_count=flow_count,
                protocol_distribution=protocols,
                rule_findings_by_severity=rule_counts,
                rule_detection_run_id=latest_run.id if latest_run else None,
                ml_anomaly_count=int(anomaly_count) if anomaly_count is not None else None,
                ml_model_id=selected_model_id,
                hybrid_risk_score=str(assessment.risk_score) if assessment else None,
                hybrid_severity=assessment.severity if assessment else None,
            )
        )
    return AnalysisComparison(items=items, metric_limitations=limitations)


def _epoch_datetime(value) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value), tz=UTC)


def _top_endpoints(db: Session, analysis_id: int, *, source: bool) -> list[EndpointTraffic]:
    address = PacketRecord.source_ip if source else PacketRecord.destination_ip
    query = (
        select(
            address,
            func.count(PacketRecord.id),
            func.coalesce(func.sum(PacketRecord.packet_length), 0),
        )
        .where(PacketRecord.analysis_id == analysis_id, address.is_not(None))
        .group_by(address)
        .order_by(func.count(PacketRecord.id).desc(), address)
        .limit(10)
    )
    return [
        EndpointTraffic(address=str(ip), packet_count=int(count), total_bytes=int(byte_count))
        for ip, count, byte_count in db.execute(query).all()
    ]


def _flow_summary(flow: NetworkFlow) -> TopFlow:
    def endpoint(ip: str | None, port: int | None) -> str | None:
        if ip is None:
            return None
        return f"{ip}:{port}" if port is not None else ip

    return TopFlow(
        flow_id=flow.flow_id,
        protocol=flow.protocol_name,
        endpoint_a=endpoint(flow.endpoint_a_ip, flow.endpoint_a_port),
        endpoint_b=endpoint(flow.endpoint_b_ip, flow.endpoint_b_port),
        total_packets=flow.total_packets,
        total_bytes=flow.total_bytes,
        forward_packets=flow.forward_packets,
        backward_packets=flow.backward_packets,
        forward_bytes=flow.forward_bytes,
        backward_bytes=flow.backward_bytes,
        duration_seconds=(
            float(flow.duration_seconds) if flow.duration_seconds is not None else None
        ),
    )
