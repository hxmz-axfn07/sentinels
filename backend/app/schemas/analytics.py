from datetime import datetime

from pydantic import BaseModel


class ProtocolTraffic(BaseModel):
    protocol: str
    packet_count: int
    packet_percentage: float
    total_bytes: int
    byte_percentage: float | None
    flow_count: int | None


class PacketLengthBucket(BaseModel):
    bucket: str
    packet_count: int


class TrafficPoint(BaseModel):
    bucket_start_epoch: float
    packet_count: int
    total_bytes: int


class EndpointTraffic(BaseModel):
    address: str
    packet_count: int
    total_bytes: int


class TopFlow(BaseModel):
    flow_id: str
    protocol: str
    endpoint_a: str | None
    endpoint_b: str | None
    total_packets: int
    total_bytes: int
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int
    duration_seconds: float | None


class TrafficAnalytics(BaseModel):
    analysis_id: int
    original_filename: str
    packet_count: int
    total_bytes: int
    flow_count: int | None
    flow_generation_status: str
    first_packet_timestamp: datetime | None
    last_packet_timestamp: datetime | None
    duration_seconds: float | None
    timestamped_packet_count: int
    unavailable_timestamp_packet_count: int
    packets_per_second: float | None
    bytes_per_second: float | None
    forward_packets: int | None
    backward_packets: int | None
    forward_bytes: int | None
    backward_bytes: int | None
    protocols: list[ProtocolTraffic]
    packet_length_distribution: list[PacketLengthBucket]
    timeline_bucket_seconds: float | None
    timeline: list[TrafficPoint]
    top_source_endpoints: list[EndpointTraffic]
    top_destination_endpoints: list[EndpointTraffic]
    top_flows_by_bytes: list[TopFlow]
    top_flows_by_packets: list[TopFlow]


class AnalysisComparisonItem(BaseModel):
    analysis_id: int
    original_filename: str
    capture_format: str
    created_at: datetime
    packet_count: int
    total_bytes: int
    flow_count: int | None
    protocol_distribution: list[ProtocolTraffic]
    rule_findings_by_severity: dict[str, int] | None
    rule_detection_run_id: int | None
    ml_anomaly_count: int | None
    ml_model_id: int | None
    hybrid_risk_score: str | None
    hybrid_severity: str | None


class AnalysisComparison(BaseModel):
    items: list[AnalysisComparisonItem]
    metric_limitations: list[str]
