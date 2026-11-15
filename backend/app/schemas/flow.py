from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict


class FlowRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analysis_id: int
    flow_id: str
    ip_version: int | None
    protocol_name: str
    protocol_number: int | None
    endpoint_a_ip: str | None
    endpoint_a_port: int | None
    endpoint_b_ip: str | None
    endpoint_b_port: int | None
    first_packet_source_ip: str | None
    first_packet_source_port: int | None
    first_packet_destination_ip: str | None
    first_packet_destination_port: int | None
    first_timestamp: Decimal | None
    last_timestamp: Decimal | None
    duration_seconds: Decimal | None
    total_packets: int
    total_bytes: int
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int
    packet_length_min: int
    packet_length_max: int
    packet_length_mean: Decimal
    packet_length_stddev: Decimal
    interarrival_min: Decimal | None
    interarrival_max: Decimal | None
    interarrival_mean: Decimal | None
    interarrival_stddev: Decimal | None
    syn_count: int | None
    ack_count: int | None
    fin_count: int | None
    rst_count: int | None
    psh_count: int | None
    urg_count: int | None
    packets_per_second: Decimal | None
    bytes_per_second: Decimal | None
    created_at: datetime


class FlowList(BaseModel):
    items: list[FlowRead]
    total: int
    offset: int
    limit: int


class FlowGenerationRead(BaseModel):
    analysis_id: int
    status: Literal["completed"]
    flow_count: int
    generated: bool
    flows_generated_at: datetime | None
