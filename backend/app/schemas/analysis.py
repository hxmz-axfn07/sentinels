from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AnalysisStatus = Literal["pending", "processing", "completed", "failed"]
FlowGenerationStatus = Literal["not_started", "processing", "completed", "failed"]


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    original_filename: str
    storage_key: str | None
    file_size_bytes: int
    capture_format: str
    status: AnalysisStatus
    packet_count: int
    error_message: str | None
    created_at: datetime
    completed_at: datetime | None
    flow_generation_status: FlowGenerationStatus
    flow_count: int
    flow_error_message: str | None
    flows_generated_at: datetime | None


class AnalysisList(BaseModel):
    items: list[AnalysisRead]
    total: int
    offset: int
    limit: int


class PacketRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    packet_index: int
    timestamp: Decimal | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    network_protocol: str
    transport_protocol: str | None
    ip_protocol_number: int | None
    packet_length: int
    tcp_flags: int | None
    icmp_type: int | None
    icmp_code: int | None


class PacketList(BaseModel):
    items: list[PacketRead]
    total: int
    offset: int
    limit: int


class UploadLimits(BaseModel):
    max_upload_size_bytes: int = Field(gt=0)
