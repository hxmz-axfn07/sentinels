from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models.analysis import Analysis
from app.models.packet import PacketRecord
from app.services.packet_metadata import PacketMetadata, read_packet_metadata

BATCH_SIZE = 500


def process_capture(db: Session, analysis: Analysis, capture_path: Path) -> int:
    batch: list[PacketMetadata] = []
    for packet in read_packet_metadata(str(capture_path)):
        batch.append(packet)
        if len(batch) >= BATCH_SIZE:
            _persist_batch(db, analysis, batch)
            batch.clear()
    if batch:
        _persist_batch(db, analysis, batch)
        batch.clear()
    if analysis.packet_count == 0:
        raise ValueError("The capture contains no readable packets.")

    analysis.status = "completed"
    analysis.completed_at = datetime.now(UTC)
    analysis.error_message = None
    db.commit()
    return analysis.packet_count


def _persist_batch(db: Session, analysis: Analysis, batch: list[PacketMetadata]) -> None:
    db.add_all(
        [
            PacketRecord(
                analysis_id=analysis.id,
                packet_index=packet.packet_index,
                timestamp=packet.timestamp,
                source_ip=packet.source_ip,
                destination_ip=packet.destination_ip,
                source_port=packet.source_port,
                destination_port=packet.destination_port,
                network_protocol=packet.network_protocol,
                transport_protocol=packet.transport_protocol,
                ip_protocol_number=packet.ip_protocol_number,
                packet_length=packet.packet_length,
                tcp_flags=packet.tcp_flags,
                icmp_type=packet.icmp_type,
                icmp_code=packet.icmp_code,
            )
            for packet in batch
        ]
    )
    analysis.packet_count += len(batch)
    db.commit()


def mark_analysis_failed(db: Session, analysis_id: int, message: str) -> Analysis:
    db.rollback()
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise RuntimeError("Analysis record was lost during processing.")
    db.execute(delete(PacketRecord).where(PacketRecord.analysis_id == analysis_id))
    analysis.status = "failed"
    analysis.packet_count = 0
    analysis.error_message = message
    analysis.completed_at = datetime.now(UTC)
    db.commit()
    db.refresh(analysis)
    return analysis
