from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.flow import NetworkFlow
from app.models.packet import PacketRecord
from app.services.flow_engine import FlowAggregate, identify_flow

BATCH_SIZE = 500


def generate_flows(db: Session, analysis_id: int) -> int:
    _stamp_packet_flow_keys(db, analysis_id)
    db.expire_all()

    current_flow_id: str | None = None
    aggregate: FlowAggregate | None = None
    pending: list[NetworkFlow] = []
    flow_count = 0
    last_flow_id: str | None = None
    last_timestamp = None
    last_packet_index: int | None = None

    while True:
        query = select(PacketRecord).where(PacketRecord.analysis_id == analysis_id)
        if last_flow_id is not None and last_packet_index is not None:
            if last_timestamp is None:
                after_same_flow = or_(
                    PacketRecord.timestamp.is_not(None),
                    and_(
                        PacketRecord.timestamp.is_(None),
                        PacketRecord.packet_index > last_packet_index,
                    ),
                )
            else:
                after_same_flow = or_(
                    PacketRecord.timestamp > last_timestamp,
                    and_(
                        PacketRecord.timestamp == last_timestamp,
                        PacketRecord.packet_index > last_packet_index,
                    ),
                )
            query = query.where(
                or_(
                    PacketRecord.flow_id > last_flow_id,
                    and_(
                        PacketRecord.flow_id == last_flow_id,
                        after_same_flow,
                    ),
                )
            )
        page = db.scalars(
            query.order_by(
                PacketRecord.flow_id,
                PacketRecord.timestamp,
                PacketRecord.packet_index,
            ).limit(BATCH_SIZE)
        ).all()
        if not page:
            break

        for packet in page:
            if packet.flow_id is None or packet.flow_forward is None:
                raise RuntimeError("Packet flow identity was not persisted.")
            if packet.flow_id != current_flow_id:
                if aggregate is not None:
                    _append_flow(db, aggregate, pending)
                    flow_count += 1
                key, _ = identify_flow(packet)
                if key.flow_id != packet.flow_id:
                    raise RuntimeError("Persisted packet flow identity is inconsistent.")
                aggregate = FlowAggregate(key=key)
                current_flow_id = packet.flow_id

            assert aggregate is not None
            aggregate.add_packet(packet, packet.flow_forward)
            if packet.timestamp is not None:
                aggregate.add_timestamp_ordered(packet.timestamp)

        last_packet = page[-1]
        last_flow_id = last_packet.flow_id
        last_timestamp = last_packet.timestamp
        last_packet_index = last_packet.packet_index

    if aggregate is not None:
        _append_flow(db, aggregate, pending)
        flow_count += 1
    if pending:
        db.add_all(pending)
        db.flush()
    return flow_count


def _stamp_packet_flow_keys(db: Session, analysis_id: int) -> None:
    last_packet_index = 0
    while True:
        page = db.scalars(
            select(PacketRecord)
            .where(
                PacketRecord.analysis_id == analysis_id,
                PacketRecord.packet_index > last_packet_index,
            )
            .order_by(PacketRecord.packet_index)
            .limit(BATCH_SIZE)
        ).all()
        if not page:
            break
        updates: list[dict[str, int | str | bool]] = []
        for packet in page:
            key, forward = identify_flow(packet)
            updates.append({"id": packet.id, "flow_id": key.flow_id, "flow_forward": forward})
        db.bulk_update_mappings(PacketRecord, updates)
        last_packet_index = page[-1].packet_index


def _append_flow(db: Session, aggregate: FlowAggregate, pending: list[NetworkFlow]) -> None:
    pending.append(NetworkFlow(analysis_id=aggregate.key.analysis_id, **aggregate.feature_values()))
    if len(pending) >= BATCH_SIZE:
        db.add_all(pending)
        db.flush()
        pending.clear()
