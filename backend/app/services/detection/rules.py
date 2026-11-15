import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Protocol

from app.services.detection.config import DetectionConfig, SeverityThresholds

SUPPORTING_FLOW_SAMPLE_LIMIT = 100


class FlowLike(Protocol):
    id: int
    protocol_name: str
    endpoint_a_ip: str | None
    endpoint_a_port: int | None
    endpoint_b_ip: str | None
    endpoint_b_port: int | None
    first_packet_source_ip: str | None
    first_packet_source_port: int | None
    first_packet_destination_ip: str | None
    first_packet_destination_port: int | None
    forward_syn_only_count: int | None
    backward_syn_only_count: int | None
    forward_syn_ack_count: int | None
    backward_syn_ack_count: int | None


@dataclass(frozen=True, slots=True)
class DetectionCandidate:
    rule_id: str
    rule_name: str
    severity: str
    source_ip: str
    destination_ip: str
    protocol_name: str | None
    explanation: str
    evidence: dict[str, object]
    supporting_flow_count: int
    supporting_flow_ids: tuple[int, ...]
    supporting_flow_sample_truncated: bool
    finding_key: str


@dataclass(slots=True)
class _Group:
    ports: set[int] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    scan_flow_count: int = 0
    scan_flow_ids: list[int] = field(default_factory=list)
    syn_only_packets: int = 0
    syn_ack_responses: int = 0
    syn_flow_count: int = 0
    syn_flow_ids: list[int] = field(default_factory=list)
    attempt_flow_count: int = 0
    attempt_flow_ids: list[int] = field(default_factory=list)


def evaluate_rules(
    flows: Iterable[FlowLike], config: DetectionConfig
) -> Iterator[DetectionCandidate]:
    """Evaluate configured rules over flow rows without retaining those rows."""
    if not (
        config.port_scan_enabled or config.syn_flood_enabled or config.connection_attempts_enabled
    ):
        return
    groups: dict[tuple[str, str], _Group] = {}

    for flow in flows:
        if flow.protocol_name not in {"TCP", "UDP"}:
            continue

        direction = _initiator_direction(flow)
        if direction is None:
            continue
        source_ip, destination_ip, _, destination_port = direction
        if not source_ip or not destination_ip:
            continue
        group = groups.setdefault((source_ip, destination_ip), _Group())

        if flow.protocol_name in {"TCP", "UDP"} and destination_port is not None:
            group.scan_flow_count += 1
            group.ports.add(destination_port)
            group.protocols.add(flow.protocol_name)
            _append_sample(group.scan_flow_ids, flow.id)

        if flow.protocol_name != "TCP":
            continue

        forward_syn = flow.forward_syn_only_count or 0
        backward_syn = flow.backward_syn_only_count or 0
        forward_syn_ack = flow.forward_syn_ack_count or 0
        backward_syn_ack = flow.backward_syn_ack_count or 0
        syn_directions = []
        if forward_syn:
            syn_directions.append(
                (flow.endpoint_a_ip, flow.endpoint_b_ip, forward_syn, backward_syn_ack)
            )
        if backward_syn:
            syn_directions.append(
                (flow.endpoint_b_ip, flow.endpoint_a_ip, backward_syn, forward_syn_ack)
            )

        flow_syn_groups: dict[tuple[str, str], tuple[int, int]] = {}
        for syn_source, syn_destination, syn_count, response_count in syn_directions:
            if not syn_source or not syn_destination:
                continue
            group_key = (syn_source, syn_destination)
            existing_syn, existing_responses = flow_syn_groups.get(group_key, (0, 0))
            flow_syn_groups[group_key] = (
                existing_syn + syn_count,
                existing_responses + response_count,
            )

        for group_key, (syn_count, response_count) in flow_syn_groups.items():
            syn_group = groups.setdefault(group_key, _Group())
            syn_group.syn_only_packets += syn_count
            syn_group.syn_ack_responses += response_count
            syn_group.syn_flow_count += 1
            _append_sample(syn_group.syn_flow_ids, flow.id)

        if flow.forward_syn_only_count is not None or flow.backward_syn_only_count is not None:
            if flow.forward_syn_only_count or flow.backward_syn_only_count:
                attempt_group = groups.setdefault((source_ip, destination_ip), _Group())
                attempt_group.attempt_flow_count += 1
                _append_sample(attempt_group.attempt_flow_ids, flow.id)

    for source_ip, destination_ip in sorted(groups):
        group = groups[(source_ip, destination_ip)]
        if config.port_scan_enabled and len(group.ports) >= config.port_scan_thresholds.low:
            yield _candidate(
                rule_id="PORT_SCAN",
                rule_name="Multi-port probing",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol_name="TCP/UDP",
                observed=len(group.ports),
                thresholds=config.port_scan_thresholds,
                explanation=(
                    f"The source contacted {len(group.ports)} distinct destination ports "
                    "on one target in this capture. This pattern can have benign causes."
                ),
                evidence={
                    "distinct_destination_port_count": len(group.ports),
                    "destination_ports_sample": sorted(group.ports)[:SUPPORTING_FLOW_SAMPLE_LIMIT],
                    "destination_ports_sample_truncated": len(group.ports)
                    > SUPPORTING_FLOW_SAMPLE_LIMIT,
                    "flow_count": group.scan_flow_count,
                    "protocols": sorted(group.protocols),
                    "thresholds": _threshold_values(config.port_scan_thresholds),
                },
                flow_count=group.scan_flow_count,
                flow_ids=group.scan_flow_ids,
            )

        if config.syn_flood_enabled and group.syn_only_packets >= config.syn_flood_thresholds.low:
            yield _candidate(
                rule_id="SYN_FLOOD_LIKE",
                rule_name="High SYN-only packet volume",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol_name="TCP",
                observed=group.syn_only_packets,
                thresholds=config.syn_flood_thresholds,
                explanation=(
                    f"The source sent {group.syn_only_packets} TCP SYN-only packets to the target "
                    "in this capture. This is an indicator, not confirmation of a "
                    "denial-of-service attack."
                ),
                evidence={
                    "observation_scope": "entire_analysis_capture",
                    "syn_only_packet_count": group.syn_only_packets,
                    "reverse_direction_syn_ack_packet_count": group.syn_ack_responses,
                    "supporting_flow_count": group.syn_flow_count,
                    "thresholds": _threshold_values(config.syn_flood_thresholds),
                    "window_limitation": (
                        "Per-packet timestamps are not retained with directional TCP flags; "
                        "the rule evaluates the whole capture and does not claim a "
                        "time-window rate."
                    ),
                },
                flow_count=group.syn_flow_count,
                flow_ids=group.syn_flow_ids,
            )

        if (
            config.connection_attempts_enabled
            and group.attempt_flow_count >= config.connection_attempts_thresholds.low
        ):
            yield _candidate(
                rule_id="EXCESSIVE_CONNECTION_ATTEMPTS",
                rule_name="Repeated TCP connection tuples with SYN",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol_name="TCP",
                observed=group.attempt_flow_count,
                thresholds=config.connection_attempts_thresholds,
                explanation=(
                    f"The source has {group.attempt_flow_count} distinct TCP flow tuples with "
                    "observed SYN-only traffic to the target. The capture does not prove that "
                    "connections were established."
                ),
                evidence={
                    "distinct_tcp_flow_tuples_with_syn": group.attempt_flow_count,
                    "supporting_flow_count": group.attempt_flow_count,
                    "connection_establishment_proven": False,
                    "thresholds": _threshold_values(config.connection_attempts_thresholds),
                    "tuple_reuse_limitation": (
                        "Repeated sessions that reuse a five-tuple are merged into one "
                        "flow by Day 3."
                    ),
                },
                flow_count=group.attempt_flow_count,
                flow_ids=group.attempt_flow_ids,
            )


def _initiator_direction(
    flow: FlowLike,
) -> tuple[str, str, int | None, int | None] | None:
    forward_syn = flow.forward_syn_only_count or 0
    backward_syn = flow.backward_syn_only_count or 0
    if forward_syn > backward_syn:
        return flow.endpoint_a_ip, flow.endpoint_b_ip, flow.endpoint_a_port, flow.endpoint_b_port
    if backward_syn > forward_syn:
        return flow.endpoint_b_ip, flow.endpoint_a_ip, flow.endpoint_b_port, flow.endpoint_a_port
    if forward_syn and backward_syn:
        first_source = flow.first_packet_source_ip
        if first_source == flow.endpoint_b_ip:
            return (
                flow.endpoint_b_ip,
                flow.endpoint_a_ip,
                flow.endpoint_b_port,
                flow.endpoint_a_port,
            )
        return flow.endpoint_a_ip, flow.endpoint_b_ip, flow.endpoint_a_port, flow.endpoint_b_port
    if flow.first_packet_source_ip and flow.first_packet_destination_ip:
        return (
            flow.first_packet_source_ip,
            flow.first_packet_destination_ip,
            flow.first_packet_source_port,
            flow.first_packet_destination_port,
        )
    return None


def _candidate(
    *,
    rule_id: str,
    rule_name: str,
    source_ip: str,
    destination_ip: str,
    protocol_name: str | None,
    observed: int,
    thresholds: SeverityThresholds,
    explanation: str,
    evidence: dict[str, object],
    flow_count: int,
    flow_ids: list[int],
) -> DetectionCandidate:
    identity = {
        "rule_id": rule_id,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol_name": protocol_name,
    }
    finding_key = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return DetectionCandidate(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=classify_severity(observed, thresholds),
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol_name=protocol_name,
        explanation=explanation,
        evidence=evidence,
        supporting_flow_count=flow_count,
        supporting_flow_ids=tuple(flow_ids),
        supporting_flow_sample_truncated=flow_count > len(flow_ids),
        finding_key=finding_key,
    )


def classify_severity(observed: int, thresholds: SeverityThresholds) -> str:
    if observed >= thresholds.critical:
        return "critical"
    if observed >= thresholds.high:
        return "high"
    if observed >= thresholds.medium:
        return "medium"
    return "low"


def _threshold_values(thresholds: SeverityThresholds) -> dict[str, int]:
    return thresholds.model_dump()


def _append_sample(samples: list[int], flow_id: int) -> None:
    if len(samples) < SUPPORTING_FLOW_SAMPLE_LIMIT:
        samples.append(flow_id)
