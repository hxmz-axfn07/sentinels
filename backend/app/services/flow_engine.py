import hashlib
import ipaddress
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Protocol


class PacketLike(Protocol):
    analysis_id: int
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


@dataclass(frozen=True, slots=True)
class Endpoint:
    address: str | None
    port: int | None


@dataclass(frozen=True, slots=True)
class CanonicalFlowKey:
    flow_id: str
    analysis_id: int
    ip_version: int | None
    protocol_name: str
    protocol_number: int | None
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    isolated: bool


def identify_flow(packet: PacketLike) -> tuple[CanonicalFlowKey, bool]:
    """Return a stable bidirectional key and whether this packet is forward."""
    transport = (packet.transport_protocol or "").strip().upper()
    network = (packet.network_protocol or "OTHER").strip().upper()
    protocol_number = packet.ip_protocol_number
    valid_protocol_number = protocol_number is None or 0 <= protocol_number <= 255

    if not transport and valid_protocol_number:
        inferred_protocols = {6: "TCP", 17: "UDP", 58: "ICMPV6"}
        if protocol_number == 1 and network != "IPV6":
            inferred_protocols[1] = "ICMP"
        transport = inferred_protocols.get(protocol_number, "")
    if transport:
        protocol = transport
    elif valid_protocol_number and protocol_number is not None:
        protocol = f"IP-{protocol_number}"
    else:
        protocol = network or "OTHER"

    uses_ports = protocol in {"TCP", "UDP"}
    source_port = packet.source_port if uses_ports and _valid_port(packet.source_port) else None
    destination_port = (
        packet.destination_port if uses_ports and _valid_port(packet.destination_port) else None
    )
    source_address = _parse_address(packet.source_ip)
    destination_address = _parse_address(packet.destination_ip)

    addresses_complete = (
        source_address is not None
        and destination_address is not None
        and source_address.version == destination_address.version
    )
    ports_complete = not uses_ports or (
        _valid_port(packet.source_port) and _valid_port(packet.destination_port)
    )
    network_version_matches = (
        network not in {"IPV4", "IPV6"}
        or (network == "IPV4" and source_address is not None and source_address.version == 4)
        or (network == "IPV6" and source_address is not None and source_address.version == 6)
    )
    expected_protocol_numbers = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV6": 58}
    protocol_number_matches = (
        protocol not in expected_protocol_numbers
        or protocol_number is None
        or protocol_number == expected_protocol_numbers[protocol]
    )
    expected_ip_versions = {"ICMP": 4, "ICMPV6": 6}
    protocol_family_matches = (
        protocol not in expected_ip_versions
        or source_address is None
        or source_address.version == expected_ip_versions[protocol]
    )
    isolated = not (
        addresses_complete
        and ports_complete
        and network_version_matches
        and valid_protocol_number
        and protocol_number_matches
        and protocol_family_matches
    )

    version = source_address.version if addresses_complete else None
    if network == "ARP":
        version = None

    source = Endpoint(
        source_address.compressed if source_address else None,
        source_port,
    )
    destination = Endpoint(
        destination_address.compressed if destination_address else None,
        destination_port,
    )

    if isolated:
        endpoint_a, endpoint_b = source, destination
        direction_forward = True
        identity = {
            "analysis_id": packet.analysis_id,
            "packet_index": packet.packet_index,
            "protocol": protocol,
            "protocol_number": protocol_number,
            "source": _endpoint_json(source),
            "destination": _endpoint_json(destination),
            "isolated": True,
        }
    else:
        source_order = _endpoint_order(source, source_address)
        destination_order = _endpoint_order(destination, destination_address)
        if source_order <= destination_order:
            endpoint_a, endpoint_b = source, destination
            direction_forward = True
        else:
            endpoint_a, endpoint_b = destination, source
            direction_forward = False
        identity = {
            "analysis_id": packet.analysis_id,
            "ip_version": version,
            "protocol": protocol,
            "protocol_number": (None if protocol in expected_protocol_numbers else protocol_number),
            "endpoint_a": _endpoint_json(endpoint_a),
            "endpoint_b": _endpoint_json(endpoint_b),
        }

    flow_id = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return (
        CanonicalFlowKey(
            flow_id=flow_id,
            analysis_id=packet.analysis_id,
            ip_version=version,
            protocol_name=protocol,
            protocol_number=protocol_number if valid_protocol_number else None,
            endpoint_a=endpoint_a,
            endpoint_b=endpoint_b,
            isolated=isolated,
        ),
        direction_forward,
    )


def _parse_address(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if value is None:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _valid_port(value: int | None) -> bool:
    return value is not None and 0 <= value <= 65535


def _endpoint_order(
    endpoint: Endpoint, address: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> tuple[int, int, int]:
    return address.version, int(address), endpoint.port if endpoint.port is not None else -1


def _endpoint_json(endpoint: Endpoint) -> list[str | int | None]:
    return [endpoint.address, endpoint.port]


@dataclass(slots=True)
class RunningStatistics:
    count: int = 0
    mean: Decimal = Decimal(0)
    squared_deviation_sum: Decimal = Decimal(0)
    minimum: Decimal | None = None
    maximum: Decimal | None = None

    def add(self, value: int | Decimal) -> None:
        value_decimal = value if isinstance(value, Decimal) else Decimal(value)
        self.count += 1
        difference = value_decimal - self.mean
        self.mean += difference / self.count
        self.squared_deviation_sum += difference * (value_decimal - self.mean)
        self.minimum = value_decimal if self.minimum is None else min(self.minimum, value_decimal)
        self.maximum = value_decimal if self.maximum is None else max(self.maximum, value_decimal)

    @property
    def standard_deviation(self) -> Decimal | None:
        if self.count == 0:
            return None
        variance = max(Decimal(0), self.squared_deviation_sum / self.count)
        return variance.sqrt()

    @property
    def optional_mean(self) -> Decimal | None:
        return self.mean if self.count else None


@dataclass(slots=True)
class FlowAggregate:
    key: CanonicalFlowKey
    total_packets: int = 0
    total_bytes: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    first_packet_index: int | None = None
    first_packet_source_ip: str | None = None
    first_packet_source_port: int | None = None
    first_packet_destination_ip: str | None = None
    first_packet_destination_port: int | None = None
    first_timestamp: Decimal | None = None
    last_timestamp: Decimal | None = None
    last_interarrival_timestamp: Decimal | None = None
    packet_lengths: RunningStatistics = field(default_factory=RunningStatistics)
    interarrival_times: RunningStatistics = field(default_factory=RunningStatistics)
    tcp_flags_observed: bool = False
    forward_tcp_flags_observed: bool = False
    backward_tcp_flags_observed: bool = False
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    forward_syn_only_count: int = 0
    backward_syn_only_count: int = 0
    forward_syn_ack_count: int = 0
    backward_syn_ack_count: int = 0

    def add_packet(self, packet: PacketLike, forward: bool) -> None:
        self.total_packets += 1
        self.total_bytes += packet.packet_length
        self.packet_lengths.add(packet.packet_length)
        if forward:
            self.forward_packets += 1
            self.forward_bytes += packet.packet_length
        else:
            self.backward_packets += 1
            self.backward_bytes += packet.packet_length

        if self.first_packet_index is None or packet.packet_index < self.first_packet_index:
            self.first_packet_index = packet.packet_index
            self.first_packet_source_ip = packet.source_ip
            self.first_packet_source_port = packet.source_port
            self.first_packet_destination_ip = packet.destination_ip
            self.first_packet_destination_port = packet.destination_port

        if packet.timestamp is not None:
            if self.first_timestamp is None or packet.timestamp < self.first_timestamp:
                self.first_timestamp = packet.timestamp
            if self.last_timestamp is None or packet.timestamp > self.last_timestamp:
                self.last_timestamp = packet.timestamp

        if self.key.protocol_name == "TCP" and packet.tcp_flags is not None:
            self.tcp_flags_observed = True
            flags = packet.tcp_flags
            if forward:
                self.forward_tcp_flags_observed = True
            else:
                self.backward_tcp_flags_observed = True
            self.fin_count += bool(flags & 0x01)
            self.syn_count += bool(flags & 0x02)
            self.rst_count += bool(flags & 0x04)
            self.psh_count += bool(flags & 0x08)
            self.ack_count += bool(flags & 0x10)
            self.urg_count += bool(flags & 0x20)
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            if syn and ack:
                if forward:
                    self.forward_syn_ack_count += 1
                else:
                    self.backward_syn_ack_count += 1
            elif syn:
                if forward:
                    self.forward_syn_only_count += 1
                else:
                    self.backward_syn_only_count += 1

    def add_timestamp_ordered(self, timestamp: Decimal) -> None:
        previous = self.last_interarrival_timestamp
        if previous is not None:
            interval = timestamp - previous
            if interval >= 0:
                self.interarrival_times.add(interval)
        self.last_interarrival_timestamp = timestamp

    def feature_values(self) -> dict[str, int | Decimal | str | None]:
        duration = (
            self.last_timestamp - self.first_timestamp
            if self.first_timestamp is not None and self.last_timestamp is not None
            else None
        )
        rate_is_defined = duration is not None and duration > 0
        flags_available = self.tcp_flags_observed
        return {
            "flow_id": self.key.flow_id,
            "ip_version": self.key.ip_version,
            "protocol_name": self.key.protocol_name,
            "protocol_number": self.key.protocol_number,
            "endpoint_a_ip": self.key.endpoint_a.address,
            "endpoint_a_port": self.key.endpoint_a.port,
            "endpoint_b_ip": self.key.endpoint_b.address,
            "endpoint_b_port": self.key.endpoint_b.port,
            "first_packet_source_ip": self.first_packet_source_ip,
            "first_packet_source_port": self.first_packet_source_port,
            "first_packet_destination_ip": self.first_packet_destination_ip,
            "first_packet_destination_port": self.first_packet_destination_port,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "duration_seconds": duration,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "forward_packets": self.forward_packets,
            "backward_packets": self.backward_packets,
            "forward_bytes": self.forward_bytes,
            "backward_bytes": self.backward_bytes,
            "packet_length_min": int(self.packet_lengths.minimum)
            if self.packet_lengths.minimum is not None
            else None,
            "packet_length_max": int(self.packet_lengths.maximum)
            if self.packet_lengths.maximum is not None
            else None,
            "packet_length_mean": self.packet_lengths.optional_mean,
            "packet_length_stddev": self.packet_lengths.standard_deviation,
            "interarrival_min": self.interarrival_times.minimum,
            "interarrival_max": self.interarrival_times.maximum,
            "interarrival_mean": self.interarrival_times.optional_mean,
            "interarrival_stddev": self.interarrival_times.standard_deviation,
            "syn_count": self.syn_count if flags_available else None,
            "ack_count": self.ack_count if flags_available else None,
            "fin_count": self.fin_count if flags_available else None,
            "rst_count": self.rst_count if flags_available else None,
            "psh_count": self.psh_count if flags_available else None,
            "urg_count": self.urg_count if flags_available else None,
            "forward_syn_only_count": self.forward_syn_only_count
            if self.forward_tcp_flags_observed
            else None,
            "backward_syn_only_count": self.backward_syn_only_count
            if self.backward_tcp_flags_observed
            else None,
            "forward_syn_ack_count": self.forward_syn_ack_count
            if self.forward_tcp_flags_observed
            else None,
            "backward_syn_ack_count": self.backward_syn_ack_count
            if self.backward_tcp_flags_observed
            else None,
            "packets_per_second": Decimal(self.total_packets) / duration
            if rate_is_defined
            else None,
            "bytes_per_second": Decimal(self.total_bytes) / duration if rate_is_defined else None,
        }


def aggregate_packets(
    packets: Iterable[PacketLike],
    timestamp_ordered_packets: Iterable[PacketLike],
) -> dict[str, FlowAggregate]:
    """Aggregate two streaming passes over one analysis's packet metadata."""
    flows: dict[str, FlowAggregate] = {}
    for packet in packets:
        key, forward = identify_flow(packet)
        aggregate = flows.get(key.flow_id)
        if aggregate is None:
            aggregate = FlowAggregate(key=key)
            flows[key.flow_id] = aggregate
        aggregate.add_packet(packet, forward)

    for packet in timestamp_ordered_packets:
        if packet.timestamp is None:
            continue
        key, _ = identify_flow(packet)
        aggregate = flows.get(key.flow_id)
        if aggregate is not None:
            aggregate.add_timestamp_ordered(packet.timestamp)
    return flows
