from decimal import Decimal
from types import SimpleNamespace

import pytest

from app.services.flow_engine import aggregate_packets, identify_flow


def packet(
    index: int,
    *,
    source: str | None = "192.0.2.1",
    destination: str | None = "198.51.100.2",
    source_port: int | None = 51500,
    destination_port: int | None = 443,
    protocol: str | None = "TCP",
    network: str = "IPv4",
    ip_protocol: int | None = 6,
    timestamp: str | None = "10.000000000",
    length: int = 100,
    flags: int | None = 0x02,
    analysis_id: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        analysis_id=analysis_id,
        packet_index=index,
        timestamp=Decimal(timestamp) if timestamp is not None else None,
        source_ip=source,
        destination_ip=destination,
        source_port=source_port,
        destination_port=destination_port,
        network_protocol=network,
        transport_protocol=protocol,
        ip_protocol_number=ip_protocol,
        packet_length=length,
        tcp_flags=flags,
    )


def aggregate(packets: list[SimpleNamespace]):
    timestamp_ordered = sorted(
        (item for item in packets if item.timestamp is not None),
        key=lambda item: (item.timestamp, item.packet_index),
    )
    return aggregate_packets(packets, timestamp_ordered)


def test_same_and_reverse_directions_share_stable_flow_with_canonical_direction() -> None:
    forward = packet(1)
    reverse = packet(
        2,
        source="198.51.100.2",
        destination="192.0.2.1",
        source_port=443,
        destination_port=51500,
    )

    forward_key, forward_direction = identify_flow(forward)
    reverse_key, reverse_direction = identify_flow(reverse)

    assert forward_key.flow_id == reverse_key.flow_id
    assert forward_key.endpoint_a.address == "192.0.2.1"
    assert forward_key.endpoint_a.port == 51500
    assert forward_direction is True
    assert reverse_direction is False
    assert identify_flow(forward)[0].flow_id == forward_key.flow_id


def test_different_ports_and_protocols_do_not_merge() -> None:
    base = packet(1)
    other_port = packet(2, source_port=51501)
    udp = packet(3, protocol="UDP", ip_protocol=17, flags=None)

    assert len({identify_flow(item)[0].flow_id for item in (base, other_port, udp)}) == 3


def test_ipv4_and_ipv6_have_distinct_keys_and_compressed_addresses() -> None:
    v4 = packet(1)
    v6 = packet(
        2,
        source="2001:0db8::1",
        destination="2001:db8::2",
        network="IPv6",
    )

    v4_key, _ = identify_flow(v4)
    v6_key, _ = identify_flow(v6)

    assert v4_key.ip_version == 4
    assert v6_key.ip_version == 6
    assert v6_key.endpoint_a.address == "2001:db8::1"
    assert v4_key.flow_id != v6_key.flow_id


def test_missing_tcp_ports_isolate_packets_instead_of_merging_unknown_tuples() -> None:
    first = packet(1, source_port=None)
    second = packet(2, source_port=None)

    assert identify_flow(first)[0].flow_id != identify_flow(second)[0].flow_id
    assert len(aggregate([first, second])) == 2


def test_invalid_endpoint_ports_are_isolated_and_not_persisted_as_valid_ports() -> None:
    invalid = packet(1, source_port=65536)

    key, _ = identify_flow(invalid)

    assert key.isolated is True
    assert key.endpoint_a.port is None


def test_icmp_reverse_directions_group_without_ports() -> None:
    request = packet(
        1,
        protocol="ICMP",
        ip_protocol=1,
        source_port=None,
        destination_port=None,
        flags=None,
    )
    reply = packet(
        2,
        source="198.51.100.2",
        destination="192.0.2.1",
        protocol="ICMP",
        ip_protocol=1,
        source_port=None,
        destination_port=None,
        flags=None,
    )

    flows = aggregate([request, reply])

    assert len(flows) == 1
    result = next(iter(flows.values()))
    assert (result.forward_packets, result.backward_packets) == (1, 1)


def test_unknown_network_protocol_without_addresses_is_isolated_per_packet() -> None:
    one = packet(1, source=None, destination=None, network="Other", protocol=None, ip_protocol=None)
    two = packet(2, source=None, destination=None, network="Other", protocol=None, ip_protocol=None)

    assert identify_flow(one)[0].flow_id != identify_flow(two)[0].flow_id
    assert len(aggregate([one, two])) == 2


def test_protocol_number_is_retained_for_unrecognized_ip_transport() -> None:
    item = packet(1, protocol=None, ip_protocol=47, flags=None)

    key, _ = identify_flow(item)

    assert key.protocol_name == "IP-47"


def test_unrecognized_transport_protocol_numbers_do_not_collide() -> None:
    gre = packet(1, protocol="OTHER", ip_protocol=47, flags=None)
    esp = packet(2, protocol="OTHER", ip_protocol=50, flags=None)

    assert identify_flow(gre)[0].flow_id != identify_flow(esp)[0].flow_id


def test_missing_transport_name_uses_known_ip_protocol_number() -> None:
    named = packet(1, protocol="TCP", ip_protocol=6)
    inferred = packet(2, protocol=None, ip_protocol=6)

    assert identify_flow(named)[0].flow_id == identify_flow(inferred)[0].flow_id
    assert identify_flow(inferred)[0].protocol_name == "TCP"


def test_conflicting_known_transport_and_ip_protocol_metadata_is_isolated() -> None:
    valid = packet(1, protocol="TCP", ip_protocol=6)
    conflicting = packet(2, protocol="TCP", ip_protocol=17)

    assert identify_flow(valid)[0].flow_id != identify_flow(conflicting)[0].flow_id
    assert identify_flow(conflicting)[0].isolated is True


def test_icmp_version_mismatch_is_isolated() -> None:
    item = packet(
        1,
        source="2001:db8::1",
        destination="2001:db8::2",
        network="IPv6",
        protocol="ICMP",
        ip_protocol=1,
        source_port=None,
        destination_port=None,
        flags=None,
    )

    key, _ = identify_flow(item)

    assert key.isolated is True


def test_analysis_id_is_part_of_stable_flow_scope() -> None:
    one = packet(1, analysis_id=1)
    two = packet(1, analysis_id=2)

    assert identify_flow(one)[0].flow_id != identify_flow(two)[0].flow_id
    assert len(aggregate([one, two])) == 2


def test_aggregates_direction_lengths_timestamps_rates_and_tcp_flags() -> None:
    packets = [
        packet(1, timestamp="1", length=100, flags=0x02),
        packet(
            2,
            source="198.51.100.2",
            destination="192.0.2.1",
            source_port=443,
            destination_port=51500,
            timestamp="2",
            length=200,
            flags=0x12,
        ),
        packet(3, timestamp="4", length=300, flags=0x11),
    ]

    features = next(iter(aggregate(packets).values())).feature_values()

    assert (features["total_packets"], features["total_bytes"]) == (3, 600)
    assert (features["forward_packets"], features["backward_packets"]) == (2, 1)
    assert (features["forward_bytes"], features["backward_bytes"]) == (400, 200)
    assert (features["first_timestamp"], features["last_timestamp"]) == (
        Decimal("1"),
        Decimal("4"),
    )
    assert features["duration_seconds"] == Decimal("3")
    assert (features["packet_length_min"], features["packet_length_max"]) == (100, 300)
    assert features["packet_length_mean"] == Decimal("200")
    assert float(features["packet_length_stddev"]) == pytest.approx((20000 / 3) ** 0.5)
    assert (features["interarrival_min"], features["interarrival_max"]) == (
        Decimal("1"),
        Decimal("2"),
    )
    assert features["interarrival_mean"] == Decimal("1.5")
    assert features["interarrival_stddev"] == Decimal("0.5")
    assert (features["syn_count"], features["ack_count"], features["fin_count"]) == (2, 2, 1)
    assert (features["rst_count"], features["psh_count"], features["urg_count"]) == (0, 0, 0)
    assert (
        features["forward_syn_only_count"],
        features["backward_syn_only_count"],
        features["forward_syn_ack_count"],
        features["backward_syn_ack_count"],
    ) == (1, 0, 0, 1)
    assert features["packets_per_second"] == Decimal("1")
    assert features["bytes_per_second"] == Decimal("200")
    assert all(value.is_finite() for value in features.values() if isinstance(value, Decimal))


def test_single_packet_has_zero_length_deviation_and_null_interarrival_and_rates() -> None:
    features = next(iter(aggregate([packet(1, timestamp="7")]).values())).feature_values()

    assert features["duration_seconds"] == Decimal("0")
    assert features["packet_length_stddev"] == Decimal("0")
    assert features["interarrival_min"] is None
    assert features["interarrival_mean"] is None
    assert features["packets_per_second"] is None
    assert features["bytes_per_second"] is None


def test_zero_duration_multiple_packets_has_zero_interarrival_and_null_rates() -> None:
    packets = [packet(1, timestamp="7"), packet(2, timestamp="7")]
    features = next(iter(aggregate(packets).values())).feature_values()

    assert features["interarrival_min"] == Decimal("0")
    assert features["interarrival_max"] == Decimal("0")
    assert features["interarrival_mean"] == Decimal("0")
    assert features["interarrival_stddev"] == Decimal("0")
    assert features["packets_per_second"] is None
    assert features["bytes_per_second"] is None


def test_out_of_order_timestamps_use_chronological_interarrival_statistics() -> None:
    packets = [
        packet(1, timestamp="1"),
        packet(2, timestamp="3"),
        packet(3, timestamp="2"),
        packet(4, timestamp="4"),
    ]

    features = next(iter(aggregate(packets).values())).feature_values()

    assert features["duration_seconds"] == Decimal("3")
    assert features["interarrival_min"] == Decimal("1")
    assert features["interarrival_max"] == Decimal("1")
    assert features["interarrival_mean"] == Decimal("1")
    assert features["interarrival_stddev"] == Decimal("0")


def test_missing_timestamps_produce_null_timing_features_and_non_tcp_flags() -> None:
    packets = [packet(1, timestamp=None, protocol="UDP", ip_protocol=17, flags=None)]
    features = next(iter(aggregate(packets).values())).feature_values()

    assert features["first_timestamp"] is None
    assert features["duration_seconds"] is None
    assert features["interarrival_mean"] is None
    assert features["packets_per_second"] is None
    assert features["syn_count"] is None
    assert features["forward_syn_only_count"] is None
    assert features["backward_syn_ack_count"] is None


def test_empty_packet_collection_produces_no_flows() -> None:
    assert aggregate([]) == {}
