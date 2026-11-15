from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.services.detection.config import DetectionConfig, SeverityThresholds
from app.services.detection.rules import classify_severity, evaluate_rules


def flow(
    flow_id: int,
    *,
    protocol: str = "TCP",
    source: str = "10.0.0.1",
    destination: str = "10.0.0.2",
    source_port: int = 40000,
    destination_port: int | None = 443,
    forward_syn: int | None = 1,
    backward_syn: int | None = 0,
    forward_syn_ack: int | None = 0,
    backward_syn_ack: int | None = 1,
    first_source: str | None = None,
) -> SimpleNamespace:
    if first_source is None:
        first_source = source
    return SimpleNamespace(
        id=flow_id,
        protocol_name=protocol,
        endpoint_a_ip=source,
        endpoint_a_port=source_port,
        endpoint_b_ip=destination,
        endpoint_b_port=destination_port,
        first_packet_source_ip=first_source,
        first_packet_source_port=source_port,
        first_packet_destination_ip=destination,
        first_packet_destination_port=destination_port,
        forward_syn_only_count=forward_syn,
        backward_syn_only_count=backward_syn,
        forward_syn_ack_count=forward_syn_ack,
        backward_syn_ack_count=backward_syn_ack,
    )


def candidates(flows, config: DetectionConfig | None = None):
    return list(evaluate_rules(flows, config or DetectionConfig()))


def test_port_scan_uses_distinct_ports_and_exact_threshold_boundaries() -> None:
    records = [flow(index, destination_port=port) for index, port in enumerate(range(1, 6), 1)]

    findings = candidates(records)

    scan = next(item for item in findings if item.rule_id == "PORT_SCAN")
    assert scan.severity == "low"
    assert scan.supporting_flow_count == 5
    assert scan.evidence["distinct_destination_port_count"] == 5
    assert scan.evidence["destination_ports_sample"] == [1, 2, 3, 4, 5]


def test_port_scan_same_port_and_reverse_flow_do_not_inflate_distinct_ports() -> None:
    records = [
        flow(1, destination_port=443),
        flow(2, source_port=40001, destination_port=443),
        flow(
            3,
            source="10.0.0.2",
            destination="10.0.0.1",
            source_port=443,
            destination_port=40000,
            forward_syn=0,
            backward_syn=1,
            first_source="10.0.0.1",
        ),
    ]

    findings = candidates(records)

    assert not any(item.rule_id == "PORT_SCAN" for item in findings)


def test_port_scan_ignores_missing_ports_and_separates_targets() -> None:
    records = [flow(index, destination_port=None) for index in range(1, 8)] + [
        flow(index + 10, destination="10.0.0.3", destination_port=index) for index in range(1, 6)
    ]

    findings = candidates(records)

    scans = [item for item in findings if item.rule_id == "PORT_SCAN"]
    assert len(scans) == 1
    assert scans[0].destination_ip == "10.0.0.3"
    assert scans[0].supporting_flow_count == 5


def test_port_scan_includes_tcp_and_udp_but_counts_port_numbers_once() -> None:
    records = [
        flow(1, destination_port=53),
        flow(2, protocol="UDP", destination_port=53, forward_syn=None, backward_syn=None),
        flow(3, destination_port=80),
        flow(4, destination_port=123),
        flow(5, destination_port=443),
        flow(6, destination_port=8080),
    ]

    scan = next(item for item in candidates(records) if item.rule_id == "PORT_SCAN")

    assert scan.evidence["distinct_destination_port_count"] == 5
    assert scan.evidence["flow_count"] == 6
    assert scan.evidence["protocols"] == ["TCP", "UDP"]


def test_tcp_port_scan_uses_syn_initiator_even_if_first_packet_is_reverse() -> None:
    records = [
        flow(
            index,
            source="10.0.0.2",
            destination="10.0.0.1",
            source_port=index,
            destination_port=40_000 + index,
            backward_syn=1,
            forward_syn=0,
            first_source="10.0.0.2",
        )
        for index in range(1, 6)
    ]

    scan = next(item for item in candidates(records) if item.rule_id == "PORT_SCAN")

    assert scan.source_ip == "10.0.0.1"
    assert scan.destination_ip == "10.0.0.2"


def test_syn_rule_counts_syn_only_and_does_not_flag_syn_ack_alone() -> None:
    records = [
        flow(1, forward_syn=19, backward_syn=0, backward_syn_ack=19),
        flow(2, forward_syn=1, backward_syn=0, backward_syn_ack=1),
        flow(
            3,
            destination="10.0.0.3",
            forward_syn=0,
            backward_syn=0,
            forward_syn_ack=80,
            backward_syn_ack=40,
        ),
    ]

    findings = candidates(records)
    syn = next(item for item in findings if item.rule_id == "SYN_FLOOD_LIKE")

    assert syn.source_ip == "10.0.0.1"
    assert syn.destination_ip == "10.0.0.2"
    assert syn.evidence["syn_only_packet_count"] == 20
    assert syn.evidence["reverse_direction_syn_ack_packet_count"] == 20
    assert syn.severity == "low"
    assert not any(
        item.rule_id == "SYN_FLOOD_LIKE" and item.destination_ip == "10.0.0.3" for item in findings
    )


def test_syn_threshold_severity_and_observation_scope() -> None:
    finding = next(
        item
        for item in candidates([flow(1, forward_syn=500, backward_syn=0)])
        if item.rule_id == "SYN_FLOOD_LIKE"
    )

    assert finding.severity == "high"
    assert finding.evidence["observation_scope"] == "entire_analysis_capture"
    assert "does not claim a time-window rate" in finding.evidence["window_limitation"]


def test_missing_tcp_metadata_does_not_invent_syn_counts() -> None:
    findings = candidates([flow(1, forward_syn=None, backward_syn=None)])

    assert not any(item.rule_id == "SYN_FLOOD_LIKE" for item in findings)
    assert not any(item.rule_id == "EXCESSIVE_CONNECTION_ATTEMPTS" for item in findings)


def test_connection_rule_counts_distinct_tcp_flow_tuples_not_packets() -> None:
    records = [
        flow(index, source_port=40000 + index, destination_port=443, forward_syn=20)
        for index in range(1, 11)
    ]

    findings = candidates(records)
    attempts = next(item for item in findings if item.rule_id == "EXCESSIVE_CONNECTION_ATTEMPTS")

    assert attempts.supporting_flow_count == 10
    assert attempts.evidence["distinct_tcp_flow_tuples_with_syn"] == 10
    assert attempts.evidence["connection_establishment_proven"] is False


def test_connection_rule_separates_direction_and_ignores_udp() -> None:
    records = [
        flow(index, destination="10.0.0.3", source_port=40000 + index) for index in range(1, 10)
    ] + [
        flow(index + 20, protocol="UDP", destination="10.0.0.2", source_port=40000 + index)
        for index in range(1, 11)
    ]

    assert not any(item.rule_id == "EXCESSIVE_CONNECTION_ATTEMPTS" for item in candidates(records))


def test_rules_can_be_disabled_and_severity_boundaries_are_deterministic() -> None:
    config = DetectionConfig(
        port_scan_enabled=False,
        syn_flood_enabled=False,
        connection_attempts_enabled=False,
    )
    assert candidates([flow(index, destination_port=index) for index in range(1, 10)], config) == []

    thresholds = SeverityThresholds(low=5, medium=10, high=25, critical=50)
    assert [classify_severity(value, thresholds) for value in (4, 5, 10, 25, 50)] == [
        "low",
        "low",
        "medium",
        "high",
        "critical",
    ]


def test_config_thresholds_must_be_positive_and_strictly_ordered() -> None:
    with pytest.raises(ValidationError):
        SeverityThresholds(low=0, medium=1, high=2, critical=3)
    with pytest.raises(ValidationError):
        SeverityThresholds(low=1, medium=2, high=2, critical=4)
    with pytest.raises(ValidationError):
        DetectionConfig(
            port_scan_thresholds=SeverityThresholds(low=1, medium=2, high=3, critical=65_536)
        )


def test_detection_configuration_can_be_overridden_by_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DETECTION_CONFIG__PORT_SCAN_ENABLED", "false")
    monkeypatch.setenv("DETECTION_CONFIG__PORT_SCAN_THRESHOLDS__LOW", "7")

    configured = Settings(_env_file=None).detection_config

    assert configured.port_scan_enabled is False
    assert configured.port_scan_thresholds.low == 7


def test_incomplete_endpoint_metadata_does_not_create_a_finding() -> None:
    incomplete = flow(1)
    incomplete.first_packet_source_ip = None
    incomplete.endpoint_a_ip = None

    assert candidates([incomplete]) == []


def test_finding_flow_link_samples_are_bounded_and_report_truncation() -> None:
    records = [flow(index, destination_port=index) for index in range(1, 102)]

    scan = next(item for item in candidates(records) if item.rule_id == "PORT_SCAN")

    assert scan.supporting_flow_count == 101
    assert len(scan.supporting_flow_ids) == 100
    assert scan.supporting_flow_sample_truncated is True
