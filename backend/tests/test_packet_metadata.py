from decimal import Decimal

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.services.packet_metadata import extract_packet_metadata, read_packet_metadata


def test_extracts_ipv4_tcp_flags_ports_timestamp_and_length() -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.4", dst="198.51.100.3")
        / TCP(sport=50123, dport=443, flags="SA")
        / Raw(load=b"payload-not-persisted")
    )
    packet.time = Decimal("1700000000.123456789")

    metadata = extract_packet_metadata(packet, 7)

    assert metadata.packet_index == 7
    assert metadata.timestamp == Decimal("1700000000.123456789")
    assert (metadata.source_ip, metadata.destination_ip) == ("192.0.2.4", "198.51.100.3")
    assert (metadata.source_port, metadata.destination_port) == (50123, 443)
    assert metadata.network_protocol == "IPv4"
    assert metadata.transport_protocol == "TCP"
    assert metadata.ip_protocol_number == 6
    assert metadata.tcp_flags == 0x12
    assert metadata.packet_length == len(packet)
    assert not hasattr(metadata, "payload")


def test_extracts_ipv6_udp_without_tcp_flags() -> None:
    packet = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=53, dport=5353)

    metadata = extract_packet_metadata(packet, 1)

    assert metadata.network_protocol == "IPv6"
    assert metadata.transport_protocol == "UDP"
    assert metadata.ip_protocol_number == 17
    assert metadata.source_ip == "2001:db8::1"
    assert metadata.destination_ip == "2001:db8::2"
    assert (metadata.source_port, metadata.destination_port) == (53, 5353)
    assert metadata.tcp_flags is None


def test_extracts_icmp_without_ports() -> None:
    metadata = extract_packet_metadata(Ether() / IP() / ICMP(type=8, code=0), 1)

    assert metadata.transport_protocol == "ICMP"
    assert metadata.source_port is None
    assert metadata.destination_port is None
    assert (metadata.icmp_type, metadata.icmp_code) == (8, 0)


def test_extracts_icmpv6_without_ports() -> None:
    metadata = extract_packet_metadata(Ether() / IPv6() / ICMPv6EchoRequest(), 1)

    assert metadata.transport_protocol == "ICMPv6"
    assert metadata.source_port is None
    assert metadata.destination_port is None
    assert metadata.icmp_type == 128


def test_handles_non_ip_packet_without_inventing_addresses_or_ports() -> None:
    metadata = extract_packet_metadata(Ether() / ARP(psrc="192.0.2.10", pdst="192.0.2.1"), 1)

    assert metadata.network_protocol == "ARP"
    assert metadata.source_ip == "192.0.2.10"
    assert metadata.destination_ip == "192.0.2.1"
    assert metadata.source_port is None
    assert metadata.destination_port is None


def test_handles_packet_without_recognized_network_or_transport_layers() -> None:
    from scapy.packet import Raw

    metadata = extract_packet_metadata(Raw(load=b"opaque synthetic bytes"), 1)

    assert metadata.network_protocol == "Other"
    assert metadata.source_ip is None
    assert metadata.destination_ip is None
    assert metadata.transport_protocol is None
    assert metadata.packet_length == 22


def test_reader_preserves_packet_order_and_timestamps(tmp_path) -> None:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    path = tmp_path / "ordered.pcap"
    first = Ether() / IP(dst="192.0.2.1") / UDP(dport=1000)
    second = Ether() / IP(dst="192.0.2.2") / UDP(dport=2000)
    first.time = Decimal("1700000000.100001")
    second.time = Decimal("1700000000.100002")
    wrpcap(str(path), [first, second])

    metadata = list(read_packet_metadata(str(path)))

    assert [packet.packet_index for packet in metadata] == [1, 2]
    assert [packet.destination_port for packet in metadata] == [1000, 2000]
    assert metadata[0].timestamp < metadata[1].timestamp
