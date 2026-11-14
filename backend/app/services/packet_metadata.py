from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet
from scapy.utils import PcapReader


@dataclass(frozen=True, slots=True)
class PacketMetadata:
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


def read_packet_metadata(path: str) -> Iterator[PacketMetadata]:
    reader = PcapReader(path)
    try:
        for packet_index, packet in enumerate(reader, start=1):
            yield extract_packet_metadata(packet, packet_index)
    finally:
        reader.close()


def extract_packet_metadata(packet: Packet, packet_index: int) -> PacketMetadata:
    ipv4 = packet.getlayer(IP)
    ipv6 = packet.getlayer(IPv6)
    if ipv4 is not None:
        network_protocol = "IPv4"
        source_ip, destination_ip = str(ipv4.src), str(ipv4.dst)
        ip_protocol_number = int(ipv4.proto)
    elif ipv6 is not None:
        network_protocol = "IPv6"
        source_ip, destination_ip = str(ipv6.src), str(ipv6.dst)
        ip_protocol_number = int(ipv6.nh)
    elif packet.haslayer(ARP):
        arp = packet.getlayer(ARP)
        network_protocol = "ARP"
        source_ip = str(arp.psrc) or None
        destination_ip = str(arp.pdst) or None
        ip_protocol_number = None
    else:
        network_protocol = "Other"
        source_ip = destination_ip = None
        ip_protocol_number = None

    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    icmp = packet.getlayer(ICMP)
    icmpv6_layer = next(
        (layer for layer in packet.layers() if layer.__name__.startswith("ICMPv6")),
        None,
    )
    icmpv6 = packet.getlayer(icmpv6_layer) if icmpv6_layer is not None else None
    source_port = destination_port = tcp_flags = icmp_type = icmp_code = None
    transport_protocol = None

    if tcp is not None:
        transport_protocol = "TCP"
        source_port, destination_port = int(tcp.sport), int(tcp.dport)
        tcp_flags = int(tcp.flags)
    elif udp is not None:
        transport_protocol = "UDP"
        source_port, destination_port = int(udp.sport), int(udp.dport)
    elif icmp is not None:
        transport_protocol = "ICMP"
        icmp_type, icmp_code = int(icmp.type), int(icmp.code)
    elif icmpv6 is not None:
        transport_protocol = "ICMPv6"
        icmp_type = _optional_int(getattr(icmpv6, "type", None))
        icmp_code = _optional_int(getattr(icmpv6, "code", None))
    elif ip_protocol_number == 1:
        transport_protocol = "ICMP"
    elif ip_protocol_number == 58:
        transport_protocol = "ICMPv6"
    elif ip_protocol_number == 6:
        transport_protocol = "TCP"
    elif ip_protocol_number == 17:
        transport_protocol = "UDP"

    timestamp = _timestamp(packet)
    return PacketMetadata(
        packet_index=packet_index,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        network_protocol=network_protocol,
        transport_protocol=transport_protocol,
        ip_protocol_number=ip_protocol_number,
        packet_length=len(packet),
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )


def _timestamp(packet: Packet) -> Decimal | None:
    try:
        value = Decimal(str(packet.time))
    except (InvalidOperation, TypeError, ValueError):
        return None
    return value if value.is_finite() else None


def _optional_int(value: int | None) -> int | None:
    return int(value) if value is not None else None
