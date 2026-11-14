import struct

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter, wrpcap, wrpcapng

from app.services.capture_format import (
    CaptureFormat,
    CaptureValidationError,
    EmptyCaptureError,
    UnsupportedCaptureError,
    inspect_capture,
)


def sample_packet() -> Ether:
    return (
        Ether()
        / IP(src="192.0.2.1", dst="198.51.100.8")
        / TCP(sport=43210, dport=443)
        / Raw(load=b"synthetic-test-payload")
    )


@pytest.mark.parametrize(
    ("endianness", "nano"),
    [("<", False), (">", False), ("<", True), (">", True)],
)
def test_accepts_pcap_byte_orders_and_timestamp_variants(
    tmp_path, endianness: str, nano: bool
) -> None:
    path = tmp_path / "synthetic.pcap"
    writer = PcapWriter(str(path), endianness=endianness, nano=nano)
    writer.write(sample_packet())
    writer.close()

    assert inspect_capture(path) is CaptureFormat.PCAP


def test_accepts_pcapng_by_content(tmp_path) -> None:
    path = tmp_path / "synthetic.pcapng"
    wrpcapng(str(path), sample_packet())

    assert inspect_capture(path) is CaptureFormat.PCAPNG


def test_accepts_big_endian_pcapng_section(tmp_path) -> None:
    packet = bytes(sample_packet())
    packet_padding = b"\x00" * ((-len(packet)) % 4)

    def block(kind: int, body: bytes) -> bytes:
        length = 12 + len(body)
        return struct.pack(">II", kind, length) + body + struct.pack(">I", length)

    section = block(0x0A0D0D0A, b"\x1a\x2b\x3c\x4d" + struct.pack(">HHq", 1, 0, -1))
    interface = block(1, struct.pack(">HHI", 1, 0, 65535))
    packet_data = struct.pack(">IIIII", 0, 0, 0, len(packet), len(packet)) + packet + packet_padding
    enhanced_packet = block(6, packet_data)
    path = tmp_path / "big-endian.pcapng"
    path.write_bytes(section + interface + enhanced_packet)

    assert inspect_capture(path) is CaptureFormat.PCAPNG


def test_rejects_empty_file(tmp_path) -> None:
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")

    with pytest.raises(EmptyCaptureError):
        inspect_capture(path)


def test_rejects_capture_without_packets(tmp_path) -> None:
    path = tmp_path / "no-packets.pcap"
    writer = PcapWriter(str(path), endianness="<")
    writer.close()

    with pytest.raises(EmptyCaptureError):
        inspect_capture(path)


def test_rejects_unsupported_content_even_with_pcap_extension(tmp_path) -> None:
    path = tmp_path / "looks-like-a-capture.pcap"
    path.write_bytes(b"this is not a packet capture")

    with pytest.raises(UnsupportedCaptureError):
        inspect_capture(path)


@pytest.mark.parametrize("data", [b"\xd4\xc3\xb2", b"\x0a\x0d\x0d\x0a\x00"])
def test_rejects_truncated_capture_headers(tmp_path, data: bytes) -> None:
    path = tmp_path / "truncated.pcap"
    path.write_bytes(data)

    with pytest.raises(CaptureValidationError):
        inspect_capture(path)


def test_rejects_truncated_pcap_packet_record(tmp_path) -> None:
    path = tmp_path / "truncated-record.pcap"
    wrpcap(str(path), sample_packet())
    path.write_bytes(path.read_bytes()[:-1])

    with pytest.raises(CaptureValidationError):
        inspect_capture(path)


def test_rejects_record_length_larger_than_remaining_file_without_reading_it(tmp_path) -> None:
    path = tmp_path / "forged-length.pcap"
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFFFFFF, 1)
    packet_header = struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    path.write_bytes(global_header + packet_header)

    with pytest.raises(CaptureValidationError):
        inspect_capture(path)


def test_rejects_corrupt_pcapng_block_trailer(tmp_path) -> None:
    path = tmp_path / "corrupt.pcapng"
    wrpcapng(str(path), sample_packet())
    contents = bytearray(path.read_bytes())
    contents[-1] ^= 0x01
    path.write_bytes(contents)

    with pytest.raises(CaptureValidationError):
        inspect_capture(path)


def test_rejects_unsupported_pcap_version(tmp_path) -> None:
    path = tmp_path / "future-version.pcap"
    writer = PcapWriter(str(path), endianness="<")
    writer.write(sample_packet())
    writer.close()
    contents = bytearray(path.read_bytes())
    contents[4:8] = struct.pack("<HH", 3, 0)
    path.write_bytes(contents)

    with pytest.raises(UnsupportedCaptureError):
        inspect_capture(path)
