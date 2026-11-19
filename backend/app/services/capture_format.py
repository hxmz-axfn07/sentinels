import struct
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO


class CaptureFormat(StrEnum):
    PCAP = "pcap"
    PCAPNG = "pcapng"

    @property
    def suffix(self) -> str:
        return f".{self.value}"


class CaptureValidationError(ValueError):
    code = "malformed_capture"
    message = "The capture file is malformed."


class EmptyCaptureError(CaptureValidationError):
    code = "empty_capture"
    message = "The capture file contains no packets."


class UnsupportedCaptureError(CaptureValidationError):
    code = "unsupported_capture"
    message = "The file is not a supported PCAP or PCAPNG capture."


class CapturePacketLimitError(CaptureValidationError):
    code = "packet_limit_exceeded"
    message = "The capture exceeds the configured packet-count limit."


def inspect_capture(path: Path, max_packets: int | None = None) -> CaptureFormat:
    if path.stat().st_size == 0:
        raise EmptyCaptureError
    with path.open("rb") as capture:
        magic = capture.read(4)
        capture.seek(0)
        if magic in _PCAP_MAGICS:
            _validate_pcap(capture, magic, max_packets)
            return CaptureFormat.PCAP
        if magic == b"\x0a\x0d\x0d\x0a":
            _validate_pcapng(capture, max_packets)
            return CaptureFormat.PCAPNG
    raise UnsupportedCaptureError


_PCAP_MAGICS: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # big endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big endian, nanoseconds
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER = {
    b"\x4d\x3c\x2b\x1a": "<",
    b"\x1a\x2b\x3c\x4d": ">",
}


def _validate_pcap(capture: BinaryIO, magic: bytes, max_packets: int | None) -> None:
    endian, timestamp_resolution = _PCAP_MAGICS[magic]
    file_size = capture.seek(0, 2)
    capture.seek(0)
    global_header = capture.read(24)
    if len(global_header) != 24:
        raise CaptureValidationError
    major, minor = struct.unpack(f"{endian}HH", global_header[4:8])
    snap_length = struct.unpack(f"{endian}I", global_header[16:20])[0]
    if (major, minor) != (2, 4) or snap_length == 0:
        raise UnsupportedCaptureError

    packet_count = 0
    while packet_header := capture.read(16):
        if len(packet_header) != 16:
            raise CaptureValidationError
        _, timestamp_fraction, captured_length, original_length = struct.unpack(
            f"{endian}IIII", packet_header
        )
        if (
            timestamp_fraction >= timestamp_resolution
            or captured_length > snap_length
            or captured_length > original_length
        ):
            raise CaptureValidationError
        if captured_length > file_size - capture.tell():
            raise CaptureValidationError
        capture.seek(captured_length, 1)
        packet_count += 1
        if max_packets is not None and packet_count > max_packets:
            raise CapturePacketLimitError
    if packet_count == 0:
        raise EmptyCaptureError


def _read_exact(capture: BinaryIO, size: int) -> bytes:
    block = capture.read(size)
    if len(block) != size:
        raise CaptureValidationError
    return block


def _padded(length: int) -> int:
    return (length + 3) & ~3


def _validate_pcapng(capture: BinaryIO, max_packets: int | None) -> None:
    file_size = capture.seek(0, 2)
    offset = 0
    endian: str | None = None
    interfaces: list[int] = []
    packet_blocks = 0

    while offset < file_size:
        capture.seek(offset)
        block_type = _read_exact(capture, 4)
        length_bytes = _read_exact(capture, 4)

        if block_type == _PCAPNG_SHB:
            byte_order = _read_exact(capture, 4)
            endian = _PCAPNG_BYTE_ORDER.get(byte_order)
            if endian is None:
                raise UnsupportedCaptureError
            block_length = struct.unpack(f"{endian}I", length_bytes)[0]
            if block_length < 28 or block_length % 4:
                raise CaptureValidationError
            major, minor = struct.unpack(f"{endian}HH", _read_exact(capture, 4))
            if major != 1 or minor > 0:
                raise UnsupportedCaptureError
            interfaces = []
        else:
            if endian is None:
                raise CaptureValidationError
            block_length = struct.unpack(f"{endian}I", length_bytes)[0]
            if block_length < 12 or block_length % 4:
                raise CaptureValidationError

        if offset + block_length > file_size:
            raise CaptureValidationError
        capture.seek(offset + block_length - 4)
        trailing_length = struct.unpack(f"{endian}I", _read_exact(capture, 4))[0]
        if trailing_length != block_length:
            raise CaptureValidationError

        block_kind = struct.unpack(f"{endian}I", block_type)[0]
        if block_type == _PCAPNG_SHB:
            pass
        elif block_kind == 1:  # Interface Description Block
            if block_length < 20:
                raise CaptureValidationError
            capture.seek(offset + 12)
            snap_length = struct.unpack(f"{endian}I", _read_exact(capture, 4))[0]
            interfaces.append(snap_length)
        elif block_kind == 6:  # Enhanced Packet Block
            if block_length < 32:
                raise CaptureValidationError
            capture.seek(offset + 8)
            (interface_id,) = struct.unpack(f"{endian}I", _read_exact(capture, 4))
            capture.seek(offset + 20)
            captured_length, original_length = struct.unpack(f"{endian}II", _read_exact(capture, 8))
            if interface_id >= len(interfaces) or captured_length > original_length:
                raise CaptureValidationError
            snap_length = interfaces[interface_id]
            if snap_length and captured_length > snap_length:
                raise CaptureValidationError
            if block_length < 32 + _padded(captured_length):
                raise CaptureValidationError
            packet_blocks += 1
            _validate_packet_count(packet_blocks, max_packets)
        elif block_kind == 3:  # Simple Packet Block
            if block_length < 16 or not interfaces:
                raise CaptureValidationError
            capture.seek(offset + 8)
            (original_length,) = struct.unpack(f"{endian}I", _read_exact(capture, 4))
            snap_length = interfaces[0]
            captured_length = min(original_length, snap_length) if snap_length else original_length
            if block_length != 16 + _padded(captured_length):
                raise CaptureValidationError
            packet_blocks += 1
            _validate_packet_count(packet_blocks, max_packets)
        elif block_kind == 2:  # Obsolete Packet Block
            if block_length < 32:
                raise CaptureValidationError
            capture.seek(offset + 8)
            (interface_id,) = struct.unpack(f"{endian}H", _read_exact(capture, 2))
            capture.seek(offset + 20)
            captured_length, original_length = struct.unpack(f"{endian}II", _read_exact(capture, 8))
            if interface_id >= len(interfaces) or captured_length > original_length:
                raise CaptureValidationError
            snap_length = interfaces[interface_id]
            if snap_length and captured_length > snap_length:
                raise CaptureValidationError
            if block_length < 32 + _padded(captured_length):
                raise CaptureValidationError
            packet_blocks += 1
            _validate_packet_count(packet_blocks, max_packets)

        offset += block_length

    if endian is None:
        raise CaptureValidationError
    if packet_blocks == 0:
        raise EmptyCaptureError


def _validate_packet_count(packet_count: int, max_packets: int | None) -> None:
    if max_packets is not None and packet_count > max_packets:
        raise CapturePacketLimitError
