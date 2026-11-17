from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

DATASET_VERSION = "sentinel-synthetic-flow-v1"
GENERATION_SEED = 1101
POSITIVE_LABEL = "suspicious"
NEGATIVE_LABEL = "benign"


@dataclass(frozen=True, slots=True)
class EvaluationSample:
    sample_id: str
    split: Literal["train", "test"]
    pattern: str
    ground_truth: Literal["benign", "suspicious"]
    expected_rule_ids: tuple[str, ...]
    ordinal: int


def _sample(
    sample_id: str,
    split: Literal["train", "test"],
    pattern: str,
    *,
    suspicious: bool = False,
    expected_rule_ids: tuple[str, ...] = (),
    ordinal: int,
) -> EvaluationSample:
    return EvaluationSample(
        sample_id=sample_id,
        split=split,
        pattern=pattern,
        ground_truth=POSITIVE_LABEL if suspicious else NEGATIVE_LABEL,
        expected_rule_ids=expected_rule_ids,
        ordinal=ordinal,
    )


def _build_samples() -> tuple[EvaluationSample, ...]:
    samples: list[EvaluationSample] = []
    ordinal = 1
    for split, groups in (
        (
            "train",
            (
                ("normal_tcp", 8, False, ()),
                ("normal_udp", 4, False, ()),
                ("normal_icmp", 2, False, ()),
                ("incomplete_metadata", 2, False, ()),
            ),
        ),
        (
            "test",
            (
                ("normal_tcp", 4, False, ()),
                ("normal_udp", 3, False, ()),
                ("normal_icmp", 2, False, ()),
                ("incomplete_metadata", 2, False, ()),
                ("benign_port_burst", 4, False, ()),
                ("port_scan_pattern", 4, True, ("PORT_SCAN",)),
                ("syn_heavy_pattern", 4, True, ("SYN_FLOOD_LIKE",)),
                (
                    "repeated_syn_tuples",
                    4,
                    True,
                    ("PORT_SCAN", "EXCESSIVE_CONNECTION_ATTEMPTS"),
                ),
            ),
        ),
    ):
        for pattern, count, suspicious, expected in groups:
            for index in range(1, count + 1):
                samples.append(
                    _sample(
                        f"{split}-{pattern}-{index:02d}",
                        split,  # type: ignore[arg-type]
                        pattern,
                        suspicious=suspicious,
                        expected_rule_ids=expected,
                        ordinal=ordinal,
                    )
                )
                ordinal += 1
    return tuple(samples)


SAMPLES = _build_samples()
TRAINING_SAMPLES = tuple(sample for sample in SAMPLES if sample.split == "train")
TEST_SAMPLES = tuple(sample for sample in SAMPLES if sample.split == "test")


def dataset_manifest() -> dict[str, object]:
    """Describe every generated sample; labels come only from its recipe."""
    return {
        "dataset_version": DATASET_VERSION,
        "generation_seed": GENERATION_SEED,
        "generator": "Scapy deterministic packet recipes",
        "ground_truth_source": "traffic recipe parameters, independent of engine output",
        "evaluation_unit": "one PCAP capture; test labels apply to the capture as a whole",
        "training_policy": "benign training captures only; test captures are disjoint",
        "public_dataset": False,
        "synthetic": True,
        "limitations": [
            "Synthetic traffic is not representative of real-world traffic distributions.",
            "Capture-level labels do not identify which individual flow is suspicious.",
            "The benign four-port burst is deliberately close to the default port-scan threshold.",
            "Repeated SYN tuples use distinct destination ports and therefore also meet "
            "the port-scan recipe.",
        ],
        "samples": [
            {
                "sample_id": sample.sample_id,
                "split": sample.split,
                "traffic_pattern": sample.pattern,
                "ground_truth": sample.ground_truth,
                "expected_rule_ids": list(sample.expected_rule_ids),
                "generation_parameters": _parameters_for(sample),
            }
            for sample in SAMPLES
        ],
    }


def write_capture(sample: EvaluationSample, path: Path, *, seed: int = GENERATION_SEED) -> int:
    from scapy.utils import wrpcap

    packets = _packets_for(sample, seed)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return len(packets)


def _parameters_for(sample: EvaluationSample) -> dict[str, Any]:
    return {
        "generator_seed": GENERATION_SEED,
        "recipe_ordinal": sample.ordinal,
        "packet_recipe": sample.pattern,
        "expected_rule_ids": list(sample.expected_rule_ids),  # type: ignore[dict-item]
        "label_rationale": (
            "The generator intentionally emits the named suspicious indicator pattern."
            if sample.ground_truth == POSITIVE_LABEL
            else (
                "The generator emits benign protocol activity; near-threshold cases remain "
                "benign by recipe."
            )
        ),
    }


def _packets_for(sample: EvaluationSample, seed: int) -> list:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    rng = random.Random(seed + sample.ordinal * 997)
    address_index = 10 + sample.ordinal % 200
    source_ip = f"192.0.2.{address_index}"
    destination_ip = f"198.51.100.{address_index}"
    timestamp = 1_700_000_000 + sample.ordinal * 100
    packets = []

    def add(packet) -> None:
        packet.time = timestamp + len(packets) * 0.002
        packets.append(packet)

    if sample.pattern in {"normal_tcp", "benign_port_burst"}:
        ports = (80, 443, 8080, 8443) if sample.pattern == "normal_tcp" else (80, 443, 8080, 8443)
        for index, destination_port in enumerate(ports):
            source_port = 40000 + sample.ordinal + index
            sequence = rng.randrange(1, 2**31)
            add(
                IP(src=source_ip, dst=destination_ip)
                / TCP(sport=source_port, dport=destination_port, flags="S", seq=sequence)
            )
            add(
                IP(src=destination_ip, dst=source_ip)
                / TCP(
                    sport=destination_port,
                    dport=source_port,
                    flags="SA",
                    seq=sequence + 100,
                )
            )
            payload_size = 16 + rng.randrange(48)
            add(
                IP(src=source_ip, dst=destination_ip)
                / TCP(
                    sport=source_port,
                    dport=destination_port,
                    flags="PA",
                    seq=sequence + 1,
                )
                / Raw(load=b"N" * payload_size)
            )
    elif sample.pattern == "normal_udp":
        for index, destination_port in enumerate((53, 123, 443, 5353)):
            source_port = 50000 + sample.ordinal + index
            payload_size = 12 + rng.randrange(40)
            add(
                IP(src=source_ip, dst=destination_ip)
                / UDP(sport=source_port, dport=destination_port)
                / Raw(load=b"U" * payload_size)
            )
            add(
                IP(src=destination_ip, dst=source_ip)
                / UDP(sport=destination_port, dport=source_port)
                / Raw(load=b"R" * (8 + payload_size // 2))
            )
    elif sample.pattern == "normal_icmp":
        for index in range(3):
            add(IP(src=source_ip, dst=destination_ip) / ICMP(type=8, id=sample.ordinal + index))
            add(IP(src=destination_ip, dst=source_ip) / ICMP(type=0, id=sample.ordinal + index))
    elif sample.pattern == "incomplete_metadata":
        add(Ether() / Raw(load=b"SENTINEL synthetic non-IP frame"))
    elif sample.pattern == "port_scan_pattern":
        for index in range(7):
            add(
                IP(src=source_ip, dst=destination_ip)
                / TCP(
                    sport=52000 + index,
                    dport=20 + index,
                    flags="S",
                    seq=sample.ordinal + index,
                )
            )
    elif sample.pattern == "syn_heavy_pattern":
        for index in range(24):
            add(
                IP(src=source_ip, dst=destination_ip)
                / TCP(
                    sport=56000,
                    dport=443,
                    flags="S",
                    seq=sample.ordinal * 100 + index,
                )
            )
    elif sample.pattern == "repeated_syn_tuples":
        for index in range(12):
            add(
                IP(src=source_ip, dst=destination_ip)
                / TCP(
                    sport=57000 + index,
                    dport=1000 + index,
                    flags="S",
                    seq=sample.ordinal * 100 + index,
                )
            )
    else:
        raise ValueError(f"Unknown synthetic traffic pattern: {sample.pattern}")
    return packets
