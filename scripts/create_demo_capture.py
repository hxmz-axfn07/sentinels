"""Create one labelled synthetic port-probing capture for a live demonstration."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.evaluation.dataset import TEST_SAMPLES, write_capture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output path. Existing files are never overwritten.",
    )
    args = parser.parse_args()
    sample = next(
        sample
        for sample in TEST_SAMPLES
        if sample.sample_id == "test-port_scan_pattern-01"
    )
    if args.output is not None:
        destination = args.output.expanduser().resolve()
        if destination.exists():
            parser.error("output file already exists; choose another path")
    else:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="sentinel-demo-", suffix=".pcap"
        )
        os.close(descriptor)
        destination = Path(temporary_name)
    write_capture(sample, destination)
    print(f"Synthetic sample: {sample.sample_id} ({sample.ground_truth})")
    print(f"Capture path: {destination}")


if __name__ == "__main__":
    main()
