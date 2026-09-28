#!/usr/bin/env python3
"""Submit a deterministic reference sample to a local MCRIT server, wait for it and label it."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _wait_for_processed_sample(client, sha256: str, timeout: float):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            sample = client.getSampleBySha256(sha256)
            if sample is not None:
                functions = client.getFunctionsBySampleId(sample.sample_id) or []
                if functions:
                    return sample, functions
        except Exception as exc:  # pragma: no cover - exercised by the live service
            last_error = exc
        time.sleep(2)

    message = f"Timed out waiting for MCRIT to process {sha256}"
    if last_error is not None:
        message += f": {last_error}"
    raise TimeoutError(message)


def _label_reference_functions(client, sample_path: Path):
    """Give every reference function a label, so label fetch and import have something to find.

    A sample submitted as a binary gets no labels. Submitting its SMDA report again makes MCRIT
    add the report's function names as labels, so unnamed functions are named after their offset.
    """
    from smda.Disassembler import Disassembler

    report = Disassembler().disassembleFile(str(sample_path))
    for function in report.getFunctions():
        if not function.function_name:
            function.function_name = "reference_%x" % function.offset
    if client.addReport(report) is None:
        raise RuntimeError("MCRIT did not accept the labelled reference report")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--family", default="mcrit-plugin-ci")
    parser.add_argument("--version", default="fixture-reference")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()

    from mcrit_plugin.core.minimcrit.client.McritClient import McritClient

    sample_path = args.sample.resolve()
    sample_bytes = sample_path.read_bytes()
    sha256 = hashlib.sha256(sample_bytes).hexdigest()
    client = McritClient(mcrit_server=args.server.rstrip("/"))
    client.setTimeout(10)

    version = client.getVersion()
    if not version:
        raise RuntimeError(f"MCRIT server did not return a version: {args.server}")

    client.addBinarySample(
        sample_bytes,
        filename=sample_path.name,
        family=args.family,
        version=args.version,
        bitness=64,
    )
    sample, functions = _wait_for_processed_sample(client, sha256, args.timeout)
    _label_reference_functions(client, sample_path)

    print(
        json.dumps(
            {
                "server": args.server,
                "version": version,
                "sha256": sha256,
                "sample_id": sample.sample_id,
                "function_count": len(functions),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
