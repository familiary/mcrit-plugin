#!/usr/bin/env python3
"""Run the shared MCRIT workflow against a live MCRIT server without any disassembler.

Uses HeadlessBackend (SMDA disassembles the input itself), so it needs no IDA or Binary Ninja
licence and can run on every pull request: connection check, SMDA conversion, upload, sample
lookup, matching job and result decoding, and label import through the backend mutation scope.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))


def _check(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS {message}")


def _wait(predicate, message, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            print(f"PASS {message}")
            return result
        time.sleep(1)
    raise TimeoutError(f"timed out: {message}")


def _matches_sample(matches, sample_id):
    samples = matches.get("samples", []) or []
    return any(isinstance(match, dict) and match.get("sample_id") == sample_id for match in samples)


def run(input_path: Path, server: str, reference_sha256: str | None, timeout: int) -> None:
    from mcrit_plugin.core.config import McritConfig
    from mcrit_plugin.core.HeadlessMcritContext import HeadlessMcritContext
    from mcrit_plugin.headless.HeadlessBackend import HeadlessBackend

    def get_setting(key):
        if key == "mcrit_server":
            return server
        raise KeyError(key)

    backend = HeadlessBackend(input_path)
    context = HeadlessMcritContext(McritConfig("headless", get_setting), backend)
    interface = context.mcrit_interface
    client = interface.mcrit_client

    interface.checkConnection(async_=False)
    _check(context.local_widget.server and context.local_widget.server[1], "MCRIT server reachable")

    report = interface.convertToSmda()
    _check(report is not None and list(report.getFunctions()), "SMDA conversion produced functions")
    report.family = "mcrit-plugin-ci"
    report.version = "headless-query"
    context.local_smda_report = report

    interface.uploadReport(report)
    _check(context.remote_sample_id is not None, "upload returned a sample id")
    _wait(
        lambda: client.getFunctionsBySampleId(context.remote_sample_id),
        "server indexed the uploaded functions",
        timeout,
    )
    interface.querySampleSha256(report.sha256)
    _check(context.remote_sample_entry is not None, "uploaded sample found by sha256")
    interface.queryAllFamilyEntries()
    interface.queryAllSampleEntries()
    interface.queryFunctionEntriesBySampleId(context.remote_sample_id)

    job_id = interface.requestMatchingJob(context.remote_sample_id)
    _check(job_id, "matching job requested")
    result = _wait(lambda: client.getResultForJob(job_id), "matching job finished", timeout)
    matches = result.get("matches", {})
    _check(matches.get("samples") or matches.get("functions"), "MCRIT returned matches")
    if reference_sha256:
        reference = client.getSampleBySha256(reference_sha256)
        _check(
            reference is not None and _matches_sample(matches, reference.sample_id),
            "query sample matches the reference sample",
        )
    interface.getMatchingJobById(job_id)
    _check(context.matching_report is not None, "MatchingResult decoded")

    functions = list(report.getFunctions())
    with backend.mutation("Import MCRIT labels"):
        backend.set_function_name(functions[0].offset, "mcrit_headless_label")
    _check(
        backend.get_function_symbols().get(functions[0].offset) == "mcrit_headless_label",
        "label applied through the backend mutation scope",
    )
    _check(
        interface.convertToSmda().getFunction(functions[0].offset).function_name
        == "mcrit_headless_label",
        "re-exported report carries the applied label",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mcrit-server", default="http://127.0.0.1:8000/")
    parser.add_argument("--reference-sha256")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    run(args.input.resolve(), args.mcrit_server, args.reference_sha256, args.timeout)
    print("MCRIT_HEADLESS_INTEGRATION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
