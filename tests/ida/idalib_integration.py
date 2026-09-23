#!/usr/bin/env python3
"""Live MCRIT integration test executed through IDALib, without Qt."""

# ruff: noqa: I001

from __future__ import annotations

# IDALib requires this to be the first import. Keep all other imports below it.
import idapro

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path


_FUNCTION_SCOPE_QUERIES = 4


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def _is_live():
    return os.environ.get("MCRIT_IDA_INTEGRATION_LIVE", "1") == "1"


def _write_report_artifact(report):
    value = os.environ.get("MCRIT_IDA_INTEGRATION_ARTIFACT_DIR")
    if not value:
        return
    artifact_dir = Path(value).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "idalib-smda.json").write_text(
        json.dumps(report.toDict(), indent=1, sort_keys=True), encoding="utf-8"
    )


def _wait_for_functions(client, sample_id):
    deadline = time.monotonic() + int(os.environ.get("MCRIT_IDA_INTEGRATION_TIMEOUT", "30"))
    while time.monotonic() < deadline:
        functions = client.getFunctionsBySampleId(sample_id) or []
        if functions:
            return functions
        time.sleep(2)
    raise TimeoutError(f"MCRIT did not process sample {sample_id} before the timeout")


def _matches_sample(matches, sample_id):
    for sample_match in matches.get("samples", []) or []:
        if isinstance(sample_match, dict) and sample_match.get("sample_id") == sample_id:
            return True
    function_summaries = matches.get("functions", {}) or {}
    if isinstance(function_summaries, dict):
        function_summaries = function_summaries.values()
    return any(
        len(match_tuple) > 1 and match_tuple[1] == sample_id
        for summary in function_summaries
        for match_tuple in summary.get("matches", []) or []
    )


def _load_plugin(plugin_root):
    if str(plugin_root) not in sys.path:
        sys.path.insert(0, str(plugin_root))
    qt_modules_before = {name for name in sys.modules if name.startswith(("PySide", "PyQt"))}
    import ida_mcrit

    _assert(
        qt_modules_before == {name for name in sys.modules if name.startswith(("PySide", "PyQt"))},
        "loading the plugin entry point imported a Qt binding under IDALib",
    )
    plugin = ida_mcrit.PLUGIN_ENTRY()
    _assert(plugin.wanted_name == "MCRIT4IDA", "unexpected plugin name")
    plugmod = plugin.init()
    _assert(plugmod is not None, "plugin init returned no plugmod")
    _assert(ida_mcrit.show_mcrit_form() is None, "GUI form unexpectedly opened under IDALib")


def _exercise_function_scope(context, interface, report):
    """Query several functions the way the Function Scope tab does.

    Guards the SMDA >= 4.8 regression fixed in 1.1.10: `SmdaReport.getFunctions()`
    caches its result, so reusing one outline report and only swapping its `xcfg`
    made every query after the first re-submit the first function. The failure is
    silent - the second query short-circuits on the first function's cached offset
    and never reaches the server at all - so assert on which offset was submitted
    rather than on how many matches came back.
    """
    from mcrit_plugin.ui_qt.McritSession import McritSession

    get_outline = McritSession.getLocalSmdaReportOutline

    eligible = [
        function
        for function in sorted(report.getFunctions(), key=lambda f: f.offset)
        if function.num_instructions >= 10
    ]
    _assert(len(eligible) >= 2, "need at least two functions with >=10 instructions")
    targets = eligible[:_FUNCTION_SCOPE_QUERIES]

    submitted = []
    original_query = interface.mcrit_client.getMatchesForSmdaFunction

    def recording_query(smda_report, *args, **kwargs):
        submitted.append([function.offset for function in smda_report.getFunctions()])
        return original_query(smda_report, *args, **kwargs)

    interface.mcrit_client.getMatchesForSmdaFunction = recording_query
    try:
        for function in targets:
            outline = get_outline(context)
            _assert(outline is not None, "outline report was not built")
            _assert(
                not outline.xcfg,
                "outline report still carries a previous query's functions; "
                "getLocalSmdaReportOutline returned a reused object rather than a fresh one",
            )
            outline.xcfg = {function.offset: function}
            before = len(submitted)
            if function.offset not in context.function_matches:
                interface.querySmdaFunctionMatches(outline)
            sent = submitted[before:]
            _assert(
                sent and sent[0] == [function.offset],
                f"Function Scope query for {function.offset:#x} submitted {sent} instead",
            )
    finally:
        interface.mcrit_client.getMatchesForSmdaFunction = original_query

    _assert(
        len(submitted) == len(targets),
        f"expected {len(targets)} function queries, recorded {len(submitted)}",
    )


def _exercise_live_mcrit():
    from mcrit_plugin.ida.config import config
    from mcrit_plugin.core.HeadlessMcritContext import HeadlessMcritContext
    from mcrit_plugin.ida.IdaBackend import IdaBackend

    context = HeadlessMcritContext(config, IdaBackend())
    interface = context.mcrit_interface
    client = interface.mcrit_client
    interface.checkConnection(async_=False)
    _assert(
        context.local_widget.server and context.local_widget.server[1], "MCRIT connection failed"
    )

    report = interface.convertToSmda()
    _assert(
        report is not None and list(report.getFunctions()),
        "IDALib conversion produced no functions",
    )
    report.family = "mcrit-plugin-ci"
    report.version = "idalib-query"
    context.local_smda_report = report
    _write_report_artifact(report)

    interface.uploadReport(report)
    _assert(context.remote_sample_id is not None, "MCRIT upload returned no sample id")
    _wait_for_functions(client, context.remote_sample_id)
    interface.querySampleSha256(report.sha256)
    _assert(context.remote_sample_entry is not None, "MCRIT SHA256 lookup returned no sample")
    interface.queryAllFamilyEntries()
    interface.queryAllSampleEntries()
    interface.queryFunctionEntriesBySampleId(context.remote_sample_id)

    job_id = interface.requestMatchingJob(context.remote_sample_id)
    _assert(job_id, "MCRIT matching request returned no job id")
    result = client.awaitResult(job_id, sleep_time=1)
    _assert(isinstance(result, dict), "MCRIT matching result was not a JSON object")
    matches = result.get("matches", {})
    _assert(matches.get("samples") or matches.get("functions"), "MCRIT returned no matches")
    reference_sha256 = os.environ.get("MCRIT_IDA_INTEGRATION_REFERENCE_SHA256")
    if reference_sha256:
        reference = client.getSampleBySha256(reference_sha256)
        _assert(reference is not None, "MCRIT reference sample was not retrievable")
        _assert(
            _matches_sample(matches, reference.sample_id),
            "MCRIT did not return the deterministic reference match",
        )
    interface.getMatchingJobById(job_id)
    _assert(
        context.matching_report is not None, "MCRIT result retrieval did not decode MatchingResult"
    )

    _exercise_function_scope(context, interface, report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    plugin_root = Path(os.environ["MCRIT_IDA_PLUGIN_ROOT"]).resolve()
    database_open = False
    try:
        idapro.open_database(str(args.input.resolve()), True)
        database_open = True
        _load_plugin(plugin_root)
        if _is_live():
            _exercise_live_mcrit()
        print("MCRIT_IDALIB_INTEGRATION_OK")
        return 0
    except Exception as exc:
        print(f"MCRIT_IDALIB_INTEGRATION_FAILURE: {exc}")
        traceback.print_exc()
        return 1
    finally:
        if database_open:
            try:
                idapro.close_database(False)
            except TypeError:
                idapro.close_database()


if __name__ == "__main__":
    raise SystemExit(main())
