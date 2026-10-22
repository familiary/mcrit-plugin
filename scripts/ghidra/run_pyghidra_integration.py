#!/usr/bin/env python3
"""Run the shared MCRIT workflow through GhidraBackend in headless PyGhidra.

Imports and analyzes the input in a throwaway Ghidra project, exports it to an SMDA report from
Ghidra's own analysis, compares that report with SMDA's disassembly of the same file, and then
drives connection check, upload, sample lookup, matching and label import through the backend's
mutation scope. Needs Ghidra 12.0 or newer (GHIDRA_INSTALL_DIR) and a Python with pyghidra, smda
and requests; no licence is involved, so it can run in CI.

--offline stops after the export and the comparison.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
# the export must agree with SMDA's disassembly on most functions; boundaries legitimately differ
# where Ghidra splits off tail-jump stubs or finds functions SMDA misses
MIN_PICHASH_AGREEMENT = 0.75


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


def _pichash_agreement(report, input_path):
    """Share of the functions both reports have whose PicHashes agree. Ghidra and SMDA may map
    a position independent ELF at different bases, so functions are paired relative to the base."""
    from smda.Disassembler import Disassembler

    native = Disassembler().disassembleFile(str(input_path))
    ours = {f.offset - report.base_addr: f.pic_hash for f in report.getFunctions()}
    theirs = {f.offset - native.base_addr: f.pic_hash for f in native.getFunctions()}
    shared = set(ours) & set(theirs)
    agreeing = sum(1 for offset in shared if ours[offset] == theirs[offset])
    print(
        f"[compare] ghidra {len(ours)} functions, smda {len(theirs)}, shared {len(shared)}, "
        f"identical PicHash {agreeing}"
    )
    return agreeing / len(shared) if shared else 0.0


def _run_workflow(program, input_path, server, reference_sha256, timeout, offline):
    from mcrit_plugin.core.config import PLUGIN_ROOT, McritConfig
    from mcrit_plugin.core.HeadlessMcritContext import HeadlessMcritContext
    from mcrit_plugin.ghidra.GhidraBackend import GhidraBackend

    def get_setting(key):
        if key == "mcrit_server":
            return server
        raise KeyError(key)

    override_path = Path(PLUGIN_ROOT) / "config_override.json"
    if override_path.exists():
        raise RuntimeError(f"{override_path} would override the test settings; move it aside")

    backend = GhidraBackend(program)
    import hashlib

    data = Path(input_path).read_bytes()
    _check(
        backend.get_input_sha256() == hashlib.sha256(data).hexdigest()
        and backend.get_input_md5() == hashlib.md5(data).hexdigest()
        and backend.get_input_size() == len(data),
        "input hashes and size match the file",
    )
    context = HeadlessMcritContext(McritConfig("pyghidra", get_setting), backend)
    interface = context.mcrit_interface

    started = time.monotonic()
    report = interface.convertToSmda()
    print(f"[export] {report.num_functions} functions in {time.monotonic() - started:.2f}s")
    _check(report is not None and list(report.getFunctions()), "Ghidra export produced functions")
    _check(
        backend.get_function_offsets() == {f.offset for f in report.getFunctions()},
        "get_function_offsets matches the exported functions",
    )
    agreement = _pichash_agreement(report, input_path)
    _check(
        agreement >= MIN_PICHASH_AGREEMENT,
        f"PicHash agreement with SMDA's disassembly ({agreement:.0%})",
    )
    smda_report = interface.convertToSmdaUsingSmda()
    _check(list(smda_report.getFunctions()), "SMDA disassembly of Ghidra's memory image")

    # a name Ghidra rejects is skipped, and the renames before it in the same mutation stay
    first, second = [
        f.offset for f in report.getFunctions() if backend.has_default_function_name(f.offset)
    ][:2]
    with backend.mutation("Import MCRIT labels"):
        renamed = backend.set_function_name(first, "mcrit_before_rejected")
        rejected = not backend.set_function_name(second, "operator new")
    _check(
        renamed and rejected and backend.get_function_name(first) == "mcrit_before_rejected",
        "a rejected label is skipped without rolling back the import",
    )

    from java.awt import Color

    from mcrit_plugin.ghidra.RemoteCfgGraph import EDGE_COLORS, EDGE_TAKEN, build_graph
    from mcrit_plugin.ghidra.ui.components import Spinner

    _graph, options = build_graph("check", next(iter(report.getFunctions())), {})
    _check(
        options.getDefaultVertexColor().getRGB() == Color.decode("#D3D3D3").getRGB()
        and options.getEdgeColor(EDGE_TAKEN).getRGB()
        == Color.decode(EDGE_COLORS[EDGE_TAKEN]).getRGB(),
        "remote CFG default vertex and edge colors are the hex values, not theme ids",
    )
    _check(Spinner(5, 100, 2).value() == 5, "an out-of-range spinner value is clamped")
    if offline:
        return

    client = interface.mcrit_client
    interface.checkConnection(async_=False)
    _check(context.local_widget.server and context.local_widget.server[1], "MCRIT server reachable")
    report.sha256 = backend.get_input_sha256()
    report.filename = backend.get_input_filename()
    report.buffer_size = backend.get_input_size()
    report.family = "mcrit-plugin-ci"
    report.version = "pyghidra-query"
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
    _check(interface.ensureRemoteInformation(), "family and sample lists downloaded")

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

    # a function query, as the Function Scope tab sends it
    queried = next(f for f in report.getFunctions() if f.num_instructions > 10)
    outline = report.__class__.fromDict(dict(report.toDict(), xcfg={}))
    outline.xcfg = {queried.offset: queried}
    _check(interface.querySmdaFunctionMatches(outline) is not None, "function query answered")

    unnamed = next(
        f.offset for f in report.getFunctions() if backend.has_default_function_name(f.offset)
    )
    with backend.mutation("Import MCRIT labels"):
        backend.set_function_name(unnamed, "mcrit_pyghidra_label")
    _check(
        backend.get_function_name(unnamed) == "mcrit_pyghidra_label"
        and not backend.has_default_function_name(unnamed),
        "label applied through the backend mutation scope",
    )
    _check(
        interface.convertToSmda().getFunction(unnamed).function_name == "mcrit_pyghidra_label",
        "re-exported report carries the applied label",
    )


def run(input_path, server, reference_sha256, timeout, offline, ghidra_dir):
    import pyghidra

    pyghidra.start(install_dir=Path(ghidra_dir) if ghidra_dir else None)
    # PyGhidra drops the working directory from sys.path, which is this checkout when run from it
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    with tempfile.TemporaryDirectory(prefix="mcrit-pyghidra-") as project_dir:
        project = pyghidra.open_project(project_dir, "mcrit", create=True)
        try:
            loader = pyghidra.program_loader().project(project).source(str(input_path))
            with loader.load() as load_results:
                load_results.save(pyghidra.task_monitor())
                domain_path = load_results.getPrimaryDomainObject().getDomainFile().getPathname()
            with pyghidra.program_context(project, domain_path) as program:
                pyghidra.analyze(program)
                _run_workflow(program, input_path, server, reference_sha256, timeout, offline)
        finally:
            project.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mcrit-server", default="http://127.0.0.1:8000/")
    parser.add_argument("--reference-sha256")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--ghidra-dir", help="Ghidra installation; defaults to GHIDRA_INSTALL_DIR")
    parser.add_argument("--offline", action="store_true", help="stop after export and comparison")
    args = parser.parse_args()
    run(
        args.input.resolve(),
        args.mcrit_server,
        args.reference_sha256,
        args.timeout,
        args.offline,
        args.ghidra_dir,
    )
    print("MCRIT_PYGHIDRA_INTEGRATION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
