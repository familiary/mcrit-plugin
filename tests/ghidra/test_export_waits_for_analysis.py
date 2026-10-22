"""Background work, such as the export behind Convert, Upload and Export, starts once Ghidra's
auto-analysis is done, as on Binary Ninja, and stops waiting when the program closes."""

import sys
import types

import pytest


@pytest.fixture
def ghidra_backend(monkeypatch):
    def implements(*_args, **_kwargs):
        return lambda cls: cls

    monkeypatch.setitem(
        sys.modules, "jpype", types.SimpleNamespace(JImplements=implements, JOverride=lambda f: f)
    )
    analyzing = []
    manager = types.SimpleNamespace(isAnalyzing=lambda: analyzing.pop(0) if analyzing else False)
    analysis = types.ModuleType("ghidra.app.plugin.core.analysis")
    analysis.AutoAnalysisManager = types.SimpleNamespace(getAnalysisManager=lambda program: manager)
    # the test suite stubs smda, which the real export interface needs
    smda_interface = types.ModuleType("mcrit_plugin.ghidra.GhidraSmdaInterface")
    smda_interface.GhidraSmdaInterface = object
    smda_interface.function_display_name = smda_interface.is_default_function_name = None
    monkeypatch.setitem(sys.modules, "mcrit_plugin.ghidra.GhidraSmdaInterface", smda_interface)
    monkeypatch.setitem(sys.modules, "ghidra.app.plugin.core.analysis", analysis)
    for name in ("mcrit_plugin.ghidra.GhidraBackend", "mcrit_plugin.ghidra.swing"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    import mcrit_plugin.ghidra as package
    from mcrit_plugin.ghidra import GhidraBackend as module

    messages = []
    monitor = types.SimpleNamespace(setMessage=messages.append)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(module.swing, "launch_background_task", lambda title, run: run(monitor))
    backend = module.GhidraBackend.__new__(module.GhidraBackend)
    backend.program, backend.tool, backend.closed = object(), object(), False
    backend._on_ui_thread = lambda func: func()
    yield backend, analyzing, messages
    # built on the stubs above; later tests must import their own
    for name in ("mcrit_plugin.ghidra.GhidraBackend", "mcrit_plugin.ghidra.swing"):
        sys.modules.pop(name, None)
    for attribute in ("GhidraBackend", "swing"):
        package.__dict__.pop(attribute, None)


def test_background_work_waits_until_analysis_is_done(ghidra_backend):
    backend, analyzing, messages = ghidra_backend
    analyzing.extend([True, True, True])
    seen = []

    backend.run_background("MCRIT: exporting", lambda: list(analyzing), seen.append)

    assert seen == [[]]
    assert messages == ["MCRIT: exporting (waiting for analysis)", "MCRIT: exporting"]


def test_a_closed_program_stops_the_wait(ghidra_backend):
    backend, analyzing, _messages = ghidra_backend
    analyzing.extend([True, True, True])
    backend.closed = True
    seen = []

    backend.run_background("MCRIT: exporting", lambda: "work", seen.append)

    assert seen == ["work"]
