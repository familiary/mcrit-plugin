"""Ghidra exports only after auto-analysis finished, as Binary Ninja does, except on Swing's thread,
which analyzers may need."""

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
    on_edt = [False]
    swing = types.ModuleType("javax.swing")
    swing.SwingUtilities = types.SimpleNamespace(isEventDispatchThread=lambda: on_edt[0])
    exporter = types.ModuleType("mcrit_plugin.ghidra.GhidraExporter")
    exported = []
    exporter.exportProgram = lambda program: exported.append(list(analyzing)) or "report"
    # the test suite stubs smda, which the real export interface needs
    smda_interface = types.ModuleType("mcrit_plugin.ghidra.GhidraSmdaInterface")
    smda_interface.GhidraSmdaInterface = object
    smda_interface.function_display_name = smda_interface.is_default_function_name = None
    for name, module in {
        "mcrit_plugin.ghidra.GhidraSmdaInterface": smda_interface,
        "ghidra.app.plugin.core.analysis": analysis,
        "javax.swing": swing,
        "mcrit_plugin.ghidra.GhidraExporter": exporter,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.delitem(sys.modules, "mcrit_plugin.ghidra.GhidraBackend", raising=False)
    from mcrit_plugin.ghidra import GhidraBackend as module

    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    backend = module.GhidraBackend.__new__(module.GhidraBackend)
    backend.program = object()
    yield backend, analyzing, on_edt, exported
    # built on the stubs above; later tests must import their own
    sys.modules.pop("mcrit_plugin.ghidra.GhidraBackend", None)


def test_the_export_waits_until_analysis_is_done(ghidra_backend):
    backend, analyzing, _on_edt, exported = ghidra_backend
    analyzing.extend([True, True])

    assert backend.export_smda_report() == "report"
    assert exported == [[]]


def test_swing_s_thread_exports_without_waiting(ghidra_backend):
    backend, analyzing, on_edt, exported = ghidra_backend
    analyzing.extend([True, True])
    on_edt[0] = True

    assert backend.export_smda_report() == "report"
    assert exported == [[True, True]]
