"""IdaBackend.run_background gives IDA the same error path Binary Ninja's background task has."""

import importlib
import sys
import types
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def backend(monkeypatch):
    kernwin = types.SimpleNamespace(
        show_wait_box=MagicMock(), hide_wait_box=MagicMock(), warning=MagicMock()
    )
    for name in ("ida_bytes", "ida_funcs", "ida_idaapi", "ida_nalt", "ida_undo", "idc"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)
    monkeypatch.setitem(sys.modules, "ida_hexrays", None)
    monkeypatch.delitem(sys.modules, "mcrit_plugin.ida.IdaBackend", raising=False)
    module = importlib.import_module("mcrit_plugin.ida.IdaBackend")
    instance = module.IdaBackend.__new__(module.IdaBackend)
    return instance, kernwin


def test_run_background_delivers_the_result_after_the_wait_box(backend):
    instance, kernwin = backend
    on_done = MagicMock()

    instance.run_background("Export", lambda: "report", on_done)

    kernwin.show_wait_box.assert_called_once_with("HIDECANCEL\nExport")
    kernwin.hide_wait_box.assert_called_once_with()
    on_done.assert_called_once_with("report")
    kernwin.warning.assert_not_called()


def test_run_background_reports_a_failure_instead_of_raising(backend):
    instance, kernwin = backend
    on_done = MagicMock()

    def work():
        raise RuntimeError("no code")

    instance.run_background("Export", work, on_done)

    kernwin.hide_wait_box.assert_called_once_with()
    kernwin.warning.assert_called_once_with("Export failed, see the Output window for details.")
    on_done.assert_not_called()
