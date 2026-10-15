"""With use_smda_for_analysis, Convert compares SMDA's function set with the disassembler's."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from mcrit_plugin.ui_qt.widgets.MainWidget import MainWidget  # noqa: E402


def _print_difference(backend_offsets, smda_offsets):
    widget = MainWidget.__new__(MainWidget)
    widget.cc = SimpleNamespace(
        backend=SimpleNamespace(name="IDA", get_function_offsets=lambda: set(backend_offsets))
    )
    report = SimpleNamespace(
        getFunctions=lambda: [SimpleNamespace(offset=offset) for offset in smda_offsets]
    )
    widget._printFunctionSetDifference(report)


def test_matching_function_sets_are_reported_as_such(capsys):
    _print_difference({0x10, 0x20}, [0x20, 0x10])

    assert "matches IDA converted report function set" in capsys.readouterr().out


def test_differing_function_sets_list_the_missing_functions(capsys):
    _print_difference({0x10, 0x20, 0x30}, [0x10, 0x40])

    out = capsys.readouterr().out
    assert "SMDA disassembly report function set (2) differs from IDA" in out
    assert "Functions in IDA but not in SMDA report (2): 0x20, 0x30" in out
    assert "Functions in SMDA but not in IDA report (1): 0x40" in out
    assert "Using SMDA converted report." in out
