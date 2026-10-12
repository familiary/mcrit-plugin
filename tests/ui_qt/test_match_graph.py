"""Opening a match's graph fetches the remote function in the background: a repeated double click
during the fetch opens no second graph, and the activity line says when the graph opened."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
import mcrit_plugin.ui_qt.widgets.FunctionMatchWidget as FunctionMatchWidgetModule  # noqa: E402
from mcrit_plugin.core.config import McritConfig  # noqa: E402
from mcrit_plugin.ui_qt.ClassCollection import ClassCollection  # noqa: E402


class _Backend:
    def __init__(self):
        self.pending = []
        self.graphs = 0

    def run_request(self, title, work, on_done):
        self.pending.append(lambda: on_done(work()))

    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        self.graphs += 1


class _Matcher:
    def __init__(self, *args):
        pass

    def getColoredMatches(self):
        return {"b": {}}


def test_a_repeated_double_click_opens_one_graph(monkeypatch):
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    monkeypatch.setattr(FunctionMatchWidgetModule, "FunctionCfgMatcher", _Matcher)
    backend = _Backend()
    activity = []
    remote = (SimpleNamespace(), SimpleNamespace(), SimpleNamespace())
    session = SimpleNamespace(
        cc=ClassCollection(QtShim, backend),
        config=McritConfig("0.0.0"),
        local_widget=SimpleNamespace(updateActivityInfo=activity.append),
        mcrit_interface=SimpleNamespace(queryRemoteFunction=lambda function_id: remote),
    )
    widget = FunctionMatchWidgetModule.FunctionMatchWidget(session)

    widget._showMatchGraph(None, None, 7)
    widget._showMatchGraph(None, None, 7)
    assert len(backend.pending) == 1
    backend.pending.pop()()

    assert backend.graphs == 1
    assert activity[-1] == "Opened the graph of function 7."
    widget._showMatchGraph(None, None, 7)  # once the graph is open, a double click opens it again
    assert len(backend.pending) == 1
