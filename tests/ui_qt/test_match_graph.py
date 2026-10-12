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
from mcrit_plugin.ui_qt.widgets.BlockMatchWidget import BlockMatchWidget  # noqa: E402


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


def test_a_repeated_double_click_on_a_block_match_opens_one_graph():
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    backend = _Backend()
    backend.theme_color = lambda role, default: default
    activity = []
    remote = (SimpleNamespace(function_id=7), SimpleNamespace(), SimpleNamespace())
    session = SimpleNamespace(
        cc=ClassCollection(QtShim, backend),
        config=McritConfig("0.0.0"),
        current_function=0x1000,
        current_block=0x1000,
        family_infos={},
        sample_infos={},
        blockhash_matches={0xAA: [(1, 1, 7, 0x5000)]},
        block_to_hash={},
        local_widget=SimpleNamespace(updateActivityInfo=activity.append),
        mcrit_interface=SimpleNamespace(queryRemoteFunction=lambda function_id: remote),
    )
    widget = BlockMatchWidget(session)
    widget.last_viewed_block = 0x1000
    widget._showBlockMatches([{"hash": 0xAA, "offset": 0x1000, "size": 4}])
    first_match = widget.table_block_matches.model().index(0, 0)

    widget._onTableBlockMatchesDoubleClicked(first_match)
    widget._onTableBlockMatchesDoubleClicked(first_match)
    assert len(backend.pending) == 1
    backend.pending.pop()()

    assert backend.graphs == 1
    assert activity[-1] == "Opened the graph of function 7."
