"""Opening a block match's graph tints the local function and block the Block Scope tables show,
not wherever the cursor has moved since."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
from mcrit_plugin.core.config import McritConfig  # noqa: E402
from mcrit_plugin.core.ScoreColorProvider import ThemeRole  # noqa: E402
from mcrit_plugin.ui_qt.ClassCollection import ClassCollection  # noqa: E402
from mcrit_plugin.ui_qt.widgets.BlockMatchWidget import BlockMatchWidget, packRgb  # noqa: E402

SHOWN_FUNCTION = 0x1000
SHOWN_BLOCK = 0x1000
REMOTE_FUNCTION_ID = 7


class _Backend:
    def __init__(self):
        self.pending = []
        self.local_coloring = []

    def run_request(self, title, work, on_done):
        self.pending.append(lambda: on_done(work()))

    def theme_color(self, role, default):
        return default

    def show_local_match_coloring(self, smda_function, coloring):
        self.local_coloring.append((smda_function.offset, coloring))

    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        pass


@pytest.fixture
def block_scope():
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    backend = _Backend()
    functions = {offset: SimpleNamespace(offset=offset) for offset in (0x1000, 0x2000)}
    remote = (SimpleNamespace(function_id=REMOTE_FUNCTION_ID), None, None)
    session = SimpleNamespace(
        cc=ClassCollection(QtShim, backend),
        config=McritConfig("0.0.0"),
        current_function=SHOWN_FUNCTION,
        current_block=SHOWN_BLOCK,
        local_smda_report=SimpleNamespace(getFunction=functions.get),
        family_infos={},
        sample_infos={},
        blockhash_matches={
            0xAA: [(1, 1, REMOTE_FUNCTION_ID, 0x5000)],
            0xBB: [(1, 1, REMOTE_FUNCTION_ID, 0x5010)],
        },
        block_to_hash={},
        local_widget=SimpleNamespace(updateActivityInfo=lambda message: None),
        mcrit_interface=SimpleNamespace(queryRemoteFunction=lambda function_id: remote),
    )
    widget = BlockMatchWidget(session)
    widget.last_viewed_block = SHOWN_BLOCK  # as a query for the shown block sets it
    widget._showBlockMatches(
        [{"hash": 0xAA, "offset": 0x1000, "size": 4}, {"hash": 0xBB, "offset": 0x1010, "size": 4}]
    )
    return widget, backend, session


def _double_click_first_match(widget, backend):
    widget._onTableBlockMatchesDoubleClicked(widget.table_block_matches.model().index(0, 0))
    backend.pending.pop()()


def test_the_tint_follows_the_tables_not_the_cursor(block_scope):
    widget, backend, session = block_scope
    session.current_block = 0x1010  # the cursor moved to another block of the same function

    _double_click_first_match(widget, backend)

    ((function_offset, coloring),) = backend.local_coloring
    assert function_offset == SHOWN_FUNCTION
    current_color = packRgb(widget.scp.roleColor(ThemeRole.CURRENT, (0x00, 0xDD, 0xFF)))
    assert coloring[SHOWN_BLOCK] == current_color
    assert coloring[0x1010] != current_color


def test_a_query_for_another_function_does_not_empty_the_tint(block_scope):
    widget, backend, session = block_scope
    session.current_function = 0x2000  # a live query for this function has not answered yet
    session.current_block = 0x2000

    _double_click_first_match(widget, backend)

    ((function_offset, coloring),) = backend.local_coloring
    assert function_offset == SHOWN_FUNCTION
    assert set(coloring) == {0x1000, 0x1010}
