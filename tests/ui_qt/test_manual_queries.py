"""With live queries off, a query asked for by button stays in the tables when a control is
changed, and the controls do nothing before a report exists."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
import mcrit_plugin.ui_qt.widgets.BlockMatchWidget as BlockMatchWidgetModule  # noqa: E402
import mcrit_plugin.ui_qt.widgets.FunctionMatchWidget as FunctionMatchWidgetModule  # noqa: E402
from mcrit_plugin.core.config import McritConfig  # noqa: E402
from mcrit_plugin.ui_qt.ClassCollection import ClassCollection  # noqa: E402


class _Backend:
    closed = False

    def __init__(self):
        self.pending = []

    def get_current_function(self, view):
        return 0x1000

    def get_cursor_address(self):
        return 0x1000

    def run_request(self, title, work, on_done):
        self.pending.append(lambda: on_done(work()))


def _session(report):
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    return SimpleNamespace(
        cc=ClassCollection(QtShim, _Backend()),
        config=McritConfig("0.0.0"),
        current_function=0x1000,
        current_block=0x1000,
        local_smda_report=report,
        family_infos={},
        sample_infos={},
        blockhash_matches={},
        block_to_hash={},
        local_widget=SimpleNamespace(updateActivityInfo=lambda text: None),
        main_widget=SimpleNamespace(hideLocalWidget=lambda: None),
    )


def _report():
    function = SimpleNamespace(offset=0x1000, num_instructions=20)
    return SimpleNamespace(
        getFunction=lambda offset: function, findBlockByContainedAddress=lambda address: None
    )


@pytest.mark.parametrize(
    "module, widget_class, update",
    [
        (FunctionMatchWidgetModule, "FunctionMatchWidget", "updateViewWithCurrentFunction"),
        (BlockMatchWidgetModule, "BlockMatchWidget", "updateViewWithCurrentBlock"),
    ],
)
def test_the_library_filter_refreshes_a_manual_query_instead_of_clearing_it(
    module, widget_class, update, monkeypatch
):
    widget = getattr(module, widget_class)(_session(_report()))
    widget.enable()
    widget.cb_activate_live_tracking.setChecked(False)
    updates = []
    cleared = []
    monkeypatch.setattr(widget, update, lambda: updates.append(1))
    monkeypatch.setattr(widget, "clearTable", lambda: cleared.append(1))
    # what the query by button leaves behind
    widget.last_viewed = widget.last_viewed_function = 0x1000

    widget.cb_filter_library.click()

    assert updates == [1]
    assert cleared == []


@pytest.mark.parametrize(
    "module, widget_class, spin_box",
    [
        (FunctionMatchWidgetModule, "FunctionMatchWidget", "sb_score_threshold"),
        (BlockMatchWidgetModule, "BlockMatchWidget", "sb_blocksize_threshold"),
    ],
)
def test_a_threshold_changed_before_convert_does_nothing(module, widget_class, spin_box):
    widget = getattr(module, widget_class)(_session(None))
    box = getattr(widget, spin_box)

    box.setValue(box.value() + 1)
    widget.handleSpinThresholdChange()


def test_block_lookups_that_failed_are_not_shown_as_blocks_without_matches(monkeypatch):
    session = _session(_report())
    session.family_infos = None
    session.mcrit_interface = SimpleNamespace(
        _pinConnection=lambda: (None, 0),
        getMatchesForPicBlockHash=lambda block_hash, connection: None,
        storeBlockMatches=lambda found, connection, shown=(): None,
    )
    widget = BlockMatchWidgetModule.BlockMatchWidget(session)
    monkeypatch.setattr(
        BlockMatchWidgetModule.FunctionCfgMatcher,
        "getPicBlockHashesForFunction",
        lambda report, smda_function, min_size: [{"hash": 5, "offset": 0x1000}],
    )
    monkeypatch.setattr(widget, "_fetch_remote_cache", lambda: True)
    monkeypatch.setattr(widget, "_showBlockMatches", lambda pbh: None)

    widget.cb_activate_live_tracking.setChecked(True)
    widget.updateViewWithCurrentBlock()
    assert "Querying" in widget.label_current_function_matches.text()
    session.cc.backend.pending.pop()()

    assert "incomplete" in widget.label_current_function_matches.text()
    assert widget.last_viewed_function is None, "the next cursor move asks again"

    # with live queries off a cursor move in the function must not clear what the button showed
    widget.cb_activate_live_tracking.setChecked(False)
    widget.updateViewWithCurrentBlock()
    session.cc.backend.pending.pop()()
    assert widget.last_viewed_function == 0x1000


def test_a_live_block_query_follows_the_cursor_to_another_block_of_the_function(monkeypatch):
    session = _session(_report())
    widget = BlockMatchWidgetModule.BlockMatchWidget(session)
    widget.enable()
    widget.cb_activate_live_tracking.setChecked(True)
    # what a finished query for the function leaves behind, shown for its first block
    widget.last_viewed_function = widget._shown_function = 0x1000
    widget._last_block_matches = {}
    widget._shown_block = 0x1000
    shown = []
    monkeypatch.setattr(
        widget, "populateBlockMatchTable", lambda matches, block: shown.append(block)
    )
    monkeypatch.setattr(widget, "updateCurrentBlock", lambda view: 0x1000)

    session.current_block = 0x1040
    widget.hook_refresh(None)

    assert shown == [0x1040]


def _function_widget(monkeypatch, query):
    session = _session(_report())
    session.function_matches = {}
    session.matched_function_entries = {}
    session.getLocalSmdaReportOutline = lambda: SimpleNamespace(xcfg=None)
    session.mcrit_interface = SimpleNamespace(
        querySmdaFunctionMatches=query, queryFunctionEntriesById=lambda ids: None
    )
    widget = FunctionMatchWidgetModule.FunctionMatchWidget(session)
    monkeypatch.setattr(widget, "_fetch_remote_cache", lambda: True)
    return session, widget


def test_a_function_query_without_an_answer_says_so_and_can_be_asked_again(monkeypatch):
    session, widget = _function_widget(monkeypatch, lambda outline: None)
    widget.cb_activate_live_tracking.setChecked(True)

    widget.updateViewWithCurrentFunction()
    session.cc.backend.pending.pop()()

    assert "failed" in widget.label_current_function_matches.text()
    assert widget.last_viewed is None


def test_a_function_asked_for_again_while_its_request_runs_starts_no_second_request(monkeypatch):
    queries = []
    session, widget = _function_widget(monkeypatch, queries.append)

    widget.updateViewWithCurrentFunction()
    widget.updateViewWithCurrentFunction()

    assert len(session.cc.backend.pending) == 1
    session.cc.backend.pending.pop()()
    # asked again meanwhile: the view is brought up to date once the request answered
    assert len(session.cc.backend.pending) == 1


def test_the_query_button_and_a_new_client_do_not_wait_for_a_request_that_never_answers(
    monkeypatch,
):
    session, widget = _function_widget(monkeypatch, lambda outline: None)
    session.mcrit_interface.mcrit_client = object()

    widget.updateViewWithCurrentFunction()  # this one never answers
    widget.queryCurrentFunction()
    assert len(session.cc.backend.pending) == 2

    session.mcrit_interface.mcrit_client = object()  # new connection settings
    widget.updateViewWithCurrentFunction()
    assert len(session.cc.backend.pending) == 3
