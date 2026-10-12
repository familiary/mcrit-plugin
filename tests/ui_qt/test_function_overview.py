"""The overview renders a result once and fetches labels through the backend's request runner."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
from mcrit_plugin.core.config import McritConfig  # noqa: E402
from mcrit_plugin.ui_qt.ClassCollection import ClassCollection  # noqa: E402
from mcrit_plugin.ui_qt.widgets.FunctionOverviewWidget import FunctionOverviewWidget  # noqa: E402


class Backend:
    name = "test"

    def __init__(self):
        self.pending = []

    def run_request(self, work, on_done):
        self.pending.append((work, on_done))

    def theme_color(self, role, default):
        return default

    def has_default_function_name(self, address):
        return True


def _match(function_id, matched_function_id, score):
    return SimpleNamespace(
        function_id=function_id,
        offset=0x1000 + function_id,
        matched_function_id=matched_function_id,
        matched_family_id=1,
        matched_sample_id=1,
        matched_score=score,
        match_is_library=False,
    )


@pytest.fixture
def overview():
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    backend = Backend()
    report = SimpleNamespace(function_matches=[_match(1, 10, 80), _match(2, 20, 95)])
    activity = []
    session = SimpleNamespace(
        cc=ClassCollection(QtShim, backend),
        config=McritConfig("test"),
        getMatchingReport=lambda: report,
        matching_job_id="job",
        matched_function_entries=None,
        local_widget=SimpleNamespace(updateActivityInfo=activity.append),
        mcrit_interface=SimpleNamespace(),
    )
    widget = FunctionOverviewWidget(session)
    widget.rb_filter_none.setChecked(True)
    return widget, backend, session


def _count_populates(widget):
    calls = []
    original = widget.populateFunctionTable
    widget.populateFunctionTable = lambda *args, **kwargs: (
        calls.append(1),
        original(*args, **kwargs),
    )
    return calls


def test_a_new_result_populates_the_table_once(overview):
    widget, _backend, _session = overview
    calls = _count_populates(widget)

    widget.update()

    assert len(calls) == 1
    assert widget.sb_minhash_threshold.value() == 80
    assert widget.table_local_functions.rowCount() == 2


def test_a_filter_click_populates_the_table_once(overview):
    widget, _backend, _session = overview
    widget.update()
    calls = _count_populates(widget)

    widget.rb_filter_labels.click()

    assert len(calls) == 1


def test_labels_are_fetched_through_the_request_runner(overview):
    widget, backend, session = overview
    queried = []
    session.mcrit_interface.queryFunctionEntriesById = lambda ids, with_label_only: (
        queried.append((sorted(ids), with_label_only)) or {}
    )

    widget.b_fetch_labels.click()

    assert queried == []
    assert not widget.b_fetch_labels.isEnabled()
    work, on_done = backend.pending.pop()
    on_done(work())
    assert queried == [([10, 20], True)]
    assert widget.b_fetch_labels.isEnabled()

    widget.fetchLabels()

    assert backend.pending == []
