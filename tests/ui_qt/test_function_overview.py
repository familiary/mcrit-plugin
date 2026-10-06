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

    def run_request(self, title, work, on_done):
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
    assert widget.table_local_functions.model().rowCount() == 2


def test_without_labels_the_label_cells_show_a_dash(overview):
    widget, _backend, _session = overview

    widget.update()

    model = widget.table_local_functions.model()
    label_column = model.columnCount() - 1
    assert [model.index(row, label_column).data() for row in range(model.rowCount())] == ["-", "-"]


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


def _chunked(monkeypatch, overview):
    import mcrit_plugin.ui_qt.widgets.FunctionOverviewWidget as module

    monkeypatch.setattr(module, "LABEL_FIRST_CHUNK_SIZE", 1)
    monkeypatch.setattr(module, "LABEL_CHUNK_SIZE", 1)
    widget, backend, session = overview
    queried = []
    session.mcrit_interface.queryFunctionEntriesById = lambda ids, with_label_only: (
        queried.append(list(ids)) or {}
    )
    return widget, backend, queried, module


def test_labels_are_fetched_in_chunks_best_match_first(monkeypatch, overview):
    widget, backend, queried, _module = _chunked(monkeypatch, overview)
    calls = _count_populates(widget)

    widget.b_fetch_labels.click()
    work, on_done = backend.pending.pop()
    on_done(work())

    assert queried == [[20]]
    assert not widget.b_fetch_labels.isEnabled()
    assert len(calls) == 1  # the first chunk is shown at once
    work, on_done = backend.pending.pop()
    on_done(work())
    assert queried == [[20], [10]]
    assert widget.b_fetch_labels.isEnabled()
    assert backend.pending == []


def test_chunks_between_renders_do_not_repopulate_the_table(monkeypatch, overview):
    widget, backend, queried, _module = _chunked(monkeypatch, overview)
    widget.b_fetch_labels.click()
    calls = _count_populates(widget)
    widget._label_last_render = float("inf")  # a render just happened

    work, on_done = backend.pending.pop()
    on_done(work())

    assert calls == []
    work, on_done = backend.pending.pop()
    on_done(work())
    assert len(calls) == 1  # the last chunk always renders


def test_a_failed_chunk_stops_the_fetch_and_is_retried_later(monkeypatch, overview):
    widget, backend, _queried, _module = _chunked(monkeypatch, overview)
    widget._label_requested_ids = set()
    widget.parent.mcrit_interface.queryFunctionEntriesById = lambda ids, with_label_only: None

    widget.b_fetch_labels.click()
    work, on_done = backend.pending.pop()
    on_done(work())

    assert backend.pending == []
    assert widget.b_fetch_labels.isEnabled()
    assert widget._label_requested_ids == set()


def test_later_chunks_are_larger_than_the_first(monkeypatch, overview):
    widget, backend, queried, module = _chunked(monkeypatch, overview)
    monkeypatch.setattr(module, "LABEL_CHUNK_SIZE", 5)
    widget.parent.getMatchingReport().function_matches.extend(
        _match(10 + n, 100 + n, 10 + n) for n in range(6)
    )

    widget.b_fetch_labels.click()
    while backend.pending:
        work, on_done = backend.pending.pop()
        on_done(work())

    assert [len(ids) for ids in queried] == [1, 5, 2]
    assert queried[0] == [20]


def _reference_aggregate(report, threshold, filtered, labeled):
    """The aggregation as it was written before the matches were grouped and cached."""
    aggregated = {}
    beyond = 0
    for match in report.function_matches:
        if match.matched_score < threshold:
            continue
        if filtered and match.matched_function_id not in labeled:
            continue
        beyond += 1
        info = aggregated.setdefault(
            match.function_id,
            {
                "offset": match.offset,
                "families": set(),
                "samples": set(),
                "functions": set(),
                "library_matches": set(),
                "labels": set(),
            },
        )
        info["families"].add(match.matched_family_id)
        info["samples"].add(match.matched_sample_id)
        info["functions"].add(match.matched_function_id)
        if match.match_is_library:
            info["library_matches"].add(match.matched_function_id)
        for label in getattr(labeled.get(match.matched_function_id), "function_labels", []):
            info["labels"].add(
                (int(match.matched_score), label.function_label, label.username, label.timestamp)
            )
    return aggregated, beyond


def test_the_grouped_aggregation_matches_the_per_match_loop(overview):
    import random

    widget, _backend, _session = overview
    rng = random.Random(7)
    matches = [
        SimpleNamespace(
            function_id=rng.randrange(20),
            offset=0,
            matched_function_id=rng.randrange(60),
            matched_family_id=rng.randrange(4),
            matched_sample_id=rng.randrange(6),
            matched_score=rng.randrange(50, 100),
            match_is_library=rng.random() < 0.2,
        )
        for _ in range(500)
    ]
    for match in matches:
        match.offset = 0x1000 + match.function_id
    report = SimpleNamespace(function_matches=matches)
    label = lambda n: SimpleNamespace(function_label="n%d" % n, username="u", timestamp="t")  # noqa: E731
    labeled = {
        fid: SimpleNamespace(function_labels=[label(fid), label(fid + 100)])
        for fid in range(0, 60, 3)
    }

    for threshold in (50, 75, 99, 100):
        for filtered in (False, True):
            aggregated, beyond, functions, total = widget._aggregateMatches(
                report, threshold, filtered, labeled
            )
            expected, expected_beyond = _reference_aggregate(report, threshold, filtered, labeled)
            assert aggregated == expected
            assert beyond == expected_beyond
            assert functions == set(expected)
            assert total == len({match.function_id for match in matches})


def test_new_labels_are_not_served_from_the_aggregation_cache(overview):
    widget, _backend, _session = overview
    report = SimpleNamespace(function_matches=[_match(1, 10, 80)])
    entry = SimpleNamespace(
        function_labels=[SimpleNamespace(function_label="a", username="u", timestamp="t")]
    )

    without = widget._aggregateMatches(report, 0, False, {})[0]
    with_label = widget._aggregateMatches(report, 0, False, {10: entry})[0]

    assert without[1]["labels"] == set()
    assert {label[1] for label in with_label[1]["labels"]} == {"a"}


def test_a_label_update_reuses_the_label_free_aggregation(overview, monkeypatch):
    import mcrit_plugin.ui_qt.widgets.FunctionOverviewWidget as overview_module

    widget, _backend, _session = overview
    report = SimpleNamespace(function_matches=[_match(1, 10, 80), _match(2, 11, 90)])
    widget._aggregateMatches(report, 0, False, {})
    calls = []
    original = overview_module._matchSets
    monkeypatch.setattr(
        overview_module, "_matchSets", lambda *args: calls.append(args) or original(*args)
    )
    entry = SimpleNamespace(
        function_labels=[SimpleNamespace(function_label="a", username="u", timestamp="t")]
    )

    aggregated = widget._aggregateMatches(report, 0, False, {10: entry})[0]

    assert calls == [], "only the labels are recomputed when labels arrive"
    assert {label[1] for label in aggregated[1]["labels"]} == {"a"}
    assert aggregated[2]["labels"] == set()
