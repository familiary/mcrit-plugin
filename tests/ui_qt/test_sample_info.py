"""Sample Info lists the best sample per family, best first, and the samples of the selected family."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
from mcrit_plugin.core.config import McritConfig  # noqa: E402
from mcrit_plugin.ui_qt.ClassCollection import ClassCollection  # noqa: E402
from mcrit_plugin.ui_qt.widgets.SampleInfoWidget import SampleInfoWidget  # noqa: E402


class _Backend:
    name = "test"

    def theme_color(self, role, default):
        return default


def _sample(sample_id, family, bytescore, version="1.0"):
    return {
        "family": family,
        "version": version,
        "sha256": "%064x" % sample_id,
        "filename": "f",
        "sample_id": sample_id,
        "minhash_matches": 1,
        "pichash_matches": 2,
        "combined_matches": 3,
        "library_matches": 0,
        "bytescore": bytescore,
        "bytescore_adjusted": 0,
        "percent": 12.5,
        "percent_adjusted": 0,
    }


@pytest.fixture
def widget():
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    session = SimpleNamespace(
        cc=ClassCollection(QtShim, _Backend()),
        config=McritConfig("test"),
        getMatchingReport=lambda: None,
        local_widget=SimpleNamespace(updateActivityInfo=lambda text: None),
    )
    widget = SampleInfoWidget(session)
    data = {
        1: _sample(1, "alpha", 50),
        2: _sample(2, "beta", 90, version=None),
        3: _sample(3, "alpha", 70),
    }
    widget._aggregatedMatchingData = lambda: data
    return widget


def _column(table, column):
    model = table.model()
    return [model.index(row, column).data() for row in range(model.rowCount())]


def test_each_family_shows_its_best_sample_best_first(widget):
    widget.populateBestMatchTable()

    assert _column(widget.table_best_family_matches, 2) == ["beta", "alpha"]
    assert _column(widget.table_best_family_matches, 0) == ["2", "3"]
    assert _column(widget.table_best_family_matches, 1) == ["1", "2"], "samples per family"
    assert _column(widget.table_best_family_matches, 3) == ["", "1.0"], "a missing version is blank"


def test_selecting_a_family_lists_its_samples(widget):
    widget.populateBestMatchTable()
    table = widget.table_best_family_matches

    table.setCurrentIndex(table.model().index(1, 2))

    assert widget.last_family_selected == "alpha"
    assert _column(widget.table_family_sample_matches, 0) == ["3", "1"]
