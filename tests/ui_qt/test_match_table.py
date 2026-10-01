"""Function Scope's match table model: values sort numerically, the fill order holds until a header
is clicked, and the selection follows its row."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QColor  # noqa: E402

from mcrit_plugin.ui_qt.widgets.MatchTable import MatchRow, MatchTableView  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _rows(scores):
    return [
        MatchRow(
            position,
            SimpleNamespace(matched_function_id=100 + position),
            ["%d" % score, "fam%d" % position],
            [score, "fam%d" % position],
            QColor(score, 0, 0),
        )
        for position, score in enumerate(scores)
    ]


def _column(view, column):
    model = view.model()
    return [model.index(row, column).data() for row in range(model.rowCount())]


def test_rows_keep_their_fill_order_until_a_header_is_clicked(app):
    view = MatchTableView()
    view.table_model.reset(["Score", "Family"], _rows([90, 100, 85]))

    assert _column(view, 0) == ["90", "100", "85"]


def test_numbers_sort_by_value_and_the_choice_survives_a_refill(app):
    view = MatchTableView()
    view.table_model.reset(["Score", "Family"], _rows([9, 100, 50]))

    view.sortByColumn(0, Qt.AscendingOrder)
    assert _column(view, 0) == ["9", "50", "100"], "as text, 100 would sort before 9"

    view.table_model.reset(["Score", "Family"], _rows([7, 70, 700]))
    assert _column(view, 0) == ["7", "70", "700"]


def test_the_selection_follows_its_row_when_sorting(app):
    view = MatchTableView()
    view.table_model.reset(["Score", "Family"], _rows([90, 100, 85]))
    view.setCurrentIndex(view.model().index(0, 1))

    view.sortByColumn(0, Qt.DescendingOrder)

    current = view.currentIndex()
    assert current.data() == "fam0"
    assert view.table_model.entryAt(current.row()).matched_function_id == 100


def test_cells_carry_the_score_color_and_the_shared_text_color(app):
    view = MatchTableView()
    text_color = QColor(1, 2, 3)
    view.table_model.reset(["Score", "Family"], _rows([90]), text_color)
    index = view.model().index(0, 1)

    assert index.data(Qt.BackgroundRole) == QColor(90, 0, 0)
    assert index.data(Qt.ForegroundRole) == text_color


def test_untinted_rows_keep_the_styles_text_color(app):
    view = MatchTableView()
    rows = _rows([90])
    rows.append(MatchRow(1, "block", ["0", "-"], [0, "-"]))
    view.table_model.reset(["Score", "Family"], rows, QColor(1, 2, 3))

    assert view.model().index(1, 0).data(Qt.ForegroundRole) is None
    assert view.model().index(0, 0).data(Qt.ForegroundRole) == QColor(1, 2, 3)


def test_a_filled_row_is_found_after_sorting(app):
    view = MatchTableView()
    view.table_model.reset(["Score", "Family"], _rows([90, 100, 85]))
    view.sortByColumn(0, Qt.AscendingOrder)

    assert view.table_model.positionOf(1) == 2
    assert view.table_model.positionOf(7) is None
