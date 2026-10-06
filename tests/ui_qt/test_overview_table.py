"""The overview's table keeps its rows in a model, so a large result renders without a widget per
row, sorting moves rows without moving what they hold, and the label drop-down is painted."""

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.core.McritTableColumn as McritTableColumn  # noqa: E402
import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
from mcrit_plugin.ui_qt.widgets.OverviewTable import (  # noqa: E402
    OverviewTableView,
    build_row,
)

Qt = QtShim.get_Qt()
COLUMNS = [
    McritTableColumn.OFFSET,
    McritTableColumn.FAMILIES,
    McritTableColumn.IS_LIBRARY,
    McritTableColumn.SCORE_AND_LABEL,
]
LABEL_COLUMN = 3


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _info(offset, families=1, library=False, criticality=0):
    return {
        "offset": offset,
        "families": set(range(families)),
        "samples": {1},
        "functions": {1},
        "library_matches": {1} if library else set(),
        "criticality": criticality,
    }


def _fill(view, infos, dropdowns=True):
    view.sortByColumn(0, Qt.AscendingOrder)
    rows = [
        build_row(
            n, info, COLUMNS, [(95, "name_%x" % info["offset"])], "95|name_%x" % info["offset"]
        )
        for n, info in enumerate(infos)
    ]
    view.table_model.reset(
        ["Offset", "Families", "Library?", "Label"], COLUMNS, LABEL_COLUMN, rows, dropdowns
    )
    view.setLabelColumn(LABEL_COLUMN)


def _cell(view, row, column):
    return view.model().index(row, column).data()


def test_offsets_and_counts_sort_by_value_not_by_text(app):
    view = OverviewTableView()
    _fill(view, [_info(0x9, families=10), _info(0x1000, families=2), _info(0x80, families=33)])

    view.sortByColumn(0, Qt.DescendingOrder)
    assert [_cell(view, row, 0) for row in range(3)] == ["0x1000", "0x80", "0x9"]

    view.sortByColumn(1, Qt.AscendingOrder)
    assert [_cell(view, row, 1) for row in range(3)] == ["2", "10", "33"]


def test_a_sorted_row_still_finds_the_row_it_was_filled_into(app):
    view = OverviewTableView()
    _fill(view, [_info(0x1000), _info(0x2000), _info(0x3000)])

    view.sortByColumn(0, Qt.DescendingOrder)

    assert [view.sourceRow(row) for row in range(3)] == [2, 1, 0]
    for row in range(3):
        offset = [0x1000, 0x2000, 0x3000][view.sourceRow(row)]
        assert _cell(view, row, LABEL_COLUMN) == "95|name_%x" % offset


def test_picking_a_label_changes_only_that_row(app):
    view = OverviewTableView()
    _fill(view, [_info(0x1000), _info(0x2000)])
    index = view.model().index(1, LABEL_COLUMN)

    assert view.model().setData(index, "-|-")

    assert _cell(view, 1, LABEL_COLUMN) == "-|-"
    assert _cell(view, 0, LABEL_COLUMN) == "95|name_1000"
    assert not view.model().setData(index, "no such label")
    assert not view.model().setData(view.model().index(1, 0), 0)


def test_without_labels_the_label_column_is_plain(app):
    view = OverviewTableView()
    _fill(view, [_info(0x1000)], dropdowns=False)

    assert not view.table_model.flags(view.table_model.index(0, LABEL_COLUMN)) & Qt.ItemIsEditable
    assert _cell(view, 0, LABEL_COLUMN) == "95|name_1000"  # the entry the row would select


def test_label_cells_are_painted_with_the_criticality_color(app):
    view = OverviewTableView()
    _fill(view, [_info(0x1000, criticality=5)])
    view.resize(500, 120)
    view.show()

    image = view.viewport().grab().toImage()

    center = view.visualRect(view.model().index(0, LABEL_COLUMN)).center()
    ratio = image.devicePixelRatio()
    painted = image.pixelColor(int((center.x() - 40) * ratio), int((center.y() - 8) * ratio))
    # the style shades the tint, so only its hue is checked: red well above green and blue
    assert painted.red() > painted.green() + 40
    assert painted.red() > painted.blue() + 40


def test_a_click_opens_one_combo_box_and_a_pick_commits(app):
    view = OverviewTableView()
    _fill(view, [_info(0x1000), _info(0x2000)])
    view.resize(500, 160)
    view.show()
    index = view.model().index(0, LABEL_COLUMN)

    view.edit(index)
    editors = view.findChildren(QtWidgets.QComboBox)
    assert len(editors) == 1
    assert [editors[0].itemText(n) for n in range(editors[0].count())] == [
        "95|name_1000",
        "-|-",
    ]
    editors[0].setCurrentIndex(1)
    editors[0].activated.emit(1)

    assert _cell(view, 0, LABEL_COLUMN) == "-|-"


def test_thousands_of_rows_fill_without_a_widget_per_row(app):
    view = OverviewTableView()
    infos = [_info(0x1000 + n) for n in range(20000)]

    start = time.perf_counter()
    _fill(view, infos)
    view.show()
    app.processEvents()
    elapsed = time.perf_counter() - start

    assert view.model().rowCount() == 20000
    assert view.findChildren(QtWidgets.QComboBox) == []
    assert elapsed < 2
