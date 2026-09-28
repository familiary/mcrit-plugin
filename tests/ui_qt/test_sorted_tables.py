"""After a header click sorts a table, lookups keyed by the row a cell was filled into still find
that cell's own entry."""

import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

import mcrit_plugin.ui_qt.QtShim as QtShim  # noqa: E402
from mcrit_plugin.ui_qt.ClassCollection import ClassCollection  # noqa: E402
from mcrit_plugin.ui_qt.widgets.FunctionOverviewWidget import (  # noqa: E402
    DropdownDelegate,
    FunctionOverviewWidget,
)
from mcrit_plugin.ui_qt.widgets.NumberQTableWidgetItem import NumberQTableWidgetItem  # noqa: E402
from mcrit_plugin.ui_qt.widgets.ResultChooserDialog import ResultChooserDialog  # noqa: E402


@pytest.fixture(scope="module")
def cc():
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    return ClassCollection(QtShim, None)


def _sort_descending(table):
    table.setSortingEnabled(True)
    table.sortItems(0, QtShim.get_Qt().DescendingOrder)


def test_the_result_chooser_returns_the_job_of_the_sorted_row(cc):
    parent = QtWidgets.QWidget()
    parent.cc = cc
    jobs = [
        SimpleNamespace(
            number=number,
            parameters="job %d" % number,
            started_at="2026-09-28T10:00:00",
            finished_at="2026-09-28T10:01:00",
            progress=1.0,
        )
        for number in (1, 2, 3)
    ]
    dialog = ResultChooserDialog(parent, jobs)

    _sort_descending(dialog.table_jobs)

    shown = [int(dialog.table_jobs.item(row, 0).text()) for row in range(3)]
    assert shown == [3, 2, 1]
    assert [dialog.jobInfoAt(row).number for row in range(3)] == shown


def test_the_overview_reads_each_sorted_row_from_its_own_editor(cc):
    offsets = [0x1000, 0x2000, 0x3000]
    labels = {
        (row, 1): [{"text": "label_%x" % offset, "preselected": True}]
        for row, offset in enumerate(offsets)
    }
    table = QtWidgets.QTableWidget(len(offsets), 2)
    delegate = DropdownDelegate(labels)
    table.setItemDelegateForColumn(1, delegate)
    for row, offset in enumerate(offsets):
        offset_item = NumberQTableWidgetItem("0x%x" % offset)
        offset_item.setData(QtShim.get_Qt().UserRole, row)
        table.setItem(row, 0, offset_item)
        table.setItem(row, 1, QtWidgets.QTableWidgetItem(""))
        table.openPersistentEditor(table.item(row, 1))
    overview = SimpleNamespace(table_local_functions=table, cc=cc)

    _sort_descending(table)

    for row in range(len(offsets)):
        populated_row = FunctionOverviewWidget._populatedRow(overview, row)
        editor = delegate.getEditorForRow(populated_row)
        assert editor.currentText() == "label_" + table.item(row, 0).text()[2:]


def test_hex_offsets_sort_by_value(cc):
    table = QtWidgets.QTableWidget(3, 1)
    for row, offset in enumerate([0x9, 0x1000, 0x80]):
        table.setItem(row, 0, NumberQTableWidgetItem("0x%x" % offset))

    _sort_descending(table)

    assert [table.item(row, 0).text() for row in range(3)] == ["0x1000", "0x80", "0x9"]
