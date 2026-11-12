"""The tables and dialogs follow the host's own lists and dialogs: no row numbers or grid, a
whole row selected, columns fitted without asking the model for every cell, buttons in the
platform's order."""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from mcrit_plugin.ui_qt.widgets import NativeLook  # noqa: E402
from mcrit_plugin.ui_qt.widgets.MatchTable import (  # noqa: E402
    MAX_FITTED_WIDTH,
    MatchRow,
    MatchTableView,
)
from mcrit_plugin.ui_qt.widgets.OverviewTable import OverviewTableView  # noqa: E402


@pytest.fixture
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.mark.parametrize("view_class", [MatchTableView, OverviewTableView])
def test_a_table_looks_like_the_hosts_lists(app, view_class):
    view = view_class()

    assert view.verticalHeader().isHidden()
    assert not view.showGrid()
    assert not view.wordWrap()
    assert view.selectionBehavior() == QtWidgets.QAbstractItemView.SelectRows
    assert view.verticalScrollMode() == QtWidgets.QAbstractItemView.ScrollPerPixel
    assert not view.horizontalHeader().highlightSections()


def _rows(texts):
    return [MatchRow(number, None, row, row) for number, row in enumerate(texts)]


def test_columns_are_fitted_without_asking_the_model_for_each_cell(app, monkeypatch):
    view = MatchTableView()
    view.table_model.reset(["Offset", "Family", "Last"], _rows([["0x401000", "win.x", "1"]] * 50))
    asked = []
    original = view.table_model.data
    monkeypatch.setattr(
        view.table_model, "data", lambda index, role=0: asked.append(1) or original(index, role)
    )

    view.resizeColumnsToContents()

    assert asked == []
    assert view.columnWidth(0) >= view.fontMetrics().horizontalAdvance("0x401000")


def test_a_fitted_column_is_capped_so_a_hash_does_not_push_the_others_out(app):
    view = MatchTableView()
    view.table_model.reset(["SHA256", "Version", "Last"], _rows([["e" * 64, "1.0", "x"]]))

    view.resizeColumnsToContents()

    assert view.columnWidth(0) == MAX_FITTED_WIDTH


def test_addresses_take_the_hosts_code_font_where_it_has_one(app, monkeypatch):
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont

    code_font = QFont("Menlo")
    monkeypatch.setattr(NativeLook, "_monospace_font", lambda widget: code_font)
    view = MatchTableView()
    view.table_model.reset(["Offset", "Family"], _rows([["0x401000", "win.x"]]))
    model = view.table_model

    assert model.data(model.index(0, 0), Qt.FontRole) is code_font
    assert model.data(model.index(0, 1), Qt.FontRole) is None


def test_dialog_buttons_go_through_the_platforms_button_box(app):
    accept, reject, action = (QtWidgets.QPushButton(text) for text in ("OK", "Cancel", "Copy"))

    box = NativeLook.button_box(accept=[accept], reject=[reject], actions=[action])

    assert box.buttonRole(accept) == QtWidgets.QDialogButtonBox.AcceptRole
    assert box.buttonRole(reject) == QtWidgets.QDialogButtonBox.RejectRole
    assert box.buttonRole(action) == QtWidgets.QDialogButtonBox.ActionRole


def _press_return_in(dialog, focus):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    dialog.show()
    focus.setFocus()
    QTest.keyClick(focus, Qt.Key_Return)
    dialog.close()


def test_return_presses_the_default_button_not_the_first_one_added(app):
    """A dialog takes the first auto-default button as its default when it shows; the action
    buttons are added first, so Return in the result chooser created a new matching job."""
    pressed = []
    dialog = QtWidgets.QDialog()
    table = QtWidgets.QTableWidget(1, 1)
    select, create, cancel = (
        QtWidgets.QPushButton(text) for text in ("Select", "Create", "Cancel")
    )
    for button, name in ((select, "select"), (create, "create"), (cancel, "cancel")):
        button.clicked.connect(lambda _checked=False, name=name: pressed.append(name))
    layout = QtWidgets.QVBoxLayout(dialog)
    layout.addWidget(table)
    layout.addWidget(
        NativeLook.button_box(accept=[select], reject=[cancel], actions=[create], default=select)
    )

    _press_return_in(dialog, table)

    assert pressed == ["select"]


def test_a_cell_without_text_does_not_break_fitting_or_painting(app):
    from PySide6.QtCore import Qt

    view = MatchTableView()
    view.table_model.address_font = view.font()
    view.table_model.reset(["User", "Last"], [MatchRow(0, None, [None, "x"], [None, "x"])])

    view.resizeColumnsToContents()

    assert view.table_model.data(view.table_model.index(0, 0), Qt.FontRole) is None
