"""The Function Overview's table: a model that holds and sorts the rows, a delegate that paints the
label column as a drop-down without creating a widget per row, and the view that hosts both.

Filling or filtering a result with thousands of rows only resets the model, and the view creates and
paints just the cells in view. A real combo box exists for one cell at a time, while the user edits
it."""

import mcrit_plugin.core.McritTableColumn as McritTableColumn
import mcrit_plugin.ui_qt.QtShim as QtShim
from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider, ThemeRole

QtCore = QtShim.get_QtCore()
Qt = QtShim.get_Qt()
QtWidgets = QtShim.get_QtWidgets()
QtGui = QtShim.get_QtGui()
QAbstractTableModel = QtCore.QAbstractTableModel
QTimer = QtCore.QTimer
QTableView = QtWidgets.QTableView
QComboBox = QtShim.get_QComboBox()
QStyle = QtShim.get_QStyle()
QStyledItemDelegate = QtShim.get_QStyledItemDelegate()

# an enum or of two flags costs microseconds a call, and data() runs per cell and role
ALIGN_CENTER = int(Qt.AlignHCenter | Qt.AlignVCenter)

# a role for the value a column sorts by, and one for the index of the entry a label cell shows
SORT_ROLE = Qt.UserRole + 1
SELECTED_ROLE = Qt.UserRole + 2

CRITICALITY_ROLES = {
    1: (ThemeRole.BLUE, (70, 120, 220)),
    2: (ThemeRole.CYAN, (70, 180, 70)),
    3: (ThemeRole.GREEN, (100, 255, 100)),
    4: (ThemeRole.YELLOW, (255, 255, 100)),
    5: (ThemeRole.RED, (255, 100, 100)),
}

NUMERIC_COLUMNS = (
    McritTableColumn.FAMILIES,
    McritTableColumn.SAMPLES,
    McritTableColumn.FUNCTIONS,
)


class OverviewRow:
    """One local function with its matches aggregated."""

    __slots__ = ("source_row", "offset", "texts", "sort_keys", "choices", "selected", "criticality")

    def __init__(self, source_row, offset, texts, sort_keys, choices, selected, criticality):
        # the position the row was filled in at, which sorting leaves alone
        self.source_row = source_row
        self.offset = offset
        # per column the text shown, and the value sorted by; the label column's come from choices
        self.texts = texts
        self.sort_keys = sort_keys
        # the entries of the label drop-down, "score|label" strings ending in the opt-out "-|-"
        self.choices = choices
        self.selected = selected
        self.criticality = criticality

    @property
    def selected_text(self):
        return self.choices[self.selected] if self.choices else "-"


def build_row(source_row, info, column_types, choices, selected):
    """The row of one aggregated function, see FunctionOverviewWidget.populateFunctionTable."""
    texts = []
    sort_keys = []
    for column_type in column_types:
        if column_type == McritTableColumn.OFFSET:
            text, key = "0x%x" % info["offset"], info["offset"]
        elif column_type == McritTableColumn.FAMILIES:
            text, key = "%d" % len(info["families"]), len(info["families"])
        elif column_type == McritTableColumn.SAMPLES:
            text, key = "%d" % len(info["samples"]), len(info["samples"])
        elif column_type == McritTableColumn.FUNCTIONS:
            text, key = "%d" % len(info["functions"]), len(info["functions"])
        elif column_type == McritTableColumn.IS_LIBRARY:
            text = "YES" if len(info["library_matches"]) > 0 else "NO"
            key = text
        else:
            text, key = "-", "-"
        texts.append(text)
        sort_keys.append(key)
    return OverviewRow(
        source_row, info["offset"], texts, sort_keys, choices, selected, info.get("criticality", 0)
    )


class OverviewTableModel(QAbstractTableModel):
    def __init__(self, backend=None, parent=None):
        super().__init__(parent)
        self.backend = backend
        self.headers = []
        self.column_types = []
        self.label_column = None
        self.rows = []
        # without any label on the server the label cells stay plain
        self.dropdowns = False
        self._colors = {}
        self._sort = (0, Qt.DescendingOrder)

    def reset(self, headers, column_types, label_column, rows, dropdowns):
        self.beginResetModel()
        self.headers = headers
        self.column_types = column_types
        self.label_column = label_column
        self.rows = rows
        self._sortRows(*self._sort)
        self.dropdowns = dropdowns
        self._colors = {}
        self.endResetModel()

    def _sortRows(self, column, order):
        if column < len(self.headers):
            if column == self.label_column:
                self.rows.sort(
                    key=lambda row: row.selected_text, reverse=order == Qt.DescendingOrder
                )
            else:
                self.rows.sort(
                    key=lambda row: row.sort_keys[column], reverse=order == Qt.DescendingOrder
                )

    def sort(self, column, order=Qt.AscendingOrder):
        """Sort by the value a column sorts by, not by the text it shows. Rows keep their
        source_row, and the view's selection follows them."""
        self._sort = (column, order)
        self.layoutAboutToBeChanged.emit()
        old_indexes = self.persistentIndexList()
        old_cells = [(self.rows[index.row()].source_row, index.column()) for index in old_indexes]
        self._sortRows(column, order)
        positions = {row.source_row: position for position, row in enumerate(self.rows)}
        self.changePersistentIndexList(
            old_indexes, [self.index(positions[source], column) for source, column in old_cells]
        )
        self.layoutChanged.emit()

    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.rows)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section] if section < len(self.headers) else None
        return super().headerData(section, orientation, role)

    def flags(self, index):
        flags = super().flags(index)
        if index.isValid() and self.isDropdown(index):
            flags |= Qt.ItemIsEditable
        return flags

    def isDropdown(self, index):
        return (
            self.dropdowns
            and index.column() == self.label_column
            and bool(self.rows[index.row()].choices)
        )

    def criticalityColors(self, criticality):
        """The background and text color of a drop-down with this criticality, or None."""
        if not criticality:
            return None
        if criticality not in self._colors:
            provider = ScoreColorProvider(self.backend)
            role, default = CRITICALITY_ROLES[min(criticality, 5)]
            background = QtGui.QColor(*provider.roleColor(role, default))
            text_color = provider.textOnTintColor()
            self._colors[criticality] = (
                background,
                QtGui.QColor(*text_color) if text_color else None,
            )
        return self._colors[criticality]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        is_label = column == self.label_column
        if role == Qt.DisplayRole:
            return row.selected_text if is_label else row.texts[column]
        if role == Qt.TextAlignmentRole:
            return ALIGN_CENTER
        if role == SORT_ROLE:
            return row.selected_text if is_label else row.sort_keys[column]
        if role == SELECTED_ROLE and is_label:
            return row.selected
        if is_label and self.isDropdown(index) and role in (Qt.BackgroundRole, Qt.ForegroundRole):
            colors = self.criticalityColors(row.criticality)
            if colors is not None:
                return colors[0] if role == Qt.BackgroundRole else colors[1]
        return None

    def setData(self, index, value, role=Qt.EditRole):
        if role != Qt.EditRole or not index.isValid() or not self.isDropdown(index):
            return False
        row = self.rows[index.row()]
        if isinstance(value, str):
            if value not in row.choices:
                return False
            value = row.choices.index(value)
        if not 0 <= value < len(row.choices):
            return False
        row.selected = value
        self.dataChanged.emit(index, index)
        return True


class LabelDelegate(QStyledItemDelegate):
    """Draws a label cell like a combo box and opens a real one when the cell is clicked."""

    def __init__(self, view, parent=None):
        super().__init__(parent)
        self.view = view

    def _isDropdown(self, index):
        return self.view.table_model.isDropdown(index)

    def paint(self, painter, option, index):
        if not self._isDropdown(index):
            super().paint(painter, option, index)
            return
        combo = QtWidgets.QStyleOptionComboBox()
        combo.rect = option.rect
        combo.state = option.state | QStyle.State_Enabled
        combo.currentText = index.data(Qt.DisplayRole)
        combo.editable = False
        combo.frame = True
        palette = QtGui.QPalette(option.palette)
        background = index.data(Qt.BackgroundRole)
        if background is not None:
            palette.setBrush(QtGui.QPalette.Button, background)
            foreground = index.data(Qt.ForegroundRole)
            if foreground is not None:
                palette.setBrush(QtGui.QPalette.ButtonText, foreground)
        combo.palette = palette
        widget = option.widget
        style = widget.style() if widget is not None else QtWidgets.QApplication.style()
        style.drawComplexControl(QStyle.CC_ComboBox, combo, painter, widget)
        style.drawControl(QStyle.CE_ComboBoxLabel, combo, painter, widget)

    def editorEvent(self, event, model, option, index):
        if (
            event.type() == QtCore.QEvent.MouseButtonRelease
            and event.button() == Qt.LeftButton
            and self._isDropdown(index)
        ):
            # editing from inside the event would replace the cell the view is still handling
            QTimer.singleShot(0, lambda: self.view.edit(index))
        return False

    def createEditor(self, parent, option, index):
        if not self._isDropdown(index):
            return None
        row = index.model().rows[index.row()]
        editor = QComboBox(parent)
        editor.addItems(row.choices)
        editor.activated.connect(lambda _: self._commit(editor))
        QTimer.singleShot(0, editor.showPopup)
        return editor

    def _commit(self, editor):
        self.commitData.emit(editor)
        self.closeEditor.emit(editor)

    def setEditorData(self, editor, index):
        editor.setCurrentIndex(index.data(SELECTED_ROLE))

    def setModelData(self, editor, model, index):
        model.setData(index, editor.currentIndex(), Qt.EditRole)


class OverviewTableView(QTableView):
    """The table of the Function Overview with its model and label delegate."""

    def __init__(self, backend=None, parent=None):
        super().__init__(parent)
        self.table_model = OverviewTableModel(backend, self)
        self.setModel(self.table_model)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setSortingEnabled(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.label_delegate = LabelDelegate(self, self)

    def setLabelColumn(self, column):
        for old_column in range(self.table_model.columnCount()):
            self.setItemDelegateForColumn(old_column, None)
        if column is not None:
            self.setItemDelegateForColumn(column, self.label_delegate)

    def sourceRow(self, row):
        """The position the row shown at this place was filled in at."""
        return self.table_model.rows[row].source_row

    def cellAtPosition(self, position):
        """The source row and column under a point of the view, or None."""
        index = self.indexAt(position)
        if not index.isValid():
            return None
        return self.sourceRow(index.row()), index.column()
