"""The tables of Function Scope, Block Scope and Sample Info: a model holding one row per match,
block, label, family or sample, and the view showing it.

A QTableWidget needed an item per cell, each colored on its own, so a function with hundreds of
matches took about half a second to show. The model computes a row's texts once and the view asks
only for the cells in view."""

import mcrit_plugin.core.McritTableColumn as McritTableColumn
import mcrit_plugin.ui_qt.QtShim as QtShim

QtCore = QtShim.get_QtCore()
Qt = QtShim.get_Qt()
QtWidgets = QtShim.get_QtWidgets()
QAbstractTableModel = QtCore.QAbstractTableModel
QItemSelection = QtCore.QItemSelection
QItemSelectionModel = QtCore.QItemSelectionModel
# PySide6 scopes the selection flags in an enum class; PyQt5 keeps them on the class
SelectionFlag = getattr(QItemSelectionModel, "SelectionFlag", QItemSelectionModel)
QTableView = QtWidgets.QTableView


class MatchRow:
    """What a row shows, a match, block, label, family or sample, with the text and the sort value of
    each column."""

    __slots__ = ("source_row", "entry", "texts", "sort_keys", "background")

    def __init__(self, source_row, entry, texts, sort_keys, background=None):
        # the position the row was filled in at, which sorting leaves alone
        self.source_row = source_row
        self.entry = entry
        self.texts = texts
        self.sort_keys = sort_keys
        self.background = background


class MatchTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.headers = []
        self.rows = []
        self.foreground = None
        self.alignment = None
        # rows stay in the order they were filled in until a header is clicked
        self._sort = None

    def reset(self, headers, rows, foreground=None, alignment=None):
        self.beginResetModel()
        self.headers = headers
        self.rows = rows
        self.foreground = foreground
        self.alignment = None if alignment is None else int(alignment)
        if self._sort is not None:
            self._sortRows(*self._sort)
        self.endResetModel()

    def _sortRows(self, column, order):
        if 0 <= column < len(self.headers):
            self.rows.sort(
                key=lambda row: row.sort_keys[column], reverse=order == Qt.DescendingOrder
            )

    def sort(self, column, order=Qt.AscendingOrder):
        """Sort by the value a column sorts by, not by the text it shows; the view's selection
        follows its rows."""
        # the view asks for the header's sort indicator, which is cleared until a click
        if not 0 <= column < len(self.headers):
            return
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

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        if role == Qt.DisplayRole:
            return row.texts[index.column()]
        if role == Qt.TextAlignmentRole:
            return self.alignment
        if role == Qt.BackgroundRole:
            return row.background
        if role == Qt.ForegroundRole and row.background is not None:
            # the text color suits the tints; an untinted row keeps the style's
            return self.foreground
        return None

    def entryAt(self, row):
        """The match or block shown in a row of the view."""
        return self.rows[row].entry

    def positionOf(self, source_row):
        """Where the row filled in at source_row is shown, after any sorting."""
        for position, row in enumerate(self.rows):
            if row.source_row == source_row:
                return position
        return None


class MatchTableView(QTableView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.table_model = MatchTableModel(self)
        self.setModel(self.table_model)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.horizontalHeader().setResizeContentsPrecision(McritTableColumn.FIT_COLUMNS_TO_ROWS)
        self.setSortingEnabled(True)
        # rows come in a meaningful order; no arrow claims a column sort until one is clicked
        self.horizontalHeader().setSortIndicator(-1, Qt.DescendingOrder)
        self.setContextMenuPolicy(Qt.CustomContextMenu)

    def selectEntireRow(self, row):
        """Highlight a whole row; selectRow does nothing while clicks select single cells."""
        model = self.table_model
        selection_model = self.selectionModel()
        selection_model.setCurrentIndex(model.index(row, 0), SelectionFlag.NoUpdate)
        selection_model.select(
            QItemSelection(model.index(row, 0), model.index(row, model.columnCount() - 1)),
            SelectionFlag.ClearAndSelect,
        )
