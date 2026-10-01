"""Function Scope's table of matches: a model holding one row per match, and the view showing it.

A QTableWidget needed an item per cell, each colored on its own, so a function with hundreds of
matches took about half a second to show. The model computes a row's texts once and the view asks
only for the cells in view."""

import mcrit_plugin.core.McritTableColumn as McritTableColumn
import mcrit_plugin.ui_qt.QtShim as QtShim

QtCore = QtShim.get_QtCore()
Qt = QtShim.get_Qt()
QtWidgets = QtShim.get_QtWidgets()
QAbstractTableModel = QtCore.QAbstractTableModel
QTableView = QtWidgets.QTableView


class MatchRow:
    """One match with the text and the sort value of each column."""

    __slots__ = ("source_row", "match", "texts", "sort_keys", "background")

    def __init__(self, source_row, match, texts, sort_keys, background):
        # the position the row was filled in at, which sorting leaves alone
        self.source_row = source_row
        self.match = match
        self.texts = texts
        self.sort_keys = sort_keys
        self.background = background


class MatchTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.headers = []
        self.rows = []
        self.foreground = None
        # rows stay in the order they were filled in until a header is clicked
        self._sort = None

    def reset(self, headers, rows, foreground=None):
        self.beginResetModel()
        self.headers = headers
        self.rows = rows
        self.foreground = foreground
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
        # the view sorts by its header's indicator when sorting is enabled, which starts out
        # past the last column
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
        if role == Qt.BackgroundRole:
            return row.background
        if role == Qt.ForegroundRole:
            return self.foreground
        return None

    def matchAt(self, row):
        """The match shown in a row of the view."""
        return self.rows[row].match


class MatchTableView(QTableView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.table_model = MatchTableModel(self)
        self.setModel(self.table_model)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.horizontalHeader().setResizeContentsPrecision(McritTableColumn.FIT_COLUMNS_TO_ROWS)
        self.setSortingEnabled(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
