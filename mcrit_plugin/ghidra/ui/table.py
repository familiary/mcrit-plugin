"""Tables of the Ghidra frontend: rows are filled from Python in one call, the Java model keeps the
texts and sort keys, and a RowSorter orders the view (see McritTableModel.java).

MatchRow and the reset/entryAt/positionOf/selectEntireRow calls mirror the Qt MatchTableView, so the
panels read like their Qt counterparts.
"""

from jpype import JArray, JClass, JDouble, JLong, JObject, JString

from mcrit_plugin.ghidra import swing

LONG_MAX = (1 << 63) - 1


class MatchRow:
    """A row of a table: the entry it shows, the text and sort value per column, and an optional
    background as an (r, g, b) tuple."""

    __slots__ = ("source_row", "entry", "texts", "sort_keys", "background")

    def __init__(self, source_row, entry, texts, sort_keys, background=None):
        self.source_row = source_row
        self.entry = entry
        self.texts = texts
        self.sort_keys = sort_keys
        self.background = background


def java_color(rgb):
    if rgb is None:
        return None
    from java.awt import Color

    return Color(int(rgb[0]), int(rgb[1]), int(rgb[2]))


def _java_key(value):
    """A sort key as a Java object: numbers as Long (Double beyond its range), the rest as text."""
    if isinstance(value, bool):
        return JString("YES" if value else "NO")
    if isinstance(value, int):
        return JLong(value) if -LONG_MAX <= value <= LONG_MAX else JDouble(float(value))
    if isinstance(value, float):
        return JDouble(value)
    return JString("" if value is None else str(value))


class MatchTableView:
    def __init__(self, centered=False):
        self._model_class = JClass("mcrit.ghidra.McritTableModel")
        self._tables = JClass("mcrit.ghidra.McritTables")
        self.model = self._model_class()
        self.model.setCentered(centered)
        self.table = self._tables.create(self.model)
        from javax.swing import JScrollPane

        self.component = JScrollPane(self.table)
        self.rows = []
        # Qt-style access used by the panels: view.table_model.reset(...)
        self.table_model = self

    # filling

    def reset(self, headers, rows, foreground=None, alignment=None):
        self.rows = rows
        texts = JArray(JString, 2)([[str(text) for text in row.texts] for row in rows])
        keys = JArray(JObject, 2)([[_java_key(key) for key in row.sort_keys] for row in rows])
        backgrounds = JArray(JClass("java.awt.Color"))([java_color(row.background) for row in rows])
        self.model.reset(
            JArray(JString)([str(header) for header in headers]),
            texts,
            keys,
            backgrounds,
            java_color(foreground),
        )

    def set_choices(self, column, choices, backgrounds):
        """Per-row drop-down entries in one column; None leaves a row's cell plain."""
        self.model.setChoices(
            column,
            JArray(JString, 2)([None if entries is None else list(entries) for entries in choices]),
            JArray(JClass("java.awt.Color"))([java_color(rgb) for rgb in backgrounds]),
        )

    def fit_columns(self, max_width=400):
        self._tables.fitColumns(self.table, max_width)

    def sort_by(self, column, ascending):
        self._tables.sortBy(self.table, column, ascending)

    # rows

    def modelRow(self, view_row):
        if view_row < 0 or view_row >= self.table.getRowCount():
            return None
        return int(self.table.convertRowIndexToModel(view_row))

    def entryAt(self, view_row):
        model_row = self.modelRow(view_row)
        return self.rows[model_row].entry if model_row is not None else None

    def rowAt(self, view_row):
        model_row = self.modelRow(view_row)
        return self.rows[model_row] if model_row is not None else None

    def positionOf(self, source_row):
        """The model row of the row filled in at source_row; model rows keep their fill order."""
        return source_row if 0 <= source_row < len(self.rows) else None

    def selectEntireRow(self, model_row):
        if model_row is not None:
            self._tables.selectModelRow(self.table, model_row)

    def selectedEntry(self):
        return self.entryAt(int(self.table.getSelectedRow()))

    def cellText(self, model_row, column):
        return str(self.model.getText(model_row, column))

    # events

    def on_click(self, func):
        """func(view_row, model_column, click_count) for left clicks on a cell."""

        def clicked(event):
            from javax.swing import SwingUtilities

            if not SwingUtilities.isLeftMouseButton(event):
                return
            point = event.getPoint()
            view_row = int(self.table.rowAtPoint(point))
            view_column = int(self.table.columnAtPoint(point))
            if view_row < 0 or view_column < 0:
                return
            func(
                view_row,
                int(self.table.convertColumnIndexToModel(view_column)),
                event.getClickCount(),
            )

        self.table.addMouseListener(swing.MouseListener(on_click=clicked))

    def on_popup(self, func):
        """func(view_row, model_column) for a context click on a cell; the cell gets selected."""

        def popup(event):
            point = event.getPoint()
            view_row = int(self.table.rowAtPoint(point))
            view_column = int(self.table.columnAtPoint(point))
            if view_row < 0 or view_column < 0:
                return
            self.table.setRowSelectionInterval(view_row, view_row)
            func(view_row, int(self.table.convertColumnIndexToModel(view_column)))

        self.table.addMouseListener(swing.MouseListener(on_popup=popup))

    def on_selection(self, func):
        """func(view_row) when the selected row changes."""

        from jpype import JImplements, JOverride

        @JImplements("javax.swing.event.ListSelectionListener")
        class _Listener:
            @JOverride
            def valueChanged(self_, event):
                if event.getValueIsAdjusting():
                    return
                try:
                    func(int(self.table.getSelectedRow()))
                except Exception:
                    import traceback

                    traceback.print_exc()

        self._selection_listener = _Listener()
        self.table.getSelectionModel().addListSelectionListener(self._selection_listener)
