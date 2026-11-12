"""What makes the widgets sit in IDA and Binary Ninja like the hosts' own lists and dialogs. The
colors, fonts and metrics come from the host's Qt style; nothing here sets one of its own."""

import mcrit_plugin.ui_qt.QtShim as QtShim

QtWidgets = QtShim.get_QtWidgets()
QtGui = QtShim.get_QtGui()
QAbstractItemView = QtWidgets.QAbstractItemView
QDialogButtonBox = QtWidgets.QDialogButtonBox

# room a text line gets above and below in a table row
ROW_PADDING = 6

# backend.monospace_font, set by the session; the host's code font for addresses, where it has one
_monospace_font = None


def set_monospace_font_provider(provider):
    global _monospace_font
    _monospace_font = provider


def monospace_font(widget):
    """The host's code font, or the system's fixed-width one."""
    font = _monospace_font(widget) if _monospace_font is not None else None
    if font is None:
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
    return font


def address_font(widget):
    """The font for the values tables show as 0x..., addresses and block hashes: the host's code
    font where its own lists use it for them (Binary Ninja), else None for the table's font
    (IDA)."""
    return _monospace_font(widget) if _monospace_font is not None else None


def is_address(text):
    """A cell text the tables show as an address or a block hash."""
    return isinstance(text, str) and text[:2] == "0x"


def apply_table_look(view, row_height=None):
    """A list like the hosts' own: no row numbers and no grid, rows one text line high, the whole
    row selected, texts cut with an ellipsis instead of wrapped, and scrolling by pixels."""
    rows = view.verticalHeader()
    rows.hide()
    rows.setDefaultSectionSize(row_height or view.fontMetrics().height() + ROW_PADDING)
    view.setShowGrid(False)
    view.setWordWrap(False)
    view.setSelectionBehavior(QAbstractItemView.SelectRows)
    view.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    view.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    header = view.horizontalHeader()
    # no bold header over the column of the current cell
    header.setHighlightSections(False)
    header.setStretchLastSection(True)


def button_box(accept=(), reject=(), actions=(), default=None):
    """The dialog's buttons in the order the platform puts them, e.g. Cancel before OK on macOS.
    default is the button Return presses."""
    box = QDialogButtonBox()
    for buttons, role in (
        (actions, QDialogButtonBox.ActionRole),
        (accept, QDialogButtonBox.AcceptRole),
        (reject, QDialogButtonBox.RejectRole),
    ):
        for button in buttons:
            box.addButton(button, role)
            # a dialog makes the first auto-default button it finds its default when it shows,
            # whichever button was told to be the default before it had a dialog
            button.setAutoDefault(button is default)
            button.setDefault(button is default)
    # Tab follows the buttons as they are laid out, not as they were added
    layout = box.layout()
    shown = [layout.itemAt(index).widget() for index in range(layout.count())]
    shown = [widget for widget in shown if widget is not None]
    for first, second in zip(shown, shown[1:]):
        QtWidgets.QWidget.setTabOrder(first, second)
    return box
