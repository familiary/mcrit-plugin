import traceback

# binaryninjaui must be imported before PySide6 so Binary Ninja's bundled Qt binding is used
from binaryninjaui import (
    Menu,
    Sidebar,
    SidebarContextSensitivity,
    SidebarWidget,
    SidebarWidgetLocation,
    SidebarWidgetType,
    UIAction,
    UIActionHandler,
    UIContext,
    UIContextNotification,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QImage, QPainter
from PySide6.QtWidgets import QFrame, QScrollArea, QVBoxLayout, QWidget

from mcrit_plugin.binja.BinjaBackend import BinjaBackend, logger
from mcrit_plugin.binja.config import clear_stored_secrets, config
from mcrit_plugin.ui_qt.McritSession import McritSession

SIDEBAR_NAME = "MCRIT"
_SIDEBAR_WIDGETS = []


class McritSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, bv):
        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.backend = BinjaBackend(bv)
        self.backend.view_frame = frame
        self.session = McritSession(self.backend, config)
        # below the widgets' minimum size their layouts overlap; the scroll area keeps that minimum
        self.session.parent = QWidget()
        self.session.setupWidgets()
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setWidget(self.session.parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll_area)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(150)
        self._refresh_timer.timeout.connect(
            lambda: self.session.refreshCursorWidgets(self.backend.cursor_offset)
        )
        _SIDEBAR_WIDGETS.append(self)
        self.destroyed.connect(lambda: _forget(self))
        if config.AUTO_ANALYZE_SMDA_ON_STARTUP:
            self.session.main_widget._onConvertSmdaButtonClicked()

    def notifyViewChanged(self, view_frame):
        self.backend.view_frame = view_frame

    def notifyOffsetChanged(self, offset):
        # coalesce rapid cursor moves; live queries hit the MCRIT server
        self.backend.cursor_offset = offset
        self._refresh_timer.start()

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


def _forget(widget):
    # background results must not reach the destroyed Qt widgets behind this session
    widget.backend.closed = True
    if widget in _SIDEBAR_WIDGETS:
        _SIDEBAR_WIDGETS.remove(widget)


def _sidebar_icon():
    """Grayscale 56x56 mask of the MCRIT logo; Binary Ninja tints white shapes to the theme."""
    source = QImage(config.ICON_FILE_PATH + "mcrit.png")
    if source.isNull():
        logger.log_warn(f"MCRIT sidebar icon not found: {config.ICON_FILE_PATH}mcrit.png")
    logo = source.scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    mask = QImage(56, 56, QImage.Format_ARGB32)
    mask.fill(Qt.transparent)
    painter = QPainter(mask)
    painter.drawImage((56 - logo.width()) // 2, (56 - logo.height()) // 2, logo)
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(mask.rect(), Qt.white)
    painter.end()
    icon = QImage(56, 56, QImage.Format_RGB32)
    icon.fill(Qt.black)
    painter = QPainter(icon)
    painter.drawImage(0, 0, mask)
    painter.end()
    return icon


class McritSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        SidebarWidgetType.__init__(self, _sidebar_icon(), SIDEBAR_NAME)

    def createWidget(self, frame, data):
        # exceptions raised here are swallowed by the sidebar, leaving an empty panel
        try:
            return McritSidebarWidget(SIDEBAR_NAME, frame, data)
        except Exception:
            logger.log_error(f"Failed to create the MCRIT sidebar:\n{traceback.format_exc()}")
            raise

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        # PerTabSidebarContext from Python only shows an invalid-context placeholder; createWidget is never called
        return SidebarContextSensitivity.PerViewTypeSidebarContext


class McritContextNotification(UIContextNotification):
    def OnAddressChange(self, context, frame, view, location):
        # navigation from the Symbols pane reaches the sidebar only through this global notification
        if view is None or location is None or not location.isValid():
            return
        widget = _widget_for_view(view.getData())
        if widget is not None:
            widget.notifyOffsetChanged(location.getOffset())

    def OnBeforeCloseFile(self, context, file, frame):
        if not config.SUBMIT_FUNCTION_NAMES_ON_CLOSE:
            return True
        session_id = file.getMetadata().session_id
        # each view type of the file has its own session and report, so each gets its own prompt
        for widget in list(_SIDEBAR_WIDGETS):
            if (
                widget.backend.bv.file.session_id != session_id
                or widget.session.local_smda_report is None
            ):
                continue
            session = widget.session
            if session.findUnsyncedFunctionNames() and widget.backend.ask_yes_no(
                "Function names changed since the SMDA report was created. "
                "Upload an updated report to the MCRIT server before closing? "
                "Binary Ninja will wait for the upload to finish."
            ):
                session.uploadUpdatedReport()
        return True


def _activate_sidebar(context):
    """Open the MCRIT sidebar for the action's view."""
    ui_context = context.context or UIContext.activeContext()
    if ui_context is None:
        return False
    sidebar = ui_context.sidebar()
    if sidebar is None:
        return False
    sidebar.activate(SIDEBAR_NAME)
    return True


def _session_for(context):
    """Open the MCRIT sidebar for the action's view and return its session."""
    if context.binaryView is None or not _activate_sidebar(context):
        return None
    widget = _widget_for_view(context.binaryView)
    if widget is None:
        logger.log_warn("No MCRIT sidebar for the current view; open the MCRIT sidebar and retry.")
        return None
    return widget.session


def _widget_for_view(bv):
    # per-view-type sidebars: the Raw and PE views of one file share a session_id
    for widget in _SIDEBAR_WIDGETS:
        widget_bv = widget.backend.bv
        if widget_bv.file.session_id == bv.file.session_id and widget_bv.view_type == bv.view_type:
            return widget
    return None


def _has_report(session):
    return session.local_smda_report is not None


# (action name, handler(session) or None to only open the sidebar, enabled(session) or None when always available)
_ACTIONS = [
    ("MCRIT\\Show Sidebar", None, None),
    (
        "MCRIT\\Convert to SMDA Report",
        lambda session: session.main_widget._onConvertSmdaButtonClicked(),
        None,
    ),
    (
        "MCRIT\\Upload SMDA Report",
        lambda session: session.main_widget._onUploadSmdaButtonClicked(),
        lambda session: session.main_widget.uploadSmdaAction.isEnabled(),
    ),
    (
        "MCRIT\\Fetch Matching Result",
        lambda session: session.main_widget._onGetMatchResultButtonClicked(),
        lambda session: session.main_widget.getMatchResultAction.isEnabled(),
    ),
    (
        "MCRIT\\Export SMDA Report...",
        lambda session: session.main_widget._onExportSmdaButtonClicked(),
        lambda session: session.main_widget.exportSmdaAction.isEnabled(),
    ),
    (
        "MCRIT\\Build YARA String from Selection",
        lambda session: session.main_widget._onBuildYaraStringButtonClicked(),
        lambda session: session.main_widget.buildYaraStringAction.isEnabled(),
    ),
    (
        "MCRIT\\Query Current Function",
        lambda session: session.function_match_widget.queryCurrentFunction(),
        _has_report,
    ),
    (
        "MCRIT\\Query Current Block",
        lambda session: session.block_match_widget.queryCurrentBlock(),
        _has_report,
    ),
]


def _register_global_actions():
    name = "MCRIT\\Clear Stored API Token"
    UIAction.registerAction(name)
    UIActionHandler.globalActions().bindAction(
        name, UIAction(lambda context: clear_stored_secrets())
    )
    Menu.mainMenu("Plugins").addAction(name, "MCRIT")


def _register_actions():
    for name, handler, enabled in _ACTIONS:

        def activate(context, handler=handler):
            if handler is None:
                _activate_sidebar(context)
                return
            session = _session_for(context)
            if session is not None:
                handler(session)

        def is_valid(context, enabled=enabled):
            if context.binaryView is None:
                return False
            if enabled is None:
                return True
            widget = _widget_for_view(context.binaryView)
            return widget is not None and enabled(widget.session)

        UIAction.registerAction(name)
        UIActionHandler.globalActions().bindAction(name, UIAction(activate, is_valid))
        Menu.mainMenu("Plugins").addAction(name, "MCRIT")


_context_notification = None


def register():
    global _context_notification
    if _context_notification is not None:
        return
    Sidebar.addSidebarWidgetType(McritSidebarWidgetType())
    _register_actions()
    _register_global_actions()
    _context_notification = McritContextNotification()
    UIContext.registerNotification(_context_notification)
