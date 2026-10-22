"""The MCRIT window of a Ghidra tool: one docked provider, one session per open program.

The provider shows the session of the active program. Cursor moves reach the session's Block and
Function Scope tabs after they settle, closing a program ends its session (offering to upload
renamed functions first when submit_function_names_on_close is set).

PyGhidra unloads a script's imported modules when the script ends, so the controllers are kept on
the sys module, which it never unloads; running the script again finds the tool's controller.
"""

import sys
import traceback

from jpype import JImplements, JOverride

from mcrit_plugin.ghidra import swing

REGISTRY_ATTRIBUTE = "_mcrit_ghidra_controllers"
WINDOW_NAME = "MCRIT"
CURSOR_SETTLE_MS = 150


def _registry():
    registry = getattr(sys, REGISTRY_ATTRIBUTE, None)
    if registry is None:
        registry = {}
        setattr(sys, REGISTRY_ATTRIBUTE, registry)
    return registry


def controller_for(tool):
    """The tool's controller, created on first use; call on the Swing thread."""
    registry = _registry()
    key = int(tool.hashCode()), str(tool.getName())
    controller = registry.get(key)
    if controller is None or controller.disposed:
        controller = McritToolController(tool, key)
        registry[key] = controller
    return controller


@JImplements("ghidra.framework.plugintool.util.PluginEventListener", deferred=True)
class _EventListener:
    def __init__(self, controller):
        self.controller = controller

    @JOverride
    def eventSent(self, event):
        try:
            self.controller.on_event(event)
        except Exception:
            traceback.print_exc()


@JImplements("mcrit.ghidra.McritComponentProvider$Listener", deferred=True)
class _ProviderListener:
    def __init__(self, controller):
        self.controller = controller

    @JOverride
    def shown(self):
        self.controller.visible = True

    @JOverride
    def hidden(self):
        self.controller.visible = False


class _SessionEntry:
    def __init__(self, program, backend, session):
        self.program = program
        self.backend = backend
        self.session = session


class McritToolController:
    def __init__(self, tool, key):
        from java.awt import BorderLayout, CardLayout
        from javax.swing import JPanel, Timer

        from mcrit_plugin.ghidra import bridge
        from mcrit_plugin.ghidra.ui.components import load_icon

        self.tool = tool
        self.key = key
        self.disposed = False
        self.visible = False
        self.entries = {}
        self.active_key = None
        self.cards = CardLayout()
        self.container = JPanel(self.cards)
        from java.awt import Dimension

        # Ghidra sizes a new dock from this; the overview's controls need about this much width
        self.container.setPreferredSize(Dimension(560, 760))
        self.placeholder = JPanel(BorderLayout())
        self._placeholder_program = None
        self._build_placeholder()
        self.container.add(self.placeholder, "placeholder")
        from mcrit_plugin.core.config import ICON_FILE_PATH

        provider_class = bridge.provider_class()
        if provider_class is None:
            raise RuntimeError(
                "The MCRIT window needs its Java bridge, which could not be compiled; "
                "see the console. Ghidra must run on a JDK."
            )
        self.provider = provider_class(
            tool, WINDOW_NAME, "MCRIT", self.container, load_icon(ICON_FILE_PATH + "mcrit.png", 16)
        )
        self._provider_listener = _ProviderListener(self)
        self.provider.setListener(self._provider_listener)
        from docking.action.builder import ActionBuilder

        # in the window's own menu, like Binary Ninja's MCRIT > Clear Match Coloring
        self._clear_coloring_action = (
            ActionBuilder("Clear Match Coloring", WINDOW_NAME)
            .menuPath("Clear Match Coloring")
            .description("Remove the tint MCRIT put on matched blocks in the listing.")
            .onAction(swing.Consumer(lambda _context: self._clear_coloring()))
            .buildAndInstallLocal(self.provider)
        )
        self._event_listener = _EventListener(self)
        tool.addListenerForAllPluginEvents(self._event_listener)
        self._settle_timer = Timer(
            CURSOR_SETTLE_MS, swing.ActionListener(lambda _e: self._cursor_settled())
        )
        self._settle_timer.setRepeats(False)

    # placeholder for programs without a session

    def _build_placeholder(self):
        from java.awt import BorderLayout

        from mcrit_plugin.ghidra.ui.components import Label, button, stack

        self._placeholder_label = Label("No program is open.")
        self._placeholder_button = button("Open MCRIT for this program", self._open_placeholder)
        self._placeholder_button.setVisible(False)
        self.placeholder.add(
            stack(self._placeholder_label.component, self._placeholder_button), BorderLayout.NORTH
        )

    def _open_placeholder(self):
        if self._placeholder_program is not None:
            self.show(self._placeholder_program)

    def _show_placeholder(self, program):
        self._placeholder_program = program
        if program is None:
            self._placeholder_label.setText("No program is open.")
            self._placeholder_button.setVisible(False)
        else:
            self._placeholder_label.setText(
                "MCRIT is not open for %s yet." % program.getDomainFile().getName()
            )
            self._placeholder_button.setVisible(True)
        self.active_key = None
        self.cards.show(self.container, "placeholder")

    # sessions

    @staticmethod
    def _program_key(program):
        return int(program.getUniqueProgramID())

    def show(self, program, cursor_offset=None):
        """Show the session of program, creating it on first use, and bring the window up."""
        key = self._program_key(program)
        entry = self.entries.get(key)
        if entry is None:
            entry = self._create_session(program, cursor_offset)
            self.entries[key] = entry
            self.container.add(entry.session.component, str(key))
        self.active_key = key
        self.cards.show(self.container, str(key))
        self.provider.setVisible(True)
        self.provider.toFront()
        return entry.session

    def _create_session(self, program, cursor_offset):
        from mcrit_plugin.ghidra.config import make_config
        from mcrit_plugin.ghidra.GhidraBackend import GhidraBackend
        from mcrit_plugin.ghidra.ui.GhidraSession import GhidraSession

        backend = GhidraBackend(program, self.tool)
        backend.parent_component = self.container
        backend.cursor_offset = cursor_offset
        session = GhidraSession(backend, make_config(self.tool))
        if cursor_offset is not None:
            session.current_function = backend.get_current_function(cursor_offset)
        session.setupWidgets()
        if session.config.AUTO_ANALYZE_SMDA_ON_STARTUP:
            session.main_widget._onConvertSmdaButtonClicked()
        return _SessionEntry(program, backend, session)

    def _clear_coloring(self):
        entry = self.entries.get(self.active_key)
        if entry is not None:
            entry.backend.clear_local_match_coloring()

    def session_for(self, program):
        entry = self.entries.get(self._program_key(program))
        return entry.session if entry is not None else None

    def _close_session(self, program):
        key = self._program_key(program)
        entry = self.entries.pop(key, None)
        if entry is None:
            return
        session = entry.session
        try:
            if (
                session.config.SUBMIT_FUNCTION_NAMES_ON_CLOSE
                and session.local_smda_report is not None
                and session.findUnsyncedFunctionNames()
                and entry.backend.ask_yes_no(
                    "Function names changed since the SMDA report was created. Upload an updated "
                    "report to the MCRIT server before closing?"
                )
            ):
                session.uploadUpdatedReport()
        except Exception:
            traceback.print_exc()
        entry.backend.close()
        self.container.remove(session.component)
        if self.active_key == key:
            self._show_placeholder(None)

    # events

    def on_event(self, event):
        from ghidra.app.events import (
            ProgramActivatedPluginEvent,
            ProgramClosedPluginEvent,
            ProgramLocationPluginEvent,
        )

        if isinstance(event, ProgramLocationPluginEvent):
            self._on_location(event)
        elif isinstance(event, ProgramActivatedPluginEvent):
            program = event.getActiveProgram()
            if program is None:
                self._show_placeholder(None)
                return
            key = self._program_key(program)
            if key in self.entries:
                self.active_key = key
                self.cards.show(self.container, str(key))
            else:
                self._show_placeholder(program)
        elif isinstance(event, ProgramClosedPluginEvent):
            self._close_session(event.getProgram())

    def _on_location(self, event):
        location = event.getLocation()
        program = event.getProgram()
        if location is None or program is None:
            return
        entry = self.entries.get(self._program_key(program))
        address = location.getAddress()
        if entry is None or address is None:
            return
        if address.getAddressSpace() != program.getAddressFactory().getDefaultAddressSpace():
            return
        entry.backend.cursor_offset = int(address.getOffset())
        # coalesce rapid cursor moves; live queries hit the MCRIT server
        self._pending = entry
        self._settle_timer.restart()

    def _cursor_settled(self):
        entry = getattr(self, "_pending", None)
        self._pending = None
        if entry is None or entry.backend.closed:
            return
        entry.session.refreshCursorWidgets(entry.backend.cursor_offset)

    def dispose(self):
        """Close every session and the window, e.g. before reloading the plugin."""
        for entry in list(self.entries.values()):
            self._close_session(entry.program)
        self.tool.removeListenerForAllPluginEvents(self._event_listener)
        self.provider.removeFromTool()
        self.disposed = True
        _registry().pop(self.key, None)
