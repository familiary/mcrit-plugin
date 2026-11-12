#!/usr/bin/python
"""
MCRIT4IDA - integration with MCRIT server
code inspired by and based on IDAscope
"""

import time
import traceback
import weakref

import ida_idaapi
import ida_kernwin
from ida_kernwin import PluginForm

from mcrit_plugin.ida.config import config
from mcrit_plugin.ui_qt.McritSession import McritSession

IdaBackend = None


def _has_gui():
    is_idaq = getattr(ida_kernwin, "is_idaq", None)
    return callable(is_idaq) and bool(is_idaq())


def _require_gui():
    """Fail clearly when a GUI-only plugin action is invoked through IDALib."""
    if not _has_gui():
        raise RuntimeError("MCRIT4IDA's Qt interface requires the IDA GUI")


def _load_dependencies():
    """Load the IDA backend only when the form is opened; Qt and widgets load in McritSession."""
    _require_gui()
    global IdaBackend

    if IdaBackend is not None:
        return

    from mcrit_plugin.ida.IdaBackend import IdaBackend as _IdaBackend

    IdaBackend = _IdaBackend


################################################################################
# Core of the MCRIT4IDA GUI.
################################################################################

MCRIT4IDA = None
NAME = "MCRIT4IDA v%s" % config.VERSION
CURSOR_SETTLE_MS = 150


class IdaViewHooks(ida_kernwin.View_Hooks):
    """
    Courtesy of Alex Hanel's FunctionTrapperKeeper
    https://github.com/alexander-hanel/FunctionTrapperKeeper/blob/main/function_trapper_keeper.py
    """

    def __init__(self, form):
        super().__init__()
        self.form = form
        # titles of the views that reported a cursor move since the last refresh, oldest first
        self._view_titles = []
        self._last_move = 0.0
        self._timer = None

    def view_curpos(self, view):
        self._schedule_refresh(view)

    def view_dblclick(self, view, event):
        self._schedule_refresh(view)

    def view_click(self, view, event):
        self._schedule_refresh(view)

    def view_loc_changed(self, view, now, was):
        self._schedule_refresh(view)

    def _schedule_refresh(self, view):
        # coalesce rapid cursor moves like the Binary Ninja sidebar; live queries hit the MCRIT server
        title = ida_kernwin.get_widget_title(view)
        # a hex or graph view reporting next must not hide a move in the disassembly
        if title not in self._view_titles:
            self._view_titles.append(title)
        self._last_move = time.monotonic()
        if self._timer is None:
            self._timer = ida_kernwin.register_timer(CURSOR_SETTLE_MS, self._on_cursor_settled)

    def _on_cursor_settled(self):
        remaining = CURSOR_SETTLE_MS - int((time.monotonic() - self._last_move) * 1000)
        if remaining > 0:
            return remaining
        self._timer = None
        titles, self._view_titles = self._view_titles, []
        current = ida_kernwin.get_current_widget()
        for title in titles:
            # the view may have closed meanwhile, so it is looked up again instead of kept;
            # find_widget only finds tabbed widgets, a floating view is usually the current one
            if current is not None and ida_kernwin.get_widget_title(current) == title:
                view = current
            else:
                view = ida_kernwin.find_widget(title) if title else None
            if view is not None:
                try:
                    self.refresh_widget(view)
                except Exception:
                    traceback.print_exc()
        return -1  # unregisters the timer

    def unhook(self):
        if self._timer is not None:
            ida_kernwin.unregister_timer(self._timer)
            self._timer = None
        return super().unhook()

    def refresh_widget(self, view):
        if not self.form:
            return
        for widget in self.form.hook_subscribed_widgets:
            widget.hook_refresh(view)


class Mcrit4IdaForm(PluginForm, McritSession):
    """
    This class contains the main window of MCRIT4IDA
    Setup of core modules and widgets is performed in here.
    """

    def __init__(self):
        _load_dependencies()
        PluginForm.__init__(self)
        McritSession.__init__(self, IdaBackend(), config)
        self.view_hook = None
        self.released = False

    def OnCreate(self, form):
        """
        When creating the form, setup the shared modules and widgets
        """
        print("[+] Loading MCRIT4IDA")
        self.view_hook = IdaViewHooks(self)
        self.view_hook.hook()
        self.parent = self.FormToPyQtWidget(form)
        self.parent.setWindowIcon(self.icon)
        self.setupWidgets()
        if self.config.AUTO_ANALYZE_SMDA_ON_STARTUP:
            # simulate button click on "Convert IDB to SMDA" to capture potential family info
            print("Performing automatic SMDA analysis on startup...")
            self.main_widget._onConvertSmdaButtonClicked()

    def OnClose(self, form):
        """
        Perform cleanup.
        """
        # check if there is a mismatch between function names stored in self.local_smda_report and the actual IDB
        # if yes, ask the user if they want to upload an updated report to the MCRIT server
        if config.SUBMIT_FUNCTION_NAMES_ON_CLOSE:
            print("Checking for unsynced function names...")
            if self.findUnsyncedFunctionNames() and self.cc.backend.ask_yes_no(
                "There are new function name changes in the IDB. Do you want to upload an updated report to the MCRIT server before closing?"
            ):
                self.uploadUpdatedReport()
        self.release()

    def release(self):
        """Unhook and drop module references; safe to call more than once."""
        self.released = True
        self.cc.backend.close()
        if self.view_hook is not None:
            self.view_hook.unhook()
            self.view_hook = None
        self.hook_subscribed_widgets = []
        global MCRIT4IDA
        if MCRIT4IDA is self:
            MCRIT4IDA = None

    def Show(self):
        if self.cc.backend.get_input_md5() is not None:
            # Show() takes WOPN_* flags and adds WOPN_RESTORE itself
            return PluginForm.Show(self, NAME, options=PluginForm.WOPN_PERSIST)
        return None


################################################################################
# Usage as plugin
################################################################################


def PLUGIN_ENTRY():
    return Mcrit4IdaPlugin()


def show_mcrit_form():
    """Create and show a form, returning it, or None when it cannot be shown."""
    try:
        _require_gui()
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return None
    try:
        form = Mcrit4IdaForm()
    except ImportError as exc:
        ida_kernwin.warning(str(exc))
        return None
    if not form.Show():
        try:
            form.release()
        except Exception as exc:
            print(f"[!] Error closing MCRIT4IDA after failed show: {exc}")
        return None
    return form


SETTINGS_ACTION = "mcrit4ida:settings"
CLEAR_COLORING_ACTION = "mcrit4ida:clear_coloring"
# the open database's plugmod; weak, so a database that closes takes its plugmod and form along
_current_plugmod = None


def _open_settings(plugmod):
    plugmod.run(0)
    if plugmod.form is not None:
        plugmod.form.main_widget._onSettingsButtonClicked()


def _clear_coloring(plugmod):
    if plugmod.form is not None:
        plugmod.form.cc.backend.clear_local_match_coloring()


# (action name, menu label, tooltip, what it does with the current database's plugmod)
MENU_ACTIONS = [
    (
        SETTINGS_ACTION,
        "MCRIT4IDA Settings...",
        "Set the MCRIT server, API token and other plugin settings.",
        _open_settings,
    ),
    (
        CLEAR_COLORING_ACTION,
        "MCRIT4IDA Clear Match Coloring",
        "Remove the tint MCRIT put on matched blocks in the disassembly.",
        _clear_coloring,
    ),
]


def _register_menu_actions():
    """The Edit > Plugins entries beside the plugin's own one. Registered once per IDA process
    and never removed: a plugmod's __del__ may run late, after the next database's plugmod
    exists, so tying them to a plugmod could remove the next database's entries."""

    class Handler(ida_kernwin.action_handler_t):
        def __init__(self, act):
            super().__init__()
            self.act = act

        def activate(self, ctx):
            current = _current_plugmod() if _current_plugmod is not None else None
            if current is not None:
                self.act(current)
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    for name, label, tooltip, act in MENU_ACTIONS:
        # registering fails once the action exists, e.g. for the second database
        if ida_kernwin.register_action(
            ida_kernwin.action_desc_t(name, label, Handler(act), None, tooltip, -1)
        ):
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", name, ida_kernwin.SETMENU_APP)


class Mcrit4IdaPlugmod(ida_idaapi.plugmod_t):
    """Per-database plugin instance (PLUGIN_MULTI); owns the form it opened."""

    def __init__(self):
        global _current_plugmod
        super().__init__()
        self.form = None
        if _has_gui():
            _current_plugmod = weakref.ref(self)
            _register_menu_actions()

    def run(self, arg):
        # a closed form still holds the previous session's reports, so reopening needs a new form
        if self.form is None or self.form.released:
            self.form = show_mcrit_form()
        else:
            self.form.Show()
        return True

    def __del__(self):
        # called when the database closes; IDA normally closes the form first (OnClose -> release)
        if self.form is not None:
            self.form.release()
            self.form = None


class Mcrit4IdaPlugin(ida_idaapi.plugin_t):
    """
    Plugin version of MCRIT4IDA. Use this to deploy MCRIT4IDA via IDA plugins folder.
    """

    flags = ida_idaapi.PLUGIN_MULTI
    comment = NAME
    help = "MCRIT4IDA - Plugin to interact with a MCRIT server."
    wanted_name = "MCRIT4IDA"
    wanted_hotkey = "Ctrl-F4"

    def init(self):
        return Mcrit4IdaPlugmod()


################################################################################
# Usage as script
################################################################################


def main():
    global MCRIT4IDA
    if MCRIT4IDA is not None:
        try:
            MCRIT4IDA.Close(PluginForm.WCLS_SAVE)
            print("reloading MCRIT4IDA")
        except Exception:
            pass
        MCRIT4IDA = None

    MCRIT4IDA = show_mcrit_form()


if __name__ == "__main__":
    main()
