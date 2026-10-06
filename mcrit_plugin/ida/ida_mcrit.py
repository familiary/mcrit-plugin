#!/usr/bin/python
"""
MCRIT4IDA - integration with MCRIT server
code inspired by and based on IDAscope
"""

import time
import traceback

import ida_idaapi
import ida_kernwin
from ida_kernwin import PluginForm

from mcrit_plugin.ida.config import config
from mcrit_plugin.ui_qt.McritSession import McritSession

IdaBackend = None


def _require_gui():
    """Fail clearly when a GUI-only plugin action is invoked through IDALib."""
    is_idaq = getattr(ida_kernwin, "is_idaq", None)
    if not callable(is_idaq) or not is_idaq():
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
        self._view_title = None
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
        self._view_title = ida_kernwin.get_widget_title(view)
        self._last_move = time.monotonic()
        if self._timer is None:
            self._timer = ida_kernwin.register_timer(CURSOR_SETTLE_MS, self._on_cursor_settled)

    def _on_cursor_settled(self):
        remaining = CURSOR_SETTLE_MS - int((time.monotonic() - self._last_move) * 1000)
        if remaining > 0:
            return remaining
        self._timer = None
        # the view may have closed meanwhile, so it is looked up again instead of kept;
        # find_widget only finds tabbed widgets, a floating view is usually the current one
        view = ida_kernwin.get_current_widget()
        if view is None or ida_kernwin.get_widget_title(view) != self._view_title:
            view = ida_kernwin.find_widget(self._view_title) if self._view_title else None
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


class Mcrit4IdaPlugmod(ida_idaapi.plugmod_t):
    """Per-database plugin instance (PLUGIN_MULTI); owns the form it opened."""

    def __init__(self):
        super().__init__()
        self.form = None

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
