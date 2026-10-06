"""Regression tests for the GUI-free plugin entry point."""

import importlib
import sys
import types
from unittest.mock import MagicMock


class _PluginT:
    """Minimal plugin base class for import-time tests."""


class _PlugmodT:
    """Minimal plugmod base class for import-time tests."""


class _PluginForm:
    """Minimal plugin form base class for import-time tests."""


class _ViewHooks:
    """Minimal view hooks base class for import-time tests."""

    def unhook(self):
        return True


def test_plugin_entry_defers_qt_imports(monkeypatch):
    """IDALib can load the plugin descriptor without importing any Qt binding."""
    monkeypatch.setitem(
        sys.modules,
        "ida_idaapi",
        types.SimpleNamespace(plugin_t=_PluginT, plugmod_t=_PlugmodT, PLUGIN_MULTI=1),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        types.SimpleNamespace(PluginForm=_PluginForm, is_idaq=lambda: False, View_Hooks=_ViewHooks),
    )
    monkeypatch.delitem(sys.modules, "mcrit_plugin.ida.ida_mcrit", raising=False)
    # the widget tests load PySide6 into this process; hide it so only the entry point's imports count
    for name in [name for name in sys.modules if name.startswith(("PySide", "PyQt", "shiboken"))]:
        monkeypatch.delitem(sys.modules, name)

    module = importlib.import_module("mcrit_plugin.ida.ida_mcrit")
    plugin = module.PLUGIN_ENTRY()

    assert plugin.wanted_name == "MCRIT4IDA"
    assert plugin.init() is not None
    assert module.show_mcrit_form() is None
    assert not any(name.startswith(("PySide", "PyQt")) for name in sys.modules)


def test_reopening_after_close_builds_a_new_form(monkeypatch):
    """Ctrl-F4 after closing the form must not bring back the previous session's reports."""
    monkeypatch.setitem(
        sys.modules,
        "ida_idaapi",
        types.SimpleNamespace(plugin_t=_PluginT, plugmod_t=_PlugmodT, PLUGIN_MULTI=1),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        types.SimpleNamespace(PluginForm=_PluginForm, is_idaq=lambda: False, View_Hooks=_ViewHooks),
    )
    monkeypatch.delitem(sys.modules, "mcrit_plugin.ida.ida_mcrit", raising=False)
    module = importlib.import_module("mcrit_plugin.ida.ida_mcrit")
    forms = []

    def show_form():
        forms.append(types.SimpleNamespace(released=False, Show=lambda: True, release=lambda: None))
        return forms[-1]

    monkeypatch.setattr(module, "show_mcrit_form", show_form)
    plugmod = module.Mcrit4IdaPlugmod()
    backend = MagicMock()
    closed = types.SimpleNamespace(
        view_hook=None,
        hook_subscribed_widgets=[],
        released=False,
        cc=types.SimpleNamespace(backend=backend),
    )
    module.Mcrit4IdaForm.release(closed)
    assert closed.released
    backend.close.assert_called_once_with()

    plugmod.run(0)
    plugmod.run(0)
    assert len(forms) == 1
    forms[0].released = True
    plugmod.run(0)
    assert len(forms) == 2
    assert plugmod.form is forms[1]


def test_cursor_moves_are_coalesced_into_one_refresh(monkeypatch):
    """Live queries hit the MCRIT server, so a burst of cursor events refreshes the widgets once."""
    timers = []
    views = {"IDA View-A": object()}
    kernwin = types.SimpleNamespace(
        PluginForm=_PluginForm,
        is_idaq=lambda: True,
        View_Hooks=_ViewHooks,
        register_timer=lambda interval, callback: timers.append(callback) or callback,
        unregister_timer=MagicMock(),
        get_widget_title=lambda view: next(t for t, v in views.items() if v is view),
        get_current_widget=lambda: views["IDA View-A"],
        find_widget=views.get,
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_idaapi",
        types.SimpleNamespace(plugin_t=_PluginT, plugmod_t=_PlugmodT, PLUGIN_MULTI=1),
    )
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)
    monkeypatch.delitem(sys.modules, "mcrit_plugin.ida.ida_mcrit", raising=False)
    module = importlib.import_module("mcrit_plugin.ida.ida_mcrit")
    now = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    widget = MagicMock()
    hooks = module.IdaViewHooks(types.SimpleNamespace(hook_subscribed_widgets=[widget]))
    view = views["IDA View-A"]

    for _ in range(5):
        hooks.view_curpos(view)
    now[0] += 0.05
    assert len(timers) == 1
    assert 0 < timers[0]() <= module.CURSOR_SETTLE_MS, "the timer waits until the cursor settles"
    widget.hook_refresh.assert_not_called()

    now[0] += 0.2
    assert timers[0]() == -1
    widget.hook_refresh.assert_called_once_with(view)

    hooks.view_curpos(view)
    hooks.unhook()
    kernwin.unregister_timer.assert_called_once()
