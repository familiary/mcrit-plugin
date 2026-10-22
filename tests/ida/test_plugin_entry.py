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


def _view_hooks(monkeypatch, titles):
    """IdaViewHooks over stub views with the given titles, a fake clock and a timer list."""
    timers = []
    views = {title: object() for title in titles}
    kernwin = types.SimpleNamespace(
        PluginForm=_PluginForm,
        is_idaq=lambda: True,
        View_Hooks=_ViewHooks,
        register_timer=lambda interval, callback: timers.append(callback) or callback,
        unregister_timer=MagicMock(),
        get_widget_title=lambda view: next(t for t, v in views.items() if v is view),
        get_current_widget=lambda: views[titles[0]],
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
    return types.SimpleNamespace(
        module=module,
        hooks=hooks,
        widget=widget,
        views=views,
        timers=timers,
        now=now,
        kernwin=kernwin,
    )


def test_cursor_moves_are_coalesced_into_one_refresh(monkeypatch):
    """Live queries hit the MCRIT server, so a burst of cursor events refreshes the widgets once."""
    setup = _view_hooks(monkeypatch, ["IDA View-A"])
    module, hooks, widget, timers, now = (
        setup.module,
        setup.hooks,
        setup.widget,
        setup.timers,
        setup.now,
    )
    kernwin = setup.kernwin
    view = setup.views["IDA View-A"]

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


def test_an_event_from_another_view_keeps_the_disassembly_move(monkeypatch):
    setup = _view_hooks(monkeypatch, ["IDA View-A", "Hex View-1"])
    disassembly, hex_view = setup.views["IDA View-A"], setup.views["Hex View-1"]

    setup.hooks.view_loc_changed(disassembly, None, None)
    setup.hooks.view_curpos(hex_view)  # a synced hex view, or a click there
    setup.hooks.view_curpos(disassembly)
    setup.now[0] += 0.2
    assert setup.timers[0]() == -1

    assert [call.args[0] for call in setup.widget.hook_refresh.call_args_list] == [
        disassembly,
        hex_view,
    ]


def test_the_menu_entries_act_on_the_current_database(monkeypatch):
    """Edit > Plugins > MCRIT4IDA Settings... and Clear Match Coloring act on the database open
    now; a previous database's plugmod going away late leaves the entries in place."""
    actions = {}

    class _ActionDesc:
        def __init__(self, name, label, handler, shortcut, tooltip, icon):
            self.name, self.handler = name, handler

    kernwin = types.SimpleNamespace(
        PluginForm=_PluginForm,
        is_idaq=lambda: True,
        View_Hooks=_ViewHooks,
        action_handler_t=object,
        action_desc_t=_ActionDesc,
        AST_ENABLE_ALWAYS=0,
        SETMENU_APP=1,
        register_action=lambda desc: actions.__setitem__(desc.name, desc.handler) or True,
        unregister_action=lambda name: actions.pop(name, None) is not None,
        attach_action_to_menu=MagicMock(),
        detach_action_from_menu=MagicMock(),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_idaapi",
        types.SimpleNamespace(plugin_t=_PluginT, plugmod_t=_PlugmodT, PLUGIN_MULTI=1),
    )
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)
    monkeypatch.delitem(sys.modules, "mcrit_plugin.ida.ida_mcrit", raising=False)
    module = importlib.import_module("mcrit_plugin.ida.ida_mcrit")
    form = types.SimpleNamespace(
        released=False, Show=lambda: True, release=lambda: None, main_widget=MagicMock()
    )
    monkeypatch.setattr(module, "show_mcrit_form", lambda: form)

    kernwin.register_action = lambda desc: (
        desc.name not in actions and actions.setdefault(desc.name, desc.handler) is not None
    )
    previous = module.Mcrit4IdaPlugmod()
    plugmod = module.Mcrit4IdaPlugmod()
    del previous
    assert [call.args for call in kernwin.attach_action_to_menu.call_args_list] == [
        ("Edit/Plugins/", module.SETTINGS_ACTION, kernwin.SETMENU_APP),
        ("Edit/Plugins/", module.CLEAR_COLORING_ACTION, kernwin.SETMENU_APP),
    ]

    actions[module.CLEAR_COLORING_ACTION].activate(None)
    assert plugmod.form is None

    actions[module.SETTINGS_ACTION].activate(None)
    assert plugmod.form is form
    form.main_widget._onSettingsButtonClicked.assert_called_once_with()

    form.cc = MagicMock()
    actions[module.CLEAR_COLORING_ACTION].activate(None)
    form.cc.backend.clear_local_match_coloring.assert_called_once_with()
