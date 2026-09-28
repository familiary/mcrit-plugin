"""Regression tests for the GUI-free plugin entry point."""

import importlib
import sys
import types


class _PluginT:
    """Minimal plugin base class for import-time tests."""


class _PlugmodT:
    """Minimal plugmod base class for import-time tests."""


class _PluginForm:
    """Minimal plugin form base class for import-time tests."""


class _ViewHooks:
    """Minimal view hooks base class for import-time tests."""


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
    closed = types.SimpleNamespace(view_hook=None, hook_subscribed_widgets=[], released=False)
    module.Mcrit4IdaForm.release(closed)
    assert closed.released

    plugmod.run(0)
    plugmod.run(0)
    assert len(forms) == 1
    forms[0].released = True
    plugmod.run(0)
    assert len(forms) == 2
    assert plugmod.form is forms[1]
