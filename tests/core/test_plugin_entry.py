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

    module = importlib.import_module("mcrit_plugin.ida.ida_mcrit")
    plugin = module.PLUGIN_ENTRY()

    assert plugin.wanted_name == "MCRIT4IDA"
    assert plugin.init() is not None
    assert module.show_mcrit_form() is None
    assert not any(name.startswith(("PySide", "PyQt")) for name in sys.modules)
