"""Test bootstrap that stubs IDA/SMDA modules so the plugin code is importable."""

import os
import sys
import types

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _make_module(name, **attrs):
    """Create a stub module and register it in sys.modules.

    Args:
        name: Module name to register.
        **attrs: Attributes to set on the module.

    Returns:
        The newly created module.
    """
    module = types.ModuleType(name)
    for attr_name, attr_value in attrs.items():
        setattr(module, attr_name, attr_value)
    sys.modules[name] = module
    return module


# Stub `smda` and its submodules used at import time by the plugin helpers.
class _StubSmdaReport:
    """Stub for smda.common.SmdaReport used during plugin tests."""

    @classmethod
    def fromDict(cls, data):
        """Create a SmdaReport from a dictionary."""
        instance = cls()
        instance._data = data
        return instance

    def toDict(self):
        """Return the internal dictionary representation."""
        return getattr(self, "_data", {})

    def getFunctions(self):
        """Return an empty list of functions."""
        return []


class _StubSmdaFunction:
    """Stub for smda.common.SmdaFunction used during plugin tests."""

    pass


class _StubBinaryInfo:
    """Stub for smda.common.BinaryInfo used during plugin tests."""

    def __init__(self, *args, **kwargs):
        """Initialize with empty/default values for testing."""
        self.architecture = ""
        self.base_addr = 0
        self.bitness = 32


class _StubDisassembler:
    """Stub for smda.Disassembler used during plugin tests."""

    def __init__(self, backend=None, *args, **kwargs):
        """Initialize with optional backend parameter."""
        self.backend = backend

    def _disassemble(self, *args, **kwargs):
        """Return a stub SMDA report."""
        return _StubSmdaReport()

    def disassembleBuffer(self, *args, **kwargs):
        """Return a stub SMDA report for a buffer."""
        return _StubSmdaReport()


class _StubIntelInstructionEscaper:
    """Stub for smda.intel.IntelInstructionEscaper used during plugin tests."""

    pass


class _StubIdaInterface:
    """Stub for smda.ida.IdaInterface used during plugin tests."""

    def __init__(self, *args, **kwargs):
        """Initialize the stub interface."""
        pass

    def getBinary(self):
        """Return an empty binary."""
        return b""

    def getArchitecture(self):
        """Return an empty architecture string."""
        return ""

    def getBaseAddr(self):
        """Return a base address of 0."""
        return 0

    def getBitness(self):
        """Return 32-bit as default."""
        return 32

    def getFunctionSymbols(self):
        """Return an empty dictionary of function symbols."""
        return {}


_make_module("smda")
_make_module("smda.common")
_make_module("smda.common.SmdaReport", SmdaReport=_StubSmdaReport)
_make_module("smda.common.SmdaFunction", SmdaFunction=_StubSmdaFunction)
_make_module("smda.common.BinaryInfo", BinaryInfo=_StubBinaryInfo)
_make_module("smda.Disassembler", Disassembler=_StubDisassembler)
_make_module("smda.ida")
_make_module("smda.ida.IdaInterface", IdaInterface=_StubIdaInterface)
_make_module("smda.intel")
_make_module(
    "smda.intel.IntelInstructionEscaper",
    IntelInstructionEscaper=_StubIntelInstructionEscaper,
)


# Stub `ida_settings` so config.py imports succeed.
def _ida_get_current_plugin_setting(key):
    """Stub for ida_settings.get_current_plugin_setting that always raises KeyError.

    Used during tests to force fallback to default values.
    """
    raise KeyError(key)


def _ida_get_plugin_setting(plugin_name, key):
    """Stub for ida_settings.get_plugin_setting that always raises KeyError."""
    raise KeyError(key)


_make_module(
    "ida_settings",
    get_current_plugin_setting=_ida_get_current_plugin_setting,
    get_plugin_setting=_ida_get_plugin_setting,
)
