"""Binary Ninja entry point for the MCRIT plugin; the IDA entry point is mcrit_plugin/ida/ida_mcrit.py."""

import os
import sys

_PLUGIN_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_ROOT not in sys.path:
    sys.path.append(_PLUGIN_ROOT)

try:
    import binaryninja  # noqa: F401
except ImportError:
    binaryninja = None

if binaryninja is not None:
    from mcrit_plugin.binja import register_plugin

    register_plugin()
