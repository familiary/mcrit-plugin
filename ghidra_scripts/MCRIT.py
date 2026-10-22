# Open the MCRIT window for the current program: convert it to an SMDA report, upload it to an
# MCRIT server and browse block, function and sample matches next to the listing.
# Needs Ghidra 12.0+ started in PyGhidra mode, and smda and requests in PyGhidra's Python.
# @author Daniel Plohmann, Rony
# @category MCRIT
# @menupath Tools.MCRIT
# @keybinding ctrl shift M
# @runtime PyGhidra

import os
import sys
import threading
import time
import traceback

from java.lang import System

# PyGhidra unloads the modules a script imported once the script ends. The MCRIT window lives on
# and imports SMDA again on its next export, and SMDA's dependency LIEF is a native extension that
# aborts the whole process when it is loaded a second time. PyGhidra skips the unloading while this
# system property is true; it is set for this script only and restored shortly after it ended.
KEEP_MODULES = "pyghidra.sys.modules.restore.disable"
RESTORE_DELAY = 5.0
_previous_keep_modules = System.getProperty(KEEP_MODULES)
System.setProperty(KEEP_MODULES, "true")


def _restore_keep_modules():
    time.sleep(RESTORE_DELAY)
    if _previous_keep_modules is None:
        System.clearProperty(KEEP_MODULES)
    else:
        System.setProperty(KEEP_MODULES, _previous_keep_modules)


# this script sits in <plugin>/ghidra_scripts; the mcrit_plugin package is next to that folder
PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, PLUGIN_ROOT)


def _missing_dependencies():
    missing = []
    for module, package in (("smda", "smda>=4.9.0"), ("requests", "requests")):
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    return missing


def main():
    from ghidra.util import Msg

    tool = state.getTool()  # noqa: F821 - provided by PyGhidra
    if tool is None:
        print(
            "MCRIT needs the Ghidra GUI; use scripts/ghidra/run_pyghidra_integration.py headless."
        )
        return
    missing = _missing_dependencies()
    if missing:
        Msg.showError(
            None,
            None,
            "MCRIT",
            "Install the MCRIT plugin's dependencies into PyGhidra's Python, then run MCRIT again:\n"
            f"  {sys.executable} -m pip install {' '.join(missing)}",
        )
        return
    program = currentProgram  # noqa: F821
    if program is None:
        Msg.showWarn(None, None, "MCRIT", "Open a program first.")
        return
    location = currentLocation  # noqa: F821
    cursor = int(location.getAddress().getOffset()) if location is not None else None

    from mcrit_plugin.ghidra import bridge, modules, swing
    from mcrit_plugin.ghidra.controller import controller_for

    modules.keep_loaded()

    # javac needs seconds on a first start: run it in this script's task, not on Swing's thread
    if not bridge.jar_path().exists():
        monitor.setMessage("MCRIT: compiling the Java bridge (first start only)")  # noqa: F821
    if bridge.provider_class() is None:
        Msg.showError(
            None,
            None,
            "MCRIT",
            "The MCRIT window needs its Java bridge, which could not be compiled; see the console. "
            "Ghidra must run on a JDK.",
        )
        return

    def open_window():
        controller_for(tool).show(program, cursor)

    swing.invoke_and_wait(open_window)


try:
    main()
except Exception:
    traceback.print_exc()
    raise
finally:
    # PyGhidra reads the property right after this script returns
    threading.Thread(target=_restore_keep_modules, daemon=True).start()
