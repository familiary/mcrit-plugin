"""mcrit_plugin.core must not import GUI toolkits or frontends, so every frontend can reuse it."""

import ast
import importlib.util
import os

import mcrit_plugin
import mcrit_plugin.core

BLOCKED_MODULES = {
    "PySide6",
    "PySide2",
    "PyQt5",
    "PyQt6",
    "shiboken6",
    "shiboken2",
    "binaryninja",
    "binaryninjaui",
    "idaapi",
    "idc",
    "idautils",
    "ghidra",
}


FRONTEND_PACKAGES = ("mcrit_plugin.ui_qt", "mcrit_plugin.ida", "mcrit_plugin.binja")


def _is_blocked(module_name):
    top_level = module_name.split(".")[0]
    if module_name in FRONTEND_PACKAGES or module_name.startswith(
        tuple(package + "." for package in FRONTEND_PACKAGES)
    ):
        return True
    return top_level in BLOCKED_MODULES or top_level.startswith("ida_")


def test_core_modules_do_not_import_gui_toolkits():
    offenders = []
    for root, _dirs, files in os.walk(mcrit_plugin.core.__path__[0]):
        for file_name in files:
            if not file_name.endswith(".py"):
                continue
            path = os.path.join(root, file_name)
            with open(path, "r", encoding="utf-8") as source_file:
                tree = ast.parse(source_file.read(), filename=path)
            relative = os.path.relpath(path, os.path.dirname(mcrit_plugin.__path__[0]))
            package = os.path.dirname(relative).replace(os.sep, ".")
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    module = importlib.util.resolve_name(
                        "." * node.level + (node.module or ""), package
                    )
                    names = [module] + [f"{module}.{alias.name}" for alias in node.names]
                else:
                    continue
                for name in names:
                    if _is_blocked(name):
                        offenders.append(f"{path}:{node.lineno}: {name}")
    assert not offenders, "GUI toolkit or frontend imports in mcrit_plugin.core: " + ", ".join(
        offenders
    )
