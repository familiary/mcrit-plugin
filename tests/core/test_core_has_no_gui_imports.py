"""mcrit_plugin.core must stay free of GUI toolkit imports so non-Qt frontends can reuse it."""

import ast
import os

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


def _is_blocked(module_name):
    top_level = module_name.split(".")[0]
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
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    # level > 0 is a relative import, which can never name a GUI toolkit
                    names = [node.module] if node.level == 0 and node.module else []
                else:
                    continue
                for name in names:
                    if _is_blocked(name):
                        offenders.append(f"{path}:{node.lineno}: {name}")
    assert not offenders, "GUI toolkit imports in mcrit_plugin.core: " + ", ".join(offenders)
