"""GhidraSession inherits McritSession's logic and replaces only the methods that touch Qt, so the
inherited methods must stay free of Qt; a Qt call there would break the Ghidra plugin only."""

import ast
from pathlib import Path

SESSION = Path(__file__).resolve().parents[2] / "mcrit_plugin" / "ui_qt" / "McritSession.py"
# what GhidraSession overrides; everything else in McritSession runs inside Ghidra
OVERRIDDEN = {"__init__", "setupWidgets", "copyStringToClipboard"}
QT_MARKERS = ("PySide", "PyQt", "QtShim", "QApplication", "QWidget", "QIcon", "cc.Q")


def _tree():
    return ast.parse(SESSION.read_text(encoding="utf-8"))


def test_mcrit_session_imports_no_qt_at_module_level():
    for node in _tree().body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.name for alias in node.names] + [getattr(node, "module", "") or ""]
            assert not any(marker in name for name in names for marker in QT_MARKERS), names


def test_inherited_session_methods_do_not_touch_qt():
    session_class = next(
        node
        for node in _tree().body
        if isinstance(node, ast.ClassDef) and node.name == "McritSession"
    )
    source = SESSION.read_text(encoding="utf-8")
    for method in session_class.body:
        if not isinstance(method, ast.FunctionDef) or method.name in OVERRIDDEN:
            continue
        body = ast.get_source_segment(source, method)
        assert not any(marker in body for marker in QT_MARKERS), method.name


def test_ghidra_session_overrides_the_qt_methods():
    ghidra_session = Path(__file__).resolve().parents[2] / "mcrit_plugin/ghidra/ui/GhidraSession.py"
    tree = ast.parse(ghidra_session.read_text(encoding="utf-8"))
    session_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "GhidraSession"
    )
    defined = {node.name for node in session_class.body if isinstance(node, ast.FunctionDef)}
    assert OVERRIDDEN <= defined


def test_ghidra_session_takes_the_shared_state_from_mcrit_session():
    """A hand copy of the state would miss attributes core adds later, on Ghidra only."""
    ghidra_session = Path(__file__).resolve().parents[2] / "mcrit_plugin/ghidra/ui/GhidraSession.py"
    tree = ast.parse(ghidra_session.read_text(encoding="utf-8"))
    session_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "GhidraSession"
    )
    init = next(
        node
        for node in session_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    )
    shared = next(
        node
        for node in ast.walk(_tree())
        if isinstance(node, ast.FunctionDef) and node.name == "_initSharedState"
    )
    shared_attributes = {
        target.attr
        for node in ast.walk(shared)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute)
    }
    assigned_here = {
        target.attr
        for node in ast.walk(init)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute)
    }
    calls = {
        node.func.attr
        for node in ast.walk(init)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "_initSharedState" in calls
    assert not shared_attributes & assigned_here, shared_attributes & assigned_here
