"""Every frontend implements the optional Backend hooks a user can see, or says here why not: an
optional hook defaults to doing nothing, so a missing one fails silently, as IDA's block colouring
did until a parity check found it."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "mcrit_plugin"
FRONTENDS = {
    "IDA": ROOT / "ida" / "IdaBackend.py",
    "Binary Ninja": ROOT / "binja" / "BinjaBackend.py",
    "Ghidra": ROOT / "ghidra" / "GhidraBackend.py",
}
# hooks whose default leaves a visible feature out
VISIBLE_HOOKS = {
    "show_local_match_coloring",
    "clear_local_match_coloring",
    "theme_color",
    "open_settings",
    "save_settings",
}
NOT_SUPPORTED = {
    ("Ghidra", "open_settings"): "no Settings button yet; settings are in Edit > Tool Options",
    ("Ghidra", "save_settings"): "no Settings button yet; settings are in Edit > Tool Options",
}


def _optional_hooks():
    tree = ast.parse((ROOT / "core" / "Backend.py").read_text(encoding="utf-8"))
    backend = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Backend")
    return {
        method.name
        for method in backend.body
        if isinstance(method, ast.FunctionDef)
        and not any(getattr(d, "id", None) == "abstractmethod" for d in method.decorator_list)
    }


def _implemented(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    frontend = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(getattr(b, "id", None) == "Backend" for b in node.bases)
    )
    return {method.name for method in frontend.body if isinstance(method, ast.FunctionDef)}


def test_the_visible_hooks_are_optional_hooks_of_the_backend():
    assert VISIBLE_HOOKS <= _optional_hooks()


def test_every_frontend_implements_the_visible_hooks_or_says_why_not():
    missing = {
        (frontend, hook)
        for frontend, path in FRONTENDS.items()
        for hook in VISIBLE_HOOKS - _implemented(path)
    }

    assert sorted(missing - NOT_SUPPORTED.keys()) == []
    assert sorted(NOT_SUPPORTED.keys() - missing) == []
