"""Every frontend implements the optional Backend hooks a user can see, or says here why not: an
optional hook defaults to doing nothing, so a missing one fails silently."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "mcrit_plugin"
FRONTENDS = {
    "IDA": ROOT / "ida" / "IdaBackend.py",
    "Binary Ninja": ROOT / "binja" / "BinjaBackend.py",
    "Ghidra": ROOT / "ghidra" / "GhidraBackend.py",
}
# optional hooks whose default does the job everywhere
WORKING_DEFAULTS = {"mutation", "run_background", "run_request", "show_failure"}
# optional hooks whose default leaves a visible feature out
VISIBLE_HOOKS = {
    "show_local_match_coloring",
    "clear_local_match_coloring",
    "theme_color",
    "open_settings",
    "save_settings",
    # without it the upload before a file closes cannot be cancelled
    "run_blocking",
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
        and not any(
            "abstractmethod" in (getattr(d, "id", None), getattr(d, "attr", None))
            for d in method.decorator_list
        )
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


def test_every_optional_hook_is_either_visible_or_has_a_working_default():
    # a new optional hook has to go into one of the two sets, so this test covers it
    assert VISIBLE_HOOKS | WORKING_DEFAULTS == _optional_hooks()
    assert not VISIBLE_HOOKS & WORKING_DEFAULTS


def test_every_frontend_implements_the_visible_hooks_or_says_why_not():
    missing = {
        (frontend, hook)
        for frontend, path in FRONTENDS.items()
        for hook in VISIBLE_HOOKS - _implemented(path)
    }

    assert sorted(missing - NOT_SUPPORTED.keys()) == []
    assert sorted(NOT_SUPPORTED.keys() - missing) == []


def test_a_blocking_run_ends_with_the_work_or_when_cancelled():
    import threading

    from mcrit_plugin.core.Backend import run_until_cancelled

    ran = []
    assert run_until_cancelled(lambda: ran.append(1), lambda: False, interval=0.01) is True
    assert ran == [1]
    server_never_answers = threading.Event()
    try:
        assert run_until_cancelled(server_never_answers.wait, lambda: True, interval=0.01) is False
    finally:
        server_never_answers.set()


def test_failures_of_one_kind_of_job_in_a_row_open_one_warning_dialog():
    from mcrit_plugin.headless.HeadlessBackend import HeadlessBackend

    backend = HeadlessBackend.__new__(HeadlessBackend)
    dialogs = []
    backend.show_warning = dialogs.append

    backend.show_failure("MCRIT: querying matches for function 0x401000 failed")
    backend.show_failure("MCRIT: querying matches for function 0x402000 failed")
    # another job's only report must not be swallowed with them
    backend.show_failure("MCRIT: exporting SMDA report failed")

    assert dialogs == [
        "MCRIT: querying matches for function 0x401000 failed",
        "MCRIT: exporting SMDA report failed",
    ]
