"""The finder that keeps MCRIT's modules loaded across a PyGhidra console Reset."""

import importlib
import sys

from mcrit_plugin.ghidra.modules import KeptModules


def test_a_dropped_module_comes_back_without_running_again(tmp_path, monkeypatch):
    package = tmp_path / "keptprobe"
    package.mkdir()
    (package / "__init__.py").write_text("")
    # a module that counts how often it runs, like a native extension that must load once
    (package / "native.py").write_text(
        "import builtins\nbuiltins.keptprobe_runs = getattr(builtins, 'keptprobe_runs', 0) + 1\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    import builtins

    finder = KeptModules(["keptprobe"])
    monkeypatch.setattr(sys, "meta_path", [finder, *sys.meta_path])
    try:
        first = importlib.import_module("keptprobe.native")
        spec = first.__spec__
        # what the console's Reset does to every module imported since it started
        for name in [name for name in sys.modules if name.startswith("keptprobe")]:
            del sys.modules[name]

        again = importlib.import_module("keptprobe.native")

        assert again is first
        assert builtins.keptprobe_runs == 1
        assert again.__spec__ is spec
        assert again.__spec__.origin.endswith("native.py")
        assert sys.modules["keptprobe"].native is first
    finally:
        for name in [name for name in sys.modules if name.startswith("keptprobe")]:
            del sys.modules[name]
        del builtins.keptprobe_runs


def test_other_modules_are_not_kept(monkeypatch):
    finder = KeptModules(["keptprobe"])
    assert finder.find_spec("json") is None
