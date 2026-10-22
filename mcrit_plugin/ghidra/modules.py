"""Keep MCRIT's modules loaded across a PyGhidra console Reset.

The console's Reset drops every module imported after the console started from sys.modules. The
MCRIT window lives on and imports SMDA again on its next export, and SMDA's dependency LIEF is a
native extension that aborts the whole process when it is loaded a second time. A finder at the
front of sys.meta_path hands such an import the module object already loaded, so nothing is
executed twice and MCRIT's classes stay the same objects. Other modules are dropped as before.
"""

import importlib.abc
import importlib.machinery
import sys

KEPT_PACKAGES = ("mcrit_plugin", "smda", "lief")


class _CachedLoader(importlib.abc.Loader):
    def __init__(self, module):
        self.module = module
        self.spec = module.__spec__

    def create_module(self, spec):
        return self.module

    def exec_module(self, module):
        # the import machinery replaced the spec with the one this loader came with
        module.__spec__ = self.spec


class _RecordingLoader(importlib.abc.Loader):
    """Loads a module with its own loader and records it once it ran."""

    def __init__(self, loader, modules):
        self.loader = loader
        self.modules = modules

    def create_module(self, spec):
        return self.loader.create_module(spec)

    def exec_module(self, module):
        self.loader.exec_module(module)
        self.modules[module.__name__] = module

    def __getattr__(self, name):
        # resource readers and the like come from the module's own loader
        return getattr(self.loader, name)


class KeptModules(importlib.abc.MetaPathFinder):
    def __init__(self, packages):
        self.packages = tuple(packages)
        self.modules = {}

    def remember_loaded(self):
        for name, module in list(sys.modules.items()):
            if module is not None and name.partition(".")[0] in self.packages:
                self.modules[name] = module

    def find_spec(self, name, path=None, target=None):
        if name.partition(".")[0] not in self.packages:
            return None
        module = self.modules.get(name)
        if module is not None:
            return importlib.machinery.ModuleSpec(
                name, _CachedLoader(module), is_package=hasattr(module, "__path__")
            )
        # a first import: the other finders load it, and the loader records the result
        for finder in sys.meta_path:
            if finder is self or not hasattr(finder, "find_spec"):
                continue
            spec = finder.find_spec(name, path, target)
            if spec is not None:
                if hasattr(spec.loader, "exec_module"):
                    spec.loader = _RecordingLoader(spec.loader, self.modules)
                return spec
        return None


def keep_loaded(packages=KEPT_PACKAGES):
    """Install the finder once per interpreter; returns it."""
    for finder in sys.meta_path:
        if getattr(finder, "packages", None) == tuple(packages):
            return finder
    try:
        # loaded by SMDA's first import anyway; recorded now, before any Reset can drop it
        import lief  # noqa: F401
    except ImportError:
        pass
    finder = KeptModules(packages)
    finder.remember_loaded()
    sys.meta_path.insert(0, finder)
    return finder
