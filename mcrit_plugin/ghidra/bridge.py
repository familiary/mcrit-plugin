"""Compile the plugin's Java bridge with PyGhidra's compiler and load it into the running Ghidra.

The jar is cached in Ghidra's user settings directory under a name derived from the Java sources
and the Ghidra version, so it is built once per plugin release and Ghidra version.
"""

import hashlib
from pathlib import Path

JAVA_ROOT = Path(__file__).resolve().parent / "java"
PROVIDER_CLASS = "mcrit.ghidra.McritComponentProvider"
_loaded = set()


def _sources():
    return sorted(JAVA_ROOT.rglob("*.java"))


def _cache_dir():
    from ghidra.framework import Application

    return Path(str(Application.getUserSettingsDirectory().getAbsolutePath())) / "mcrit"


def jar_path():
    from ghidra.framework import Application

    digest = hashlib.sha256(str(Application.getApplicationVersion()).encode())
    for source in _sources():
        digest.update(source.relative_to(JAVA_ROOT).as_posix().encode())
        digest.update(source.read_bytes())
    return _cache_dir() / f"mcrit-bridge-{digest.hexdigest()[:16]}.jar"


def load_bridge():
    """Path of the loaded bridge jar; compiles it first unless a cached build exists."""
    from java.lang import ClassLoader

    jar = jar_path()
    if str(jar) in _loaded:
        return jar
    if not jar.exists():
        from pyghidra.javac import java_compile

        jar.parent.mkdir(parents=True, exist_ok=True)
        # an interrupted earlier build leaves no partial jar behind under the final name
        partial = jar.with_suffix(".partial")
        java_compile(JAVA_ROOT, partial)
        partial.replace(jar)
        for stale in jar.parent.glob("mcrit-bridge-*.jar"):
            if stale != jar:
                try:
                    stale.unlink()
                except OSError:
                    pass
    # Ghidra's system class loader accepts paths at runtime; PyGhidra loads plugins the same way
    ClassLoader.getSystemClassLoader().addPath(str(jar))
    _loaded.add(str(jar))
    return jar


def provider_class():
    """The McritComponentProvider class, or None when the bridge cannot be compiled or loaded."""
    try:
        load_bridge()
        from jpype import JClass

        return JClass(PROVIDER_CLASS)
    except Exception as exc:
        print(f"[MCRIT] Java bridge unavailable ({exc}); the MCRIT window cannot open.")
        return None
