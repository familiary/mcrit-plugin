"""Install the extension ZIP with Ghidra's own installer, as File > Install Extensions does, into a
throwaway settings folder, and check that every file arrives. Needs GHIDRA_INSTALL_DIR and pyghidra.
"""

import argparse
import os
import sys
import tempfile
import zipfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--zip", type=Path, required=True)
    args = parser.parse_args()
    zip_path = args.zip.resolve()

    with tempfile.TemporaryDirectory(prefix="mcrit-extension-") as settings:
        # Ghidra keeps its settings, and so its installed extensions, under XDG_CONFIG_HOME
        os.environ["XDG_CONFIG_HOME"] = str(Path(settings) / "config")
        os.environ["XDG_CACHE_HOME"] = str(Path(settings) / "cache")
        import pyghidra

        pyghidra.start()
        from ghidra.framework import Application
        from ghidra.util.extensions import ExtensionUtils
        from ghidra.util.task import TaskMonitor
        from java.io import File

        ExtensionUtils.initializeExtensions()
        details = ExtensionUtils.getExtension(File(str(zip_path)), False)
        if details is None or not ExtensionUtils.install(
            details, File(str(zip_path)), TaskMonitor.DUMMY
        ):
            print(f"FAIL Ghidra did not install {zip_path.name}")
            return 1
        name = str(details.getName())
        installed = (
            Path(str(Application.getUserSettingsDirectory().getAbsolutePath())) / "Extensions"
        )
        members = [n for n in zipfile.ZipFile(zip_path).namelist() if not n.endswith("/")]
        missing = [member for member in members if not (installed / member).is_file()]
        if missing:
            print(f"FAIL {len(missing)} files missing after the install, e.g. {missing[0]}")
            return 1
        print(
            f"PASS Ghidra {Application.getApplicationVersion()} installed {name}, {len(members)} files"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
