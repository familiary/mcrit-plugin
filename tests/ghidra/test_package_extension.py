"""The extension ZIP has the layout Ghidra installs: one folder with extension.properties, the
script in ghidra_scripts and the mcrit_plugin package next to it, without the other disassemblers."""

import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_the_extension_zip_has_the_layout_ghidra_installs(tmp_path):
    output = tmp_path / "mcrit-ghidra.zip"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/ghidra/package_extension.py"),
            "--repo",
            str(ROOT),
            "--output",
            str(output),
            "--ghidra-version",
            "12.2",
        ],
        check=True,
        capture_output=True,
    )

    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        properties = archive.read("MCRIT/extension.properties").decode()

    assert {name.split("/")[0] for name in names} == {"MCRIT"}
    assert {
        "MCRIT/Module.manifest",
        "MCRIT/ghidra_scripts/MCRIT.py",
        "MCRIT/icons/mcrit.png",
        "MCRIT/mcrit_plugin/ghidra/controller.py",
    } <= names
    assert "version=12.2" in properties.splitlines()
    for left_out in ("ida", "binja", "headless", "ghidra/ghidra_scripts"):
        assert not any(name.startswith(f"MCRIT/mcrit_plugin/{left_out}/") for name in names)
