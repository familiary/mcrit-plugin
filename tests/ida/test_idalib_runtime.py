import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/ida/install_idalib_runtime.py"
spec = importlib.util.spec_from_file_location("install_idalib_runtime", SCRIPT)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


@pytest.mark.parametrize("root", ["", "Contents/MacOS"])
@pytest.mark.parametrize("distribution", ["idapro-9.5-py3-none-any.whl", "setup.py"])
def test_bindings_from_installer_layouts(tmp_path, root, distribution):
    package = tmp_path / root / "idalib/python"
    package.mkdir(parents=True)
    (package / distribution).touch()
    expected = package if distribution == "setup.py" else package / distribution
    assert runtime.find_bindings(tmp_path) == expected


def test_missing_or_ambiguous_bindings_fail(tmp_path):
    with pytest.raises(FileNotFoundError):
        runtime.find_bindings(tmp_path)
    package = tmp_path / "idalib/python"
    package.mkdir(parents=True)
    for version in ("9.4", "9.5"):
        (package / f"idapro-{version}-py3-none-any.whl").touch()
    with pytest.raises(ValueError, match="Multiple"):
        runtime.find_bindings(tmp_path)
