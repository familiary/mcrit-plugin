import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/binja/run_gui_integration.py"
spec = importlib.util.spec_from_file_location("run_binja_gui", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_isolated_gui_profile_pins_the_python_abi_without_persisting_credentials(tmp_path):
    license_file = tmp_path / "input-license.dat"
    license_file.write_text("private license fixture")
    profile = tmp_path / "isolated"
    library = tmp_path / "libpython3.12.so.1.0"
    runner._prepare_user_dir(profile, ROOT, license_file, "http://localhost:8000", "/deps", library)
    settings = json.loads((profile / "settings.json").read_text())
    assert settings["python.interpreter"] == str(library.resolve())
    assert settings["python.binaryOverride"] == sys.executable
    assert settings["python.virtualenv"] == "/deps"
    assert "private license fixture" not in (profile / "settings.json").read_text()
    assert (profile / "plugins/mcrit_plugin_integration").resolve() == ROOT
