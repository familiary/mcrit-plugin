#!/usr/bin/env python3
"""Run the IDA headless integration test with an existing local IDA installation."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def _find_ida_binary(ida_dir: Path) -> Path:
    root = ida_dir.expanduser().resolve()
    gui_names = ("ida64", "ida", "ida64.exe", "ida.exe")
    batch_names = ("idat64", "idat", "idat64.exe", "idat.exe")
    names = gui_names + batch_names
    candidates = [root / name for name in names] + [
        root / "Contents" / "MacOS" / name for name in names
    ]
    candidates.extend(path for name in gui_names for path in root.rglob(name))
    candidates.extend(path for name in batch_names for path in root.rglob(name))

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(f"Could not find an IDA GUI or batch executable under {root}")


def _build_plugin_zip(repo_root: Path, output: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "ida" / "package_plugin.py"),
            "--repo",
            str(repo_root),
            "--output",
            str(output),
        ],
        check=True,
    )


def _safe_extract_plugin(plugin_zip: Path, plugin_root: Path) -> None:
    plugin_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(plugin_zip) as archive:
        for member in archive.infolist():
            target = (plugin_root / member.filename).resolve()
            if not str(target).startswith(str(plugin_root.resolve()) + os.sep):
                raise ValueError(f"Unsafe plugin archive member: {member.filename}")
        archive.extractall(plugin_root)


def _read_log(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def _test_settings(server: str, timeout: int) -> dict[str, object]:
    settings = {
        "mcritweb_username": "",
        "mcritweb_api_token": "",
        "mcrit_server": server.rstrip("/"),
        "mcrit_request_timeout": str(timeout),
        "sample_group_only": False,
        "auto_analyze_smda_on_startup": False,
        "use_smda_for_analysis": False,
        "submit_function_names_on_close": False,
        "overview_fetch_labels_automatically": False,
    }
    return settings


def _activate_current_venv(environment: dict[str, str]) -> None:
    """Let IDAPython use the virtual environment running this test runner."""
    if sys.prefix == sys.base_prefix:
        return
    # not resolve(): the venv's python is a symlink into the base installation, and IDAPython
    # picks its interpreter from PATH, which then misses the virtual environment's packages
    venv_bin = Path(sys.executable).parent
    environment["VIRTUAL_ENV"] = sys.prefix
    environment["PATH"] = str(venv_bin) + os.pathsep + environment.get("PATH", "")


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _prepare_ida_settings(idausr: Path, settings: dict[str, object]):
    config_path = idausr / "ida-config.json"
    previous_contents = config_path.read_bytes() if config_path.exists() else None
    if previous_contents is None:
        config = {"Version": 1, "Plugins": {}}
    else:
        config = json.loads(previous_contents.decode("utf-8"))

    plugins = config.setdefault("Plugins", {})
    plugin_config = plugins.setdefault("mcrit-ida", {})
    plugin_config.setdefault("settings", {}).update(settings)
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return config_path, previous_contents


def _restore_ida_settings(config_path: Path, previous_contents) -> None:
    if previous_contents is not None:
        config_path.write_bytes(previous_contents)
        return

    if not config_path.exists():
        return
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        plugins = config.get("Plugins")
        if isinstance(plugins, dict):
            plugins.pop("mcrit-ida", None)
        if config == {"Version": 1, "Plugins": {}}:
            config_path.unlink()
        else:
            config_path.write_text(
                json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    except (OSError, json.JSONDecodeError):
        config_path.unlink(missing_ok=True)


def _disable_pyqt5_shim(idausr: Path) -> None:
    """Keep IDA >= 9.2 from prompting about PyQt5 shims, which a dependency triggers on import."""
    config_path = idausr / "cfg" / "idapython.cfg"
    if config_path.is_file():
        return
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "#if __IDAVER__ >= 920\nIDAPYTHON_USE_PYQT5_SHIM = 0\n#endif\n", encoding="utf-8"
    )


def _find_installed_plugin(idausr: Path) -> Path:
    expected = idausr / "plugins" / "mcrit-ida"
    if (expected / "ida_mcrit.py").is_file():
        return expected
    raise FileNotFoundError(f"mcrit-ida was not found below {idausr}")


def _candidate_idausr_paths() -> list[Path]:
    candidates = []
    configured = os.environ.get("IDAUSR")
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend(
        [
            Path.home() / ".idapro",
            Path.home() / "Library" / "Application Support" / "Hex-Rays" / "IDA Pro",
        ]
    )

    unique = []
    seen = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


def _infer_idausr_from_plugin_root(plugin_root: Path):
    plugin_root = plugin_root.resolve()
    if plugin_root.parent.name == "plugins":
        return plugin_root.parent.parent
    return None


def _select_local_idausr(plugin_root: Path | None):
    """Select the user's normal IDA profile instead of creating a fresh one.

    A fresh IDAUSR is useful in CI, where the caller passes ``--idausr``.  It
    is counterproductive for a local run: IDA treats a new profile as a new
    installation and may refuse batch execution until its license and Python
    configuration have been initialized.  Reusing the profile that already
    loads the plugin also makes this command exercise the user's real setup.
    """
    if plugin_root is not None:
        inferred = _infer_idausr_from_plugin_root(plugin_root)
        if inferred is not None:
            return inferred

    for candidate in _candidate_idausr_paths():
        if (candidate / "plugins" / "mcrit-ida" / "ida_mcrit.py").is_file():
            return candidate

    candidates = _candidate_idausr_paths()
    return candidates[0] if candidates else None


def _install_with_hcli(
    plugin_zip: Path, ida_dir: Path, idausr: Path, settings: dict[str, object]
) -> bool:
    if (idausr / "plugins" / "mcrit-ida" / "ida_mcrit.py").is_file():
        print(
            "[ida-integration] mcrit-ida is already installed; updating its files directly "
            "without requiring an HCLI API key"
        )
        return False

    hcli = shutil.which("hcli")
    if hcli is None:
        return False

    environment = os.environ.copy()
    environment.update(
        {
            "IDAUSR": str(idausr),
            "IDADIR": str(ida_dir),
            "HCLI_CURRENT_IDA_INSTALL_DIR": str(ida_dir),
            "HCLI_DISABLE_UPDATES": "1",
            # hcli otherwise runs `idat` to auto-detect IDA's Python interpreter,
            # which fails on a headless/fresh CI install (no accepted license,
            # no display). Point it at the Python that runs this harness so the
            # plugin files are still installed correctly.
            "HCLI_CURRENT_IDA_PYTHON_EXE": sys.executable,
        }
    )
    command = [
        hcli,
        "plugin",
        "install",
        str(plugin_zip),
    ]
    for key, value in settings.items():
        if isinstance(value, bool):
            value = str(value).lower()
        command.extend(["--config", f"{key}={value}"])
    print("[ida-integration] installing plugin with hcli")
    try:
        subprocess.run(command, check=True, env=environment)
    except subprocess.CalledProcessError as exc:
        print(
            f"[ida-integration] hcli plugin install failed ({exc.returncode}); "
            "falling back to manual extraction of the plugin archive",
        )
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", type=Path, required=True)
    parser.add_argument(
        "--ida-binary",
        type=Path,
        help="Optional IDA executable; defaults to the GUI binary so Qt widgets can load in-process.",
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mcrit-server", default="http://127.0.0.1:8000")
    parser.add_argument("--reference-sha256")
    parser.add_argument("--idausr", type=Path)
    parser.add_argument("--plugin-zip", type=Path)
    parser.add_argument("--plugin-root", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--log", type=Path)
    parser.add_argument(
        "--qt-platform",
        help="Qt platform plugin (defaults to cocoa on macOS and offscreen elsewhere).",
    )
    parser.add_argument("--offline", action="store_true")
    parser.add_argument(
        "--ui-session",
        action="store_true",
        help="Start IDA with its UI instead of batch mode (-A), so the test can drive the "
        "disassembly cursor; deletes an existing database for the input beforehand, because "
        "no dialog is answered automatically.",
    )
    parser.add_argument("--require-hcli", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    input_path = args.input.expanduser().resolve()
    ida_dir = args.ida_dir.expanduser().resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f"Input binary does not exist: {input_path}")

    if args.idausr:
        idausr = args.idausr.expanduser().resolve()
        idausr.mkdir(parents=True, exist_ok=True)
    else:
        requested_plugin_root = (
            args.plugin_root.expanduser().resolve() if args.plugin_root else None
        )
        idausr = _select_local_idausr(requested_plugin_root)
        if idausr is None:
            raise RuntimeError("Could not determine the normal local IDA profile; pass --idausr")
        idausr.mkdir(parents=True, exist_ok=True)

    plugin_root = args.plugin_root.expanduser().resolve() if args.plugin_root else None
    package_root = None
    session_root = None
    plugin_zip = None
    ida_config_path = None
    previous_ida_config = None
    settings = _test_settings(args.mcrit_server, args.timeout)
    if plugin_root is None:
        if args.plugin_zip:
            plugin_zip = args.plugin_zip.expanduser().resolve()
        else:
            package_root = Path(tempfile.mkdtemp(prefix="mcrit-ida-package-"))
            plugin_zip = package_root / "mcrit-ida.zip"
        if not plugin_zip.is_file():
            _build_plugin_zip(repo_root, plugin_zip)

    try:
        if plugin_root is None:
            installed_with_hcli = _install_with_hcli(plugin_zip, ida_dir, idausr, settings)
            if args.require_hcli and shutil.which("hcli") is None:
                raise RuntimeError("hcli is required but was not found on PATH")
            if installed_with_hcli:
                plugin_root = _find_installed_plugin(idausr)
            else:
                plugin_root = idausr / "plugins" / "mcrit-ida"
                _safe_extract_plugin(plugin_zip, plugin_root)

        if not (plugin_root / "ida_mcrit.py").is_file():
            raise FileNotFoundError(f"mcrit-ida entrypoint was not found at {plugin_root}")

        _disable_pyqt5_shim(idausr)
        ida_config_path, previous_ida_config = _prepare_ida_settings(idausr, settings)
        ida_binary = (
            args.ida_binary.expanduser().resolve() if args.ida_binary else _find_ida_binary(ida_dir)
        )
        integration_script = repo_root / "tests" / "ida" / "gui_integration.py"
        log_path = args.log.expanduser().resolve() if args.log else idausr / "ida-integration.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        qt_platform = (
            args.qt_platform
            or os.environ.get("QT_QPA_PLATFORM")
            or ("cocoa" if sys.platform == "darwin" else "offscreen")
        )

        environment = os.environ.copy()
        _activate_current_venv(environment)
        environment.update(
            {
                "IDAUSR": str(idausr),
                "MCRIT_IDA_PLUGIN_ROOT": str(plugin_root),
                "MCRIT_IDA_INTEGRATION_LIVE": "0" if args.offline else "1",
                "MCRIT_IDA_INTEGRATION_TIMEOUT": str(args.timeout),
                "QT_QPA_PLATFORM": qt_platform,
                "PYTHONUTF8": "1",
            }
        )
        if args.reference_sha256:
            environment["MCRIT_IDA_INTEGRATION_REFERENCE_SHA256"] = args.reference_sha256
        if args.artifacts:
            artifacts = args.artifacts.expanduser().resolve()
            artifacts.mkdir(parents=True, exist_ok=True)
            environment["MCRIT_IDA_INTEGRATION_ARTIFACT_DIR"] = str(artifacts)
        command = [str(ida_binary)]
        if ida_license := environment.get("IDA_LICENSE"):
            command.append(f"-Olicense:{ida_license}")
        if args.ui_session:
            # without -A nothing answers the "database already exists" dialog, so analyze a copy
            # in an empty directory where no database or its unpacked sidecars can sit
            session_root = Path(tempfile.mkdtemp(prefix="mcrit-ida-session-"))
            input_path = Path(shutil.copy2(input_path, session_root / input_path.name))
        else:
            command.append("-A")
        command.extend(
            [
                f"-L{log_path}",
                f"-S{integration_script}",
                str(input_path),
            ]
        )
        display_command = [
            "-Olicense:keyfile=<redacted>"
            if argument.startswith("-Olicense:keyfile=")
            else argument
            for argument in command
        ]
        print("[ida-integration]", " ".join(display_command))
        process_options = {}
        if os.name != "nt":
            process_options["start_new_session"] = True
        process = subprocess.Popen(
            command,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **process_options,
        )
        process_timeout = args.timeout + 60
        try:
            stdout, stderr = process.communicate(timeout=process_timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process)
            stdout, stderr = process.communicate()
            if stderr:
                print(stderr, file=sys.stderr)
            if stdout:
                print("--- IDA stdout ---", file=sys.stderr)
                print(stdout, file=sys.stderr)
            for diagnostic_path in (log_path, environment.get("IDALOG")):
                if diagnostic_path:
                    diagnostic_log = _read_log(Path(diagnostic_path))
                    if diagnostic_log:
                        print(diagnostic_log)
            raise RuntimeError(
                f"IDA integration test timed out after {process_timeout} seconds; "
                f"see {log_path} and IDALOG for startup diagnostics"
            )
        completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        log_text = _read_log(log_path)
        # IDA's -L log is empty when IDALOG is set (the env var reroutes output),
        # so fall back to IDALOG for the success-marker check.
        if not log_text:
            idalog_path = environment.get("IDALOG")
            if idalog_path:
                log_text = _read_log(Path(idalog_path))
        if log_text:
            print(log_text)
        if "License not yet accepted" in log_text:
            raise RuntimeError(
                "IDA has not accepted its license yet; start IDA Pro once interactively "
                "and accept the license before running the headless integration test"
            )
        if "Python 3 is not configured" in log_text:
            raise RuntimeError(
                "IDA Python is not configured; configure it with idapyswitch before running the integration test"
            )
        if completed.returncode != 0 and "MCRIT_IDA_INTEGRATION_OK" not in log_text:
            if completed.stderr and completed.stderr.strip():
                print(completed.stderr, file=sys.stderr)
            if completed.stdout and completed.stdout.strip():
                print("--- IDA stdout ---", file=sys.stderr)
                print(completed.stdout, file=sys.stderr)
            raise RuntimeError(f"IDA integration test failed with exit code {completed.returncode}")
        if "MCRIT_IDA_INTEGRATION_OK" not in log_text:
            raise RuntimeError(f"IDA integration test marker was not found in {log_path}")
        print(f"[ida-integration] completed successfully; log: {log_path}")
        return 0
    finally:
        if ida_config_path is not None:
            _restore_ida_settings(ida_config_path, previous_ida_config)
        if package_root is not None:
            shutil.rmtree(package_root, ignore_errors=True)
        if session_root is not None:
            shutil.rmtree(session_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
