#!/usr/bin/env python3
"""Run the IDALib MCRIT integration test with an installed IDA Pro."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from run_gui_integration import (
    _activate_current_venv,
    _build_plugin_zip,
    _disable_pyqt5_shim,
    _find_installed_plugin,
    _install_with_hcli,
    _prepare_ida_settings,
    _restore_ida_settings,
    _safe_extract_plugin,
    _test_settings,
)


def _find_activation_script(ida_dir: Path) -> Path:
    roots = (ida_dir, ida_dir / "Contents" / "MacOS")
    for root in roots:
        for candidate in (
            root / "py-activate-idalib.py",
            root / "idalib" / "python" / "py-activate-idalib.py",
        ):
            if candidate.is_file():
                return candidate
    raise FileNotFoundError(f"Could not find py-activate-idalib.py below {ida_dir}")


def _activate_idalib(ida_dir: Path, idausr: Path) -> None:
    """Register the current Python environment with IDALib's installation."""
    environment = os.environ.copy()
    environment["IDAUSR"] = str(idausr)
    script = _find_activation_script(ida_dir)
    subprocess.run(
        [sys.executable, str(script), "-d", str(script.parents[2])],
        check=True,
        env=environment,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mcrit-server", default="http://127.0.0.1:8000")
    parser.add_argument("--reference-sha256")
    parser.add_argument("--idausr", type=Path, required=True)
    parser.add_argument("--plugin-zip", type=Path)
    parser.add_argument("--plugin-root", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--require-hcli", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    ida_dir = args.ida_dir.expanduser().resolve()
    input_path = args.input.expanduser().resolve()
    idausr = args.idausr.expanduser().resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f"Input binary does not exist: {input_path}")
    idausr.mkdir(parents=True, exist_ok=True)

    package_root = None
    ida_config_path = None
    previous_ida_config = None
    settings = _test_settings(args.mcrit_server, args.timeout)
    try:
        _disable_pyqt5_shim(idausr)
        _activate_idalib(ida_dir, idausr)
        plugin_root = args.plugin_root.expanduser().resolve() if args.plugin_root else None
        if plugin_root is None:
            plugin_zip = args.plugin_zip.expanduser().resolve() if args.plugin_zip else None
            if plugin_zip is None:
                package_root = Path(tempfile.mkdtemp(prefix="mcrit-idalib-package-"))
                plugin_zip = package_root / "mcrit-ida.zip"
                _build_plugin_zip(repo_root, plugin_zip)
            if not plugin_zip.is_file():
                raise FileNotFoundError(f"Plugin ZIP does not exist: {plugin_zip}")

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

        ida_config_path, previous_ida_config = _prepare_ida_settings(idausr, settings)
        integration_script = repo_root / "tests" / "ida" / "idalib_integration.py"
        log_path = (
            args.log.expanduser().resolve() if args.log else idausr / "idalib-integration.log"
        )
        log_path.parent.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        _activate_current_venv(environment)
        environment.update(
            {
                "IDAUSR": str(idausr),
                "MCRIT_IDA_PLUGIN_ROOT": str(plugin_root),
                "MCRIT_IDA_INTEGRATION_LIVE": "0" if args.offline else "1",
                "MCRIT_IDA_INTEGRATION_TIMEOUT": str(args.timeout),
                "PYTHONUTF8": "1",
            }
        )
        if args.reference_sha256:
            environment["MCRIT_IDA_INTEGRATION_REFERENCE_SHA256"] = args.reference_sha256
        if args.artifacts:
            artifacts = args.artifacts.expanduser().resolve()
            artifacts.mkdir(parents=True, exist_ok=True)
            environment["MCRIT_IDA_INTEGRATION_ARTIFACT_DIR"] = str(artifacts)

        completed = subprocess.run(
            [sys.executable, str(integration_script), "--input", str(input_path)],
            env=environment,
            check=False,
            text=True,
            capture_output=True,
        )
        log_path.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        print(log_path.read_text(encoding="utf-8", errors="replace"))
        if completed.returncode != 0 or "MCRIT_IDALIB_INTEGRATION_OK" not in completed.stdout:
            raise RuntimeError(
                f"IDALib integration test failed with exit code {completed.returncode}"
            )
        print(f"[idalib-integration] completed successfully; log: {log_path}")
        return 0
    finally:
        if ida_config_path is not None:
            _restore_ida_settings(ida_config_path, previous_ida_config)
        if package_root is not None:
            shutil.rmtree(package_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
