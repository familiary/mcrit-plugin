#!/usr/bin/env python3
"""Run the Binary Ninja GUI integration test against a live MCRIT server.

A throwaway Binary Ninja user directory is created with a copy of the license, this checkout
linked as a user plugin, and tests/binja/gui_integration.py installed as startup.py. The local Binary Ninja
profile is never modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import time
from pathlib import Path

RESULT_MARKERS = ("MCRIT_BN_INTEGRATION_OK", "MCRIT_BN_INTEGRATION_FAILURE")


def _find_binja_binary(install_dir: Path) -> Path:
    root = install_dir.expanduser().resolve()
    candidates = [
        root / "Contents" / "MacOS" / "binaryninja",
        root / "binaryninja",
        root / "binaryninja.exe",
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(f"Could not find the Binary Ninja executable under {root}")


def _default_install_dir() -> Path:
    if sys.platform == "darwin":
        return Path("/Applications/Binary Ninja.app")
    if os.name == "nt":
        return (
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Vector35" / "BinaryNinja"
        )
    return Path.home() / "binaryninja"


def _default_license() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Binary Ninja" / "license.dat"
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", "")) / "Binary Ninja" / "license.dat"
    return Path.home() / ".binaryninja" / "license.dat"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _prepare_user_dir(
    user_dir: Path, repo_root: Path, license_path: Path, server: str, site_packages: str
) -> Path:
    plugins_dir = user_dir / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(license_path, user_dir / "license.dat")
    plugin_link = plugins_dir / "mcrit_plugin_integration"
    if not plugin_link.exists():
        plugin_link.symlink_to(repo_root, target_is_directory=True)
    settings = {
        "python.virtualenv": site_packages,
        "mcrit.mcrit_server": server,
        "network.enableUpdates": False,
        "ui.allowWelcome": False,
    }
    (user_dir / "settings.json").write_text(json.dumps(settings, indent=2), encoding="utf-8")
    shutil.copy2(repo_root / "tests" / "binja" / "gui_integration.py", user_dir / "startup.py")
    return user_dir / "gui-integration.log"


def _wait_for_result(process: subprocess.Popen, result_log: Path, timeout: int) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = result_log.read_text(encoding="utf-8") if result_log.exists() else ""
        if any(marker in text for marker in RESULT_MARKERS):
            return text
        if process.poll() is not None:
            return text
        time.sleep(2)
    return result_log.read_text(encoding="utf-8") if result_log.exists() else ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", type=Path, default=_default_install_dir())
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mcrit-server", default="http://127.0.0.1:8000/")
    parser.add_argument("--reference-sha256")
    parser.add_argument("--license", type=Path, default=_default_license())
    parser.add_argument(
        "--site-packages",
        default=sysconfig.get_paths()["purelib"],
        help="Python site-packages with smda and requests (default: this interpreter's)",
    )
    parser.add_argument("--timeout", type=int, default=600, help="Overall timeout in seconds")
    parser.add_argument("--step-timeout", type=int, default=120)
    parser.add_argument("--log", type=Path, help="Binary Ninja debug log output")
    parser.add_argument("--keep-user-dir", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    input_path = args.input.expanduser().resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f"Input binary does not exist: {input_path}")
    if not args.license.is_file():
        raise FileNotFoundError(f"Binary Ninja license not found: {args.license}")
    binary = _find_binja_binary(args.install_dir)

    user_dir = Path(tempfile.mkdtemp(prefix="mcrit-binja-integration-"))
    process = None
    try:
        result_log = _prepare_user_dir(
            user_dir, repo_root, args.license, args.mcrit_server, args.site_packages
        )
        environment = os.environ.copy()
        environment.update(
            {
                "BN_USER_DIRECTORY": str(user_dir),
                "MCRIT_BN_INTEGRATION_SHA256": _sha256(input_path),
                "MCRIT_BN_INTEGRATION_TIMEOUT": str(args.step_timeout),
                "PYTHONUTF8": "1",
            }
        )
        if args.reference_sha256:
            environment["MCRIT_BN_INTEGRATION_REFERENCE_SHA256"] = args.reference_sha256
        command = [str(binary), "-n"]
        if args.log:
            command += ["-l", str(args.log.expanduser().resolve())]
        command.append(str(input_path))
        process = subprocess.Popen(command, env=environment)
        text = _wait_for_result(process, result_log, args.timeout)
        print(text, end="")
        if "MCRIT_BN_INTEGRATION_OK" not in text:
            print("[binja-integration] failed", file=sys.stderr)
            return 1
        print(f"[binja-integration] completed successfully (user directory: {user_dir})")
        return 0
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if not args.keep_user_dir:
            shutil.rmtree(user_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
