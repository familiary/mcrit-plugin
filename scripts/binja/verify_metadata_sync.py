#!/usr/bin/env python3
"""Check that the Binary Ninja plugin metadata agrees with itself and with what users install.

The extension manager installs from the GitHub source archive of the latest release, reads
plugin.json at its root and installs requirements.txt, so the committed archive is checked too.
"""

import argparse
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path

ARCHIVE_ROOT_FILES = ("plugin.json", "__init__.py", "requirements.txt", "LICENSE")


def extract_readme_min_build(readme_path: Path) -> int:
    match = re.search(
        r"Requires Binary Ninja \d+\.\d+ \(build (\d+)\)", readme_path.read_text(encoding="utf-8")
    )
    if not match:
        raise ValueError(
            f"Could not determine README minimum Binary Ninja build from {readme_path}"
        )
    return int(match.group(1))


def read_requirements(requirements_path: Path) -> list[str]:
    lines = requirements_path.read_text(encoding="utf-8").splitlines()
    return sorted(line.strip() for line in lines if line.strip() and not line.startswith("#"))


def archive_names(repo: Path) -> list[str]:
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", "HEAD"],
        capture_output=True,
        check=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        return tar.getnames()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Path to the repository root")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    manifest = json.loads((repo / "plugin.json").read_text(encoding="utf-8"))
    manifest_pip = sorted(manifest.get("dependencies", {}).get("pip", []))
    requirements = read_requirements(repo / "requirements.txt")
    manifest_min_build = manifest["minimumbinaryninjaversion"]
    readme_min_build = extract_readme_min_build(repo / "README.md")
    names = archive_names(repo)

    print(f"[INFO] plugin.json version: {manifest['version']}")
    print(f"[INFO] plugin.json dependencies.pip: {manifest_pip}")
    print(f"[INFO] requirements.txt: {requirements}")
    print(f"[INFO] plugin.json minimum Binary Ninja build: {manifest_min_build}")
    print(f"[INFO] README minimum Binary Ninja build: {readme_min_build}")
    print(f"[INFO] source archive of HEAD: {len(names)} entries")

    failures: list[str] = []
    if manifest_pip != requirements:
        failures.append(
            "Dependency mismatch: plugin.json dependencies.pip does not match requirements.txt."
        )
    if manifest_min_build != readme_min_build:
        failures.append(
            "Binary Ninja compatibility mismatch: plugin.json minimumbinaryninjaversion and the README build are inconsistent."
        )
    missing = [name for name in ARCHIVE_ROOT_FILES if name not in names]
    if missing:
        failures.append(f"Source archive of HEAD lacks root files: {', '.join(missing)}.")
    shipped_dirs = [
        name
        for name in names
        if name.startswith("scripts/") or name.startswith("tests/") or name in ("scripts", "tests")
    ]
    if shipped_dirs:
        failures.append(
            "Source archive of HEAD contains scripts/ or tests/; they would become importable top-level packages."
        )
    leaked = [name for name in names if name.endswith("ida-plugin.json")]
    if leaked:
        failures.append(
            f"Source archive of HEAD contains {', '.join(leaked)}; HCLI would index it as an IDA plugin."
        )

    if failures:
        print("[FAIL] Metadata consistency checks failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("[PASS] Metadata consistency checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
