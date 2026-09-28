import argparse
import json
import subprocess
import sys
import zipfile
from pathlib import Path

# (source in the repository, path inside the archive); HCLI requires ida-plugin.json and the entry
# point at the archive root and treats every ida-plugin.json in an archive as a separate plugin
INCLUDE_PATHS = [
    ("mcrit_plugin/ida/ida-plugin.json", "ida-plugin.json"),
    ("mcrit_plugin/ida/ida_mcrit.py", "ida_mcrit.py"),
    ("docs/config_override.json.template", "config_override.json.template"),
    ("LICENSE", "LICENSE"),
    ("README.md", "README.md"),
    ("icons", "icons"),
    ("mcrit_plugin", "mcrit_plugin"),
]

EXCLUDE_DIR_NAMES = {
    "__pycache__",
}

# other disassemblers' code is not shipped; the manifest and entry point are already at the root
EXCLUDE_RELATIVE_PATHS = {
    Path("mcrit_plugin/binja"),
    Path("mcrit_plugin/headless"),
    Path("mcrit_plugin/ida/ida-plugin.json"),
    Path("mcrit_plugin/ida/ida_mcrit.py"),
}

EXCLUDE_SUFFIXES = {
    ".pyc",
    ".pyo",
}


def should_include(path: Path) -> bool:
    if any(part in EXCLUDE_DIR_NAMES for part in path.parts):
        return False
    if path.suffix in EXCLUDE_SUFFIXES:
        return False
    return True


def iter_files(root: Path, relative_path: str) -> list[Path]:
    source_path = root / relative_path
    if not source_path.exists():
        raise FileNotFoundError(f"Required packaging path is missing: {source_path}")

    if source_path.is_file():
        return [source_path]

    return sorted(
        path
        for path in source_path.rglob("*")
        if path.is_file()
        and should_include(path)
        and not any(
            path.relative_to(root).is_relative_to(excluded) for excluded in EXCLUDE_RELATIVE_PATHS
        )
    )


REVISION_FILE = "mcrit_plugin/core/revision.py"
REVISION_PLACEHOLDER = '"$Format:%H$"'


def _stamped_revision_source(repo: Path) -> str:
    """revision.py with the placeholder replaced like `git archive` does for source archives."""
    source = (repo / REVISION_FILE).read_text(encoding="utf-8")
    try:
        commit = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return source
    return source.replace(REVISION_PLACEHOLDER, f'"{commit}"')


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a minimal ZIP archive for the MCRIT IDA plugin."
    )
    parser.add_argument("--repo", required=True, help="Path to the repository root")
    parser.add_argument("--output", required=True, help="Path to the output ZIP file")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    manifest_path = repo / "mcrit_plugin" / "ida" / "ida-plugin.json"
    plugin_name = json.loads(manifest_path.read_text(encoding="utf-8"))["plugin"]["name"]
    written_files: list[str] = []

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path, archive_path in INCLUDE_PATHS:
            source_root = repo / relative_path
            for source_path in iter_files(repo, relative_path):
                inner = source_path.relative_to(source_root) if source_root.is_dir() else Path()
                arcname = (Path(archive_path) / inner).as_posix()
                if arcname == REVISION_FILE:
                    archive.writestr(arcname, _stamped_revision_source(repo))
                else:
                    archive.write(source_path, arcname)
                written_files.append(arcname)

    print(f"[INFO] Packaged plugin: {plugin_name}")
    print(f"[INFO] Output archive: {output}")
    print(f"[INFO] Files written: {len(written_files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
