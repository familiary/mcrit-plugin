"""ZIP building shared by the IDA plugin and Ghidra extension packagers."""

import stat
import subprocess
import time
import zipfile
from pathlib import Path

EXCLUDE_DIR_NAMES = {"__pycache__"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}
REVISION_FILE = "mcrit_plugin/core/revision.py"
REVISION_PLACEHOLDER = '"$Format:%H$"'


def _should_include(path: Path) -> bool:
    return not any(part in EXCLUDE_DIR_NAMES for part in path.parts) and (
        path.suffix not in EXCLUDE_SUFFIXES
    )


def _iter_files(root: Path, relative_path: str, excluded: set[Path]) -> list[Path]:
    source_path = root / relative_path
    if not source_path.exists():
        raise FileNotFoundError(f"Required packaging path is missing: {source_path}")
    if source_path.is_file():
        return [source_path]
    return sorted(
        path
        for path in source_path.rglob("*")
        if path.is_file()
        and _should_include(path)
        and not any(path.relative_to(root).is_relative_to(skip) for skip in excluded)
    )


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


def _write_text(archive, arcname, text):
    # writestr alone gives the member mode 0600, which Ghidra applies when it unpacks
    info = zipfile.ZipInfo(arcname, date_time=time.localtime()[:6])
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    archive.writestr(info, text)


def _write_directory(archive, arcname):
    info = zipfile.ZipInfo(arcname + "/", date_time=time.localtime()[:6])
    # 0x10 is the MS-DOS directory flag, which ZIP readers also check
    info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
    archive.writestr(info, b"")


def write_archive(
    repo, output, include_paths, excluded, prefix="", extra_files=(), directories=False
):
    """Write the ZIP and return its member names.

    include_paths holds (source in the repository, path inside the archive) pairs; excluded holds
    repository paths left out; prefix is a folder every member goes under; extra_files holds
    (path inside the archive, text) pairs written as they are. directories adds an entry for every
    folder ahead of its files, for unpackers that do not create folders themselves.
    """
    repo, output = Path(repo).resolve(), Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    root = Path(prefix)
    members = []
    for relative_path, archive_path in include_paths:
        source_root = repo / relative_path
        for source_path in _iter_files(repo, relative_path, set(map(Path, excluded))):
            inner = source_path.relative_to(source_root) if source_root.is_dir() else Path()
            member = (Path(archive_path) / inner).as_posix()
            text = _stamped_revision_source(repo) if member == REVISION_FILE else None
            members.append(((root / member).as_posix(), source_path, text))
    members += [((root / member).as_posix(), None, text) for member, text in extra_files]
    written = []
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if directories:
            folders = {
                parent.as_posix()
                for arcname, _source, _text in members
                for parent in Path(arcname).parents
                if parent != Path(".")
            }
            for folder in sorted(folders):
                _write_directory(archive, folder)
                written.append(folder + "/")
        for arcname, source_path, text in members:
            if text is not None:
                _write_text(archive, arcname, text)
            else:
                archive.write(source_path, arcname)
            written.append(arcname)
    return written
