"""The release gate (`.github/workflows/scripts/ida/release_guard.py`) runs once per release, so here is
the only place its checks can be exercised before they matter."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "workflows" / "scripts" / "ida" / "release_guard.py"

CHANGELOG = """# Changelog

## [Unreleased]

### Fixed

- something not yet released.

## [1.2.0] - 2026-09-20

### Changed

- the thing this release did.

## [1.2.0rc1] - 2026-09-15

### Added

- the candidate.

## Older releases

### v1.1.9 (2026-08-04)
- the README shape.
"""


@pytest.fixture(scope="module")
def guard():
    if not SCRIPT.exists():
        pytest.skip("running outside a source tree")
    spec = importlib.util.spec_from_file_location("release_guard", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, version: str, changelog: str = CHANGELOG) -> Path:
    ida = tmp_path / "mcrit_plugin" / "ida"
    ida.mkdir(parents=True)
    (ida / "ida-plugin.json").write_text(
        f'{{\n  "plugin": {{\n    "name": "mcrit-ida",\n    "version": "{version}",\n    "x": 1\n  }}\n}}\n'
    )
    (ida / "config.py").write_text(f'VERSION = "{version}"\n')
    (tmp_path / "CHANGELOG.md").write_text(changelog)
    return tmp_path


def test_the_section_for_a_version_is_returned_and_stops_at_the_next(guard):
    notes = guard.changelogSection(CHANGELOG, "1.2.0")
    assert "the thing this release did" in notes
    assert "the candidate" not in notes
    assert "not yet released" not in notes
    assert "README shape" not in notes


def test_a_missing_or_empty_or_undated_section_fails(guard):
    with pytest.raises(SystemExit, match="Unreleased"):
        guard.changelogSection(CHANGELOG, "1.3.0")
    with pytest.raises(SystemExit, match="nothing under it"):
        guard.changelogSection(
            "# Changelog\n\n## [9.0.0] - 2026-01-01\n\n## Older releases\n\n- x\n", "9.0.0"
        )
    with pytest.raises(SystemExit):
        guard.changelogSection("# Changelog\n\n## [9.0.0]\n\n- something.\n", "9.0.0")


def test_the_declared_versions_in_this_tree_agree(guard):
    versions = guard.declaredVersions(ROOT)
    assert set(versions) == {"ida-plugin.json plugin.version", "config.py VERSION"}
    assert len(set(versions.values())) == 1


def test_a_matching_tag_passes_and_writes_notes_and_outputs(guard, tmp_path):
    root = _tree(tmp_path, "1.2.0")
    notes, output = root / "notes.md", root / "output.txt"
    argv = [
        "--tag",
        "ida-v1.2.0",
        "--root",
        str(root),
        "--notes",
        str(notes),
        "--github-output",
        str(output),
    ]
    assert guard.main(argv) == 0
    assert "the thing this release did" in notes.read_text()
    assert output.read_text() == "version=1.2.0\nprerelease=false\n"


def test_a_pre_release_tag_is_flagged(guard, tmp_path):
    root = _tree(tmp_path, "1.2.0rc1")
    output = root / "output.txt"
    assert (
        guard.main(["--tag", "ida-v1.2.0rc1", "--root", str(root), "--github-output", str(output)])
        == 0
    )
    assert "prerelease=true" in output.read_text()


@pytest.mark.parametrize(
    "tag", ["1.2.0", "v1.2.0", "ida-v1.2", "ida-v1.2.0-rc1", "ida-v1.2.0.dev1", "ida-vlatest"]
)
def test_a_malformed_tag_fails(guard, tmp_path, tag):
    root = _tree(tmp_path, "1.2.0")
    with pytest.raises(SystemExit):
        guard.main(["--tag", tag, "--root", str(root)])


def test_a_tag_disagreeing_with_any_declared_version_fails(guard, tmp_path):
    root = _tree(tmp_path, "1.1.9")
    with pytest.raises(SystemExit, match=r"1\.1\.9"):
        guard.main(["--tag", "ida-v1.2.0", "--root", str(root)])
    (root / "mcrit_plugin" / "ida" / "config.py").write_text('VERSION = "1.2.0"\n')
    with pytest.raises(SystemExit, match=r"plugin\.version = 1\.1\.9"):
        guard.main(["--tag", "ida-v1.2.0", "--root", str(root)])
