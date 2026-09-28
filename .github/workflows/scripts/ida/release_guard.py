"""Checks that decide whether a tag may be released, and the notes that go with it.

A script rather than inline workflow steps so the parsing has tests: the changelog format it
reads is a convention, and a release is the one action here that cannot be undone.

The same script, with a different VERSION_SOURCES table, guards every repository in the MCRIT
ecosystem. Keep the logic identical across them and vary only the table.
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path

#: Where this repository states its version. Every entry has to agree with the tag.
#: ("label", "relative/path", regex-with-one-group) reads a literal from a text file;
#: ("label", "pyproject.toml", None) reads `[project].version`.
VERSION_SOURCES = [
    (
        "ida-plugin.json plugin.version",
        "mcrit_plugin/ida/ida-plugin.json",
        r'^    "version": "([0-9][0-9a-z.]*)",$',
    ),
    ("config.py VERSION", "mcrit_plugin/ida/config.py", r'^VERSION = "([0-9][0-9a-z.]*)"'),
]
TAG_PREFIX = "ida-v"

VERSION = re.compile(r"^(?P<release>\d+\.\d+\.\d+)(?P<pre>(a|b|rc)\d+)?$")
SECTION = re.compile(r"^## \[v?(?P<version>[0-9][0-9a-z.]*)\] - (?P<date>\d{4}-\d{2}-\d{2})\s*$")
NEXT_HEADING = re.compile(r"^## ")


def declaredVersions(root: Path) -> dict:
    """The version as each place that carries it states it."""
    found = {}
    for label, relative, pattern in VERSION_SOURCES:
        path = root / relative
        if pattern is None:
            found[label] = tomllib.loads(path.read_text(encoding="utf-8"))["project"]["version"]
            continue
        match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
        if match is None:
            raise SystemExit(f"could not read a version from {path}")
        found[label] = match.group(1)
    return found


def changelogSection(changelog: str, version: str) -> str:
    """The release notes for `version`, or a failure naming what is missing."""
    lines = changelog.splitlines()
    for index, line in enumerate(lines):
        match = SECTION.match(line)
        if match is None or match.group("version") != version:
            continue
        body = []
        for following in lines[index + 1 :]:
            if NEXT_HEADING.match(following):
                break
            body.append(following)
        text = "\n".join(body).strip()
        if not text:
            raise SystemExit(f"CHANGELOG.md has a heading for {version} but nothing under it")
        return text
    raise SystemExit(
        f"CHANGELOG.md has no `## [{version}] - <date>` section. "
        "Rename `## [Unreleased]` to the release being cut before tagging."
    )


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag", required=True, help=f"the tag being released, e.g. {TAG_PREFIX}1.2.0"
    )
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--notes", help="write the release notes to this file")
    parser.add_argument("--github-output", help="append version= and prerelease= to this file")
    args = parser.parse_args(argv)

    if not args.tag.startswith(TAG_PREFIX):
        raise SystemExit(f"tag {args.tag!r} does not start with {TAG_PREFIX!r}")
    version = args.tag[len(TAG_PREFIX) :]
    shape = VERSION.match(version)
    if shape is None:
        shape_wanted = f"{TAG_PREFIX}MAJOR.MINOR.PATCH with an optional a/b/rc pre-release suffix"
        raise SystemExit(f"tag {args.tag!r} is not {shape_wanted}")

    versions = declaredVersions(Path(args.root))
    disagreeing = {label: value for label, value in versions.items() if value != version}
    if disagreeing:
        stated = ", ".join(f"{label} = {value}" for label, value in versions.items())
        raise SystemExit(f"tag {args.tag} does not match the packaged version ({stated})")

    changelog = (Path(args.root) / "CHANGELOG.md").read_text(encoding="utf-8")
    notes = changelogSection(changelog, version)
    if args.notes:
        Path(args.notes).write_text(notes + "\n", encoding="utf-8")
    if args.github_output:
        prerelease = "true" if shape.group("pre") else "false"
        with open(args.github_output, "a", encoding="utf-8") as output:
            output.write(f"version={version}\nprerelease={prerelease}\n")
    print(f"{args.tag} matches the declared version and has a changelog section")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
