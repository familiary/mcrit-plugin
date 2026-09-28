import argparse
import json
import re
import sys
from pathlib import Path


def extract_config_version(config_path: Path) -> str:
    match = re.search(
        r'^VERSION = "([^"]+)"', config_path.read_text(encoding="utf-8"), re.MULTILINE
    )
    if not match:
        raise ValueError(f"Could not find VERSION in {config_path}")
    return match.group(1)


def extract_changelog_release_version(changelog_path: Path) -> str:
    # the newest heading is either a Keep a Changelog section or, below `## Older releases`,
    # one of the headings carried over from the README
    match = re.search(
        r"^(?:## \[v?(\d+\.\d+\.\d+[0-9a-z]*)\] - \d{4}-\d{2}-\d{2}|### v(\d+\.\d+\.\d+)\b)",
        changelog_path.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not match:
        raise ValueError(f"Could not find latest release heading in {changelog_path}")
    return match.group(1) or match.group(2)


def extract_readme_min_ida_version(readme_path: Path) -> str:
    text = readme_path.read_text(encoding="utf-8")
    patterns = [
        r"badge/IDA-(\d+(?:\.\d+)?)%2B",
        r"\bIDA (\d+(?:\.\d+)?)\+",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    raise ValueError(f"Could not determine README minimum IDA version from {readme_path}")


def extract_plugin_min_ida_version(value: str) -> str:
    match = re.search(r">=\s*(\d+(?:\.\d+)?)", value)
    if not match:
        raise ValueError(f"Unsupported plugin idaVersions format: {value}")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="Path to the repository root")
    parser.add_argument(
        "--expected-version",
        help="Optional semantic version that mcrit_plugin/ida/config.py, ida-plugin.json, and CHANGELOG.md must all match",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    config_path = repo / "mcrit_plugin" / "ida" / "config.py"
    plugin_path = repo / "mcrit_plugin" / "ida" / "ida-plugin.json"
    readme_path = repo / "README.md"
    changelog_path = repo / "CHANGELOG.md"

    plugin_data = json.loads(plugin_path.read_text(encoding="utf-8"))
    config_version = extract_config_version(config_path)
    plugin_version = plugin_data["plugin"]["version"]
    changelog_version = extract_changelog_release_version(changelog_path)
    plugin_min_ida = extract_plugin_min_ida_version(plugin_data["plugin"]["idaVersions"])
    readme_min_ida = extract_readme_min_ida_version(readme_path)

    print(f"[INFO] mcrit_plugin/ida/config.py VERSION: {config_version}")
    print(f"[INFO] ida-plugin.json plugin.version: {plugin_version}")
    print(f"[INFO] CHANGELOG.md latest release version: {changelog_version}")
    print(f"[INFO] ida-plugin.json minimum IDA version: {plugin_min_ida}")
    print(f"[INFO] README top-level minimum IDA version: {readme_min_ida}")

    failures: list[str] = []
    if config_version != changelog_version:
        failures.append(
            "Version mismatch: mcrit_plugin/ida/config.py VERSION does not match latest CHANGELOG.md release heading."
        )
    if plugin_version != changelog_version:
        failures.append(
            "Version mismatch: ida-plugin.json plugin.version does not match latest CHANGELOG.md release heading."
        )
    if plugin_min_ida != readme_min_ida:
        failures.append(
            "IDA compatibility mismatch: ida-plugin.json plugin.idaVersions and README top-level compatibility badge/text are inconsistent."
        )

    if args.expected_version:
        if config_version != args.expected_version:
            failures.append(
                f"Version mismatch: mcrit_plugin/ida/config.py VERSION does not match expected version {args.expected_version}."
            )
        if plugin_version != args.expected_version:
            failures.append(
                f"Version mismatch: ida-plugin.json plugin.version does not match expected version {args.expected_version}."
            )
        if changelog_version != args.expected_version:
            failures.append(
                f"Version mismatch: CHANGELOG.md latest release heading does not match expected version {args.expected_version}."
            )

    if failures:
        print("[FAIL] Metadata consistency checks failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("[PASS] Metadata consistency checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
