import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from plugin_archive import write_archive  # noqa: E402

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

# other disassemblers' code is not shipped; the manifest and entry point are already at the root
EXCLUDE_RELATIVE_PATHS = {
    "mcrit_plugin/binja",
    "mcrit_plugin/ghidra",
    "mcrit_plugin/headless",
    "mcrit_plugin/ida/ida-plugin.json",
    "mcrit_plugin/ida/ida_mcrit.py",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a minimal ZIP archive for the MCRIT IDA plugin."
    )
    parser.add_argument("--repo", required=True, help="Path to the repository root")
    parser.add_argument("--output", required=True, help="Path to the output ZIP file")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()

    manifest_path = repo / "mcrit_plugin" / "ida" / "ida-plugin.json"
    plugin_name = json.loads(manifest_path.read_text(encoding="utf-8"))["plugin"]["name"]
    written_files = write_archive(repo, output, INCLUDE_PATHS, EXCLUDE_RELATIVE_PATHS)

    print(f"[INFO] Packaged plugin: {plugin_name}")
    print(f"[INFO] Output archive: {output}")
    print(f"[INFO] Files written: {len(written_files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
