"""Build the MCRIT Ghidra extension ZIP, installed with File > Install Extensions in Ghidra.

Ghidra adds an installed extension's ghidra_scripts folder to the Script Manager by itself, so
MCRIT.py shows up without managing script directories. extension.properties carries the Ghidra
version the extension is marked for; Ghidra offers to install it into another version anyway.
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from plugin_archive import write_archive  # noqa: E402

EXTENSION_NAME = "MCRIT"
# the oldest Ghidra the plugin supports; see the README
DEFAULT_GHIDRA_VERSION = "12.0"

# (source in the repository, path inside the extension folder)
INCLUDE_PATHS = [
    ("mcrit_plugin/ghidra/ghidra_scripts/MCRIT.py", "ghidra_scripts/MCRIT.py"),
    ("docs/config_override.json.template", "config_override.json.template"),
    ("LICENSE", "LICENSE"),
    ("README.md", "README.md"),
    ("icons", "icons"),
    ("mcrit_plugin", "mcrit_plugin"),
]

# other disassemblers' code is not shipped; the script is already in ghidra_scripts
EXCLUDE_RELATIVE_PATHS = {
    "mcrit_plugin/binja",
    "mcrit_plugin/headless",
    "mcrit_plugin/ida",
    "mcrit_plugin/ghidra/ghidra_scripts",
}


def extension_properties(ghidra_version, plugin_version):
    return "\n".join(
        [
            f"name={EXTENSION_NAME}",
            "description=MCRIT client: match functions and blocks against an MCRIT server "
            f"(plugin {plugin_version}). Run Tools > MCRIT after ticking In Tool for MCRIT.py "
            "in the Script Manager.",
            "author=Daniel Plohmann",
            "createdOn=",
            f"version={ghidra_version}",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the MCRIT Ghidra extension ZIP.")
    parser.add_argument("--repo", required=True, help="Path to the repository root")
    parser.add_argument("--output", required=True, help="Path to the output ZIP file")
    parser.add_argument(
        "--ghidra-version",
        default=DEFAULT_GHIDRA_VERSION,
        help=f"Ghidra version written into extension.properties (default {DEFAULT_GHIDRA_VERSION})",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    config = (repo / "mcrit_plugin" / "ghidra" / "config.py").read_text(encoding="utf-8")
    version = re.search(r'^VERSION = "([^"]+)"', config, re.MULTILINE).group(1)

    written = write_archive(
        repo,
        args.output,
        INCLUDE_PATHS,
        EXCLUDE_RELATIVE_PATHS,
        prefix=EXTENSION_NAME,
        extra_files=[
            ("extension.properties", extension_properties(args.ghidra_version, version)),
            ("Module.manifest", ""),
        ],
    )
    print(f"[INFO] Packaged Ghidra extension {EXTENSION_NAME} {version}")
    print(f"[INFO] Output archive: {Path(args.output).resolve()}")
    print(f"[INFO] Files written: {len(written)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
