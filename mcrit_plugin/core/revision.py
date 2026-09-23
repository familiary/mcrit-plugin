"""Revision of the shared core code, so reports from differently versioned plugins can be compared."""

import os
import subprocess

# expanded by `git archive` (export-subst in .gitattributes) and by scripts/ida/package_plugin.py
ARCHIVE_COMMIT = "$Format:%H$"


def core_revision():
    if not ARCHIVE_COMMIT.startswith("$"):
        return ARCHIVE_COMMIT[:12]
    plugin_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        return subprocess.run(
            ["git", "-C", plugin_root, "rev-parse", "--short=12", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"
