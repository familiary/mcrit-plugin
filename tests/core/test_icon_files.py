"""Every icon the plugins name exists in icons/, and every icon there is used: a missing file only
shows as a blank button or tab."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ICON_NAME = re.compile(r"""["']([\w-]+\.png)["']""")


def _named_icons():
    sources = list((ROOT / "mcrit_plugin").rglob("*.py")) + list(
        (ROOT / "mcrit_plugin").rglob("*.json")
    )
    return {name for path in sources for name in ICON_NAME.findall(path.read_text("utf-8"))}


def test_every_icon_the_code_names_exists():
    named = _named_icons()

    assert named
    assert sorted(name for name in named if not (ROOT / "icons" / name).is_file()) == []


def test_every_shipped_icon_is_used():
    shipped = {path.name for path in (ROOT / "icons").glob("*.png")}

    assert sorted(shipped - _named_icons()) == []
