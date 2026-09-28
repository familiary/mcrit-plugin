import pytest

from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider, ThemeRole
from mcrit_plugin.headless.HeadlessBackend import HeadlessBackend


@pytest.fixture
def headless_backend(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    return HeadlessBackend(str(sample))


def test_backend_default_theme_color_returns_the_default(headless_backend):
    assert headless_backend.theme_color(ThemeRole.RED, (1, 2, 3)) == (1, 2, 3)


def test_backendless_and_default_backend_colors_are_identical(headless_backend):
    plain = ScoreColorProvider()
    themed = ScoreColorProvider(headless_backend)
    scores = [120, 100, 95, 85, 75, 65, 55, 10]
    counts = [0, 1, 2, 4, 8, 16, 32, 64, 1000]
    assert [themed.scoreToColor(s) for s in scores] == [plain.scoreToColor(s) for s in scores]
    assert [themed.frequencyToColor(c) for c in counts] == [
        plain.frequencyToColor(c) for c in counts
    ]
    assert themed.textOnTintColor() == plain.textOnTintColor() == (0, 0, 0)


def test_defaults_match_the_documented_palette():
    scp = ScoreColorProvider()
    assert scp.scoreToColor(120) == (0x00, 0x45, 0xBA)
    assert scp.scoreToColor(100) == (0x00, 0x80, 0xFF)
    assert scp.scoreToColor(10) == (0xFF, 0xFF, 0xFF)
    assert scp.frequencyToColor(1) == (0x10, 0x7F, 0xFC)
    assert scp.frequencyToColor(1000) == (0xB4, 0x00, 0xFF)
    assert scp.roleColor(ThemeRole.CURRENT, (0x00, 0xDD, 0xFF)) == (0x00, 0xDD, 0xFF)
