"""The MCRIT render layer tints exactly the blocks inside the colored address ranges.

binaryninja is stubbed: RenderLayer is an empty base class and highlights are plain objects.
"""

import importlib
import sys
import types

import pytest

STANDARD, CUSTOM = 0, 2
NO_COLOR, RED = 0, 4


class _Highlight:
    def __init__(self, red=None, green=None, blue=None, alpha=255, color=NO_COLOR):
        self.style = CUSTOM if red is not None else STANDARD
        self.color = color
        self.rgba = (red, green, blue, alpha)


UNSET = _Highlight()


class _Line:
    def __init__(self, highlight=UNSET, address=None):
        self.highlight = highlight
        self.address = address


def _block(start, session_id=1, il_source=None):
    view = types.SimpleNamespace(file=types.SimpleNamespace(session_id=session_id))
    return types.SimpleNamespace(
        start=start, view=view, is_il=il_source is not None, source_block=il_source
    )


@pytest.fixture
def layer_module(monkeypatch):
    binaryninja = types.SimpleNamespace(RenderLayer=object, HighlightColor=_Highlight)
    enums = types.SimpleNamespace(
        RenderLayerDefaultEnableState=types.SimpleNamespace(
            EnabledByDefaultRenderLayerDefaultEnableState=1
        ),
        HighlightColorStyle=types.SimpleNamespace(StandardHighlightColor=STANDARD),
        HighlightStandardColor=types.SimpleNamespace(NoHighlightColor=NO_COLOR),
    )
    monkeypatch.setitem(sys.modules, "binaryninja", binaryninja)
    monkeypatch.setitem(sys.modules, "binaryninja.enums", enums)
    monkeypatch.delitem(sys.modules, "mcrit_plugin.binja.MatchRenderLayer", raising=False)
    module = importlib.import_module("mcrit_plugin.binja.MatchRenderLayer")
    module.MatchRenderLayer._ranges = {}
    return module


def test_blocks_inside_a_range_are_tinted(layer_module):
    layer = layer_module.MatchRenderLayer
    layer.set_coloring(1, [(0x1000, 0x1010, 0xFF8000)])
    lines = [_Line(), _Line()]

    assert layer().apply_to_block(_block(0x1000), lines) is lines
    assert all(line.highlight.rgba == (0xFF, 0x80, 0x00, 128) for line in lines)


def test_other_blocks_and_sessions_stay_untouched(layer_module):
    layer = layer_module.MatchRenderLayer
    layer.set_coloring(1, [(0x1000, 0x1010, 0xFF8000)])

    for block in (_block(0x1010), _block(0x0FFF), _block(0x1000, session_id=2)):
        lines = [_Line()]
        layer().apply_to_block(block, lines)
        assert lines[0].highlight is UNSET


def test_il_blocks_use_the_block_they_were_lifted_from(layer_module):
    layer = layer_module.MatchRenderLayer
    layer.set_coloring(1, [(0x1000, 0x1010, 0x00FF00)])
    lines = [_Line()]

    layer().apply_to_block(_block(0, il_source=_block(0x1004)), lines)
    assert lines[0].highlight.rgba == (0, 0xFF, 0, 128)


def test_clear_removes_the_coloring(layer_module):
    layer = layer_module.MatchRenderLayer
    layer.set_coloring(1, [(0x1000, 0x1010, 0x00FF00)])
    layer.clear(1)

    assert layer.color_at(1, 0x1000) is None


def test_lines_the_analyst_highlighted_keep_their_highlight(layer_module):
    layer = layer_module.MatchRenderLayer
    layer.set_coloring(1, [(0x1000, 0x1010, 0xFF8000)])
    own = _Highlight(color=RED)
    lines = [_Line(), _Line(own)]

    layer().apply_to_block(_block(0x1000), lines)

    assert lines[0].highlight.rgba == (0xFF, 0x80, 0x00, 128)
    assert lines[1].highlight is own


def test_hlil_bodies_in_linear_view_are_tinted_by_line_address(layer_module):
    layer = layer_module.MatchRenderLayer
    layer.set_coloring(1, [(0x1000, 0x1010, 0x00FF00)])
    function = types.SimpleNamespace(view=_block(0).view)
    lines = [
        types.SimpleNamespace(contents=_Line(address=address)) for address in (0x1004, 0x1010, None)
    ]

    assert layer().apply_to_high_level_il_body(function, lines) is lines
    assert lines[0].contents.highlight.rgba == (0, 0xFF, 0, 128)
    assert lines[1].contents.highlight is UNSET
    assert lines[2].contents.highlight is UNSET


def test_the_range_lookup_finds_each_block_among_many(layer_module):
    layer = layer_module.MatchRenderLayer
    ranges = [(start, start + 8, start) for start in range(0x1000, 0x1000 + 16 * 500, 16)]
    layer.set_coloring(1, list(reversed(ranges)))

    for start, end, rgb in ranges:
        assert layer.color_at(1, start) == rgb
        assert layer.color_at(1, end - 1) == rgb
        assert layer.color_at(1, end) is None
    assert layer.color_at(1, 0x0FFF) is None
