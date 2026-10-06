"""The MCRIT render layer tints exactly the blocks inside the colored address ranges.

binaryninja is stubbed: RenderLayer is an empty base class and highlights are plain objects.
"""

import importlib
import sys
import types

import pytest


class _Highlight:
    def __init__(self, red, green, blue, alpha):
        self.rgba = (red, green, blue, alpha)


class _Line:
    highlight = None


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
        )
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
        assert lines[0].highlight is None


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
