import bisect
import threading

import binaryninja
from binaryninja.enums import (
    HighlightColorStyle,
    HighlightStandardColor,
    RenderLayerDefaultEnableState,
)

# Binary Ninja composites highlights over the view or graph background, like its own highlighting
HIGHLIGHT_ALPHA = 128


class MatchRenderLayer(binaryninja.RenderLayer):
    """Tints the basic blocks of the local function that MCRIT matched, in Binary Ninja's own
    graph and linear views (layer "MCRIT Matches" in the render layer menu).

    The match colouring is shared state keyed by file session, because Binary Ninja instantiates
    and calls the registered layer itself, possibly from its render threads.
    """

    name = "MCRIT Matches"
    default_enable_state = (
        RenderLayerDefaultEnableState.EnabledByDefaultRenderLayerDefaultEnableState
    )

    _lock = threading.Lock()
    # session id -> (sorted range starts, the (start, end, 0xRRGGBB) ranges in the same order)
    _ranges = {}

    @classmethod
    def set_coloring(cls, session_id, ranges):
        with cls._lock:
            if ranges:
                ranges = sorted(ranges)
                cls._ranges[session_id] = ([start for start, _, _ in ranges], ranges)
            else:
                cls._ranges.pop(session_id, None)

    @classmethod
    def clear(cls, session_id):
        cls.set_coloring(session_id, None)

    @classmethod
    def color_at(cls, session_id, address):
        with cls._lock:
            coloring = cls._ranges.get(session_id)
        if coloring is None or address is None:
            return None
        starts, ranges = coloring
        position = bisect.bisect_right(starts, address) - 1
        if position >= 0:
            start, end, rgb = ranges[position]
            if address < end:
                return rgb
        return None

    def apply_to_block(self, block, lines):
        # one override for disassembly and IL blocks in graph view and, through the base class, in
        # linear view; IL blocks are located by the disassembly block they were lifted from
        source = block.source_block if block.is_il else block
        if source is None:
            return lines
        rgb = self.color_at(source.view.file.session_id, source.start)
        if rgb is not None:
            highlight = _highlight(rgb)
            for line in lines:
                _tint(line, highlight)
        return lines

    def apply_to_high_level_il_body(self, function, lines):
        # linear view hands HLIL and Pseudo-C function bodies over without basic blocks, so each
        # line is placed by its own address
        session_id = function.view.file.session_id
        highlights = {}
        for line in lines:
            rgb = self.color_at(session_id, line.contents.address)
            if rgb is not None:
                if rgb not in highlights:
                    highlights[rgb] = _highlight(rgb)
                _tint(line.contents, highlights[rgb])
        return lines


def _highlight(rgb):
    return binaryninja.HighlightColor(
        red=(rgb >> 16) & 0xFF, green=(rgb >> 8) & 0xFF, blue=rgb & 0xFF, alpha=HIGHLIGHT_ALPHA
    )


def _tint(line, highlight):
    """Tint a line unless the analyst highlighted it."""
    current = line.highlight
    if (
        current.style == HighlightColorStyle.StandardHighlightColor
        and current.color == HighlightStandardColor.NoHighlightColor
    ):
        line.highlight = highlight


_registered = False


def register_layer():
    global _registered
    if not _registered:
        MatchRenderLayer.register()
        _registered = True
