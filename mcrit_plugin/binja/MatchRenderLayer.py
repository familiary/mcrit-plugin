import threading

import binaryninja
from binaryninja.enums import RenderLayerDefaultEnableState

# Binary Ninja composites highlights over the view background, like its own highlighting
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
    # session id -> sorted list of (start, end, 0xRRGGBB) address ranges
    _ranges = {}

    @classmethod
    def set_coloring(cls, session_id, ranges):
        with cls._lock:
            if ranges:
                cls._ranges[session_id] = sorted(ranges)
            else:
                cls._ranges.pop(session_id, None)

    @classmethod
    def clear(cls, session_id):
        cls.set_coloring(session_id, None)

    @classmethod
    def color_at(cls, session_id, address):
        with cls._lock:
            ranges = cls._ranges.get(session_id)
        if not ranges:
            return None
        for start, end, rgb in ranges:
            if start <= address < end:
                return rgb
        return None

    def apply_to_block(self, block, lines):
        # one override for disassembly and IL blocks in graph view and, through the base class, in
        # linear view; IL blocks are located by the disassembly block they were lifted from
        source = block.source_block if block.is_il else block
        if source is None:
            return lines
        rgb = self.color_at(source.view.file.session_id, source.start)
        if rgb is None:
            return lines
        highlight = binaryninja.HighlightColor(
            red=(rgb >> 16) & 0xFF,
            green=(rgb >> 8) & 0xFF,
            blue=rgb & 0xFF,
            alpha=HIGHLIGHT_ALPHA,
        )
        for line in lines:
            line.highlight = highlight
        return lines


_registered = False


def register_layer():
    global _registered
    if not _registered:
        MatchRenderLayer.register()
        _registered = True
