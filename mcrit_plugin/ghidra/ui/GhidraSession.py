"""Per-program state of the Ghidra frontend.

McritSession holds the state the widgets share and its report, label-sync and download logic does
not touch Qt; only its constructor, widget setup and clipboard do. GhidraSession replaces those
three with Swing and inherits the rest, so both frontends keep one copy of that logic.
"""

import time

from mcrit_plugin.core.McritInterface import McritInterface
from mcrit_plugin.ghidra.ui.components import copy_to_clipboard
from mcrit_plugin.ui_qt.McritSession import McritSession


class _Classes:
    """The part of the Qt ClassCollection the shared code reads: the backend."""

    def __init__(self, backend):
        self.backend = backend


class GhidraSession(McritSession):
    def __init__(self, backend, config):
        # McritSession.__init__ imports Qt, so the state is set up here instead
        self.cc = _Classes(backend)
        self.config = config
        self.tabs = None
        self.parent = None
        self.remote_sample_id = None
        self.remote_sample_entry = None
        self.local_smda_report = None
        self.local_smda_report_outline = None
        self._outline_source = None
        self.matching_job_id = None
        self.matching_report = None
        self.matched_function_entries = None
        self.current_block = None
        self.current_function = None
        self.function_matches = {}
        self.block_to_hash = {}
        self.blockhash_matches = {}
        self.sample_infos = None
        self.family_infos = None
        self.function_id_to_offset = {}
        self.hook_subscribed_widgets = []
        self.component = None
        # McritInterface reports to local_widget from its constructor on, so it exists first
        from mcrit_plugin.ghidra.ui.LocalInfoPanel import LocalInfoPanel

        self.local_widget = LocalInfoPanel(self)
        self.mcrit_interface = McritInterface(self, backend)

    def copyStringToClipboard(self, string_to_copy):
        if string_to_copy is not None:
            copy_to_clipboard(string_to_copy)
            self.local_widget.updateActivityInfo('Copied "%s" to the clipboard.' % string_to_copy)

    def setupWidgets(self):
        """Create the panels; self.component is the Swing component hosting them."""
        from mcrit_plugin.ghidra.ui.BlockMatchPanel import BlockMatchPanel
        from mcrit_plugin.ghidra.ui.FunctionMatchPanel import FunctionMatchPanel
        from mcrit_plugin.ghidra.ui.FunctionOverviewPanel import FunctionOverviewPanel
        from mcrit_plugin.ghidra.ui.MainPanel import MainPanel
        from mcrit_plugin.ghidra.ui.SampleInfoPanel import SampleInfoPanel

        started = time.time()
        self.block_match_widget = BlockMatchPanel(self)
        self.function_match_widget = FunctionMatchPanel(self)
        self.sample_widget = SampleInfoPanel(self)
        self.function_widget = FunctionOverviewPanel(self)
        self.main_widget = MainPanel(self)
        self.hook_subscribed_widgets = [self.function_match_widget, self.block_match_widget]
        self.component = self.main_widget.component
        print("[MCRIT] panels ready in %3.2f seconds" % (time.time() - started))
