"""Block Scope tab: PicBlockHash matches of the blocks of the function under the cursor. Ports the
Qt BlockMatchWidget; the request, caching and coloring logic is the same."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import mcrit_plugin.core.McritTableColumn as McritTableColumn
from mcrit_plugin.core.minimcrit.matchers.FunctionCfgMatcher import FunctionCfgMatcher
from mcrit_plugin.core.presentation import block_matches_headline, summarize_block_matches
from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider, ThemeRole
from mcrit_plugin.ghidra.ui.components import (
    Label,
    Spinner,
    button,
    checkbox,
    grid,
    separator,
    stack,
)
from mcrit_plugin.ghidra.ui.FunctionMatchPanel import entry_field
from mcrit_plugin.ghidra.ui.table import MatchRow, MatchTableView

BLOCK_QUERY_WORKERS = 8


def packRgb(rgb):
    return (rgb[0] << 16) | (rgb[1] << 8) | rgb[2]


class BlockMatchPanel:
    def __init__(self, parent):
        self.parent = parent
        self.cc = parent.cc
        self.scp = ScoreColorProvider(self.cc.backend)
        self.last_viewed_function = None
        self._request_number = 0
        self.last_viewed_block = None
        self._last_block_matches = None
        self._graph_fetches = set()
        self._shown_function = None
        self._shown_block = None
        self.name = "Block Scope"
        self.icon_file = "puzzle.png"
        config = parent.config
        self.label_current_function_matches = Label("Block Matches for: <function_offset>")
        self.cb_filter_library = checkbox(
            "Filter out Library Matches",
            config.BLOCKS_FILTER_LIBRARY_FUNCTIONS,
            enabled=False,
            on_click=lambda: self.hook_refresh(None, use_current_block=True),
        )
        self.cb_activate_live_tracking = checkbox(
            "Live Block Queries",
            config.BLOCKS_LIVE_QUERY,
            enabled=False,
            on_click=self._onCbLiveClicked,
        )
        self.sb_blocksize_threshold = Spinner(
            4, 20, config.BLOCKS_MIN_SIZE, on_change=self.updateViewWithCurrentBlock
        )
        self.b_query_single = button(
            "Query current basic block", self.queryCurrentBlock, enabled=False
        )
        self.label_block_summary = Label("Blocks Summary")
        self.table_block_summary = MatchTableView()
        self.table_block_summary.on_click(self._onBlockSummaryClicked)
        self.label_block_matches = Label("Block Matches for <block_offset>")
        self.table_block_matches = MatchTableView()
        self.table_block_matches.on_click(self._onBlockMatchClicked)
        self.table_block_matches.on_popup(self._onBlockMatchPopup)
        controls = grid(
            [
                (self.cb_filter_library, Label("Min. Block Size:", wrap=False).component),
                (self.cb_activate_live_tracking, self.sb_blocksize_threshold.component),
            ]
        )
        self.component = stack(
            self.label_current_function_matches.component,
            controls,
            self.b_query_single,
            separator(),
            self.label_block_summary.component,
            self.table_block_summary.component,
            self.label_block_matches.component,
            self.table_block_matches.component,
            fill=(self.table_block_summary.component, self.table_block_matches.component),
        )
        self.clearTable()

    def _onCbLiveClicked(self):
        if self.cb_activate_live_tracking.isSelected():
            self.queryCurrentBlock()

    def enable(self):
        for widget in (self.cb_filter_library, self.cb_activate_live_tracking, self.b_query_single):
            widget.setEnabled(True)
        self.label_current_function_matches.setText(
            "Move the cursor to a basic block, or query the current one."
        )

    def _get_sample_entry(self, sample_id):
        infos = self.parent.sample_infos
        return infos.get(sample_id) if isinstance(infos, dict) else None

    def _get_family_entry(self, family_id):
        infos = self.parent.family_infos
        return infos.get(family_id) if isinstance(infos, dict) else None

    @staticmethod
    def _headers(column_types):
        return [McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col] for col in column_types]

    def clearTable(self):
        config = self.parent.config
        self.table_block_summary.reset(self._headers(config.BLOCK_SUMMARY_TABLE_COLUMNS), [])
        self.table_block_matches.reset(self._headers(config.BLOCK_MATCHES_TABLE_COLUMNS), [])

    def updateCurrentBlock(self, view):
        function_start = self.cc.backend.get_current_function(view)
        if function_start is None:
            return None
        self.parent.current_function = function_start
        address = self.cc.backend.get_cursor_address()
        block = (
            self.parent.local_smda_report.findBlockByContainedAddress(address)
            if address is not None
            else None
        )
        if block:
            self.parent.current_block = block.offset
        return function_start

    def queryCurrentBlock(self):
        self.parent.main_widget.hideLocalWidget()
        address = self.cc.backend.get_cursor_address()
        if address is not None and self.parent.local_smda_report is not None:
            block = self.parent.local_smda_report.findBlockByContainedAddress(address)
            if block:
                self.parent.current_block = block.offset
                self.parent.current_function = block.smda_function.offset
        if self.parent.current_function is None:
            self.label_current_function_matches.setText("Place the cursor in a function first.")
            return
        self.updateViewWithCurrentBlock()

    def hook_refresh(self, view, use_current_block=False):
        if self.parent.local_smda_report is None:
            self.label_current_function_matches.setText("Convert to SMDA report first.")
            return
        if self.updateCurrentBlock(view) is None and not use_current_block:
            return
        if self.parent.current_function == self.last_viewed_function and not use_current_block:
            return
        if not self.cb_activate_live_tracking.isSelected():
            self.clearTable()
            self.label_current_function_matches.setText("Live Block Queries are deactivated.")
            return
        self.updateViewWithCurrentBlock()

    def updateViewWithCurrentBlock(self):
        if self.parent.local_smda_report is None or self.parent.current_function is None:
            return
        self._request_number += 1
        request_number = self._request_number
        function_offset = self.parent.current_function
        self.last_viewed_function = function_offset
        self.last_viewed_block = self.parent.current_block
        smda_function = self.parent.local_smda_report.getFunction(function_offset)
        if smda_function is None or smda_function.num_instructions < 4:
            self.clearTable()
            self.label_current_function_matches.setText(
                "Can only query functions with 4 instructions or more."
            )
            return
        pbh = FunctionCfgMatcher.getPicBlockHashesForFunction(
            self.parent.local_smda_report,
            smda_function,
            min_size=self.sb_blocksize_threshold.value(),
        )

        def superseded():
            return (
                self.parent.current_function != function_offset
                or request_number != self._request_number
                or self.cc.backend.closed
            )

        def request():
            if superseded():
                return None
            if not self.parent.mcrit_interface.ensureRemoteInformation():
                return False
            self._lookupBlockHashes([entry["hash"] for entry in pbh], stop=superseded)
            return True

        def show(remote_cache_ready):
            if remote_cache_ready is None or superseded():
                return
            if not remote_cache_ready:
                self.last_viewed_function = None
                self.clearTable()
                self.label_current_function_matches.setText(
                    "Remote family/sample info unavailable. Check server connection."
                )
                return
            if self.parent.current_block:
                self.label_block_matches.setText(
                    "No Block Matches for: 0x%x" % self.parent.current_block
                )
            self._showBlockMatches(pbh)

        if (
            self.parent.family_infos is not None
            and self.parent.sample_infos is not None
            and all(entry["hash"] in self.parent.blockhash_matches for entry in pbh)
        ):
            show(True)
        else:
            self.label_current_function_matches.setText(
                "Querying block matches for function 0x%x..." % function_offset
            )
            self.cc.backend.run_request(
                "MCRIT: querying block matches for function 0x%x" % function_offset, request, show
            )

    def _lookupBlockHashes(self, hashes, stop=None):
        missing = [h for h in dict.fromkeys(hashes) if h not in self.parent.blockhash_matches]
        if not missing:
            return
        failed = threading.Event()

        def lookup(block_hash):
            if failed.is_set() or (stop is not None and stop()):
                return None
            matches = self.parent.mcrit_interface.getMatchesForPicBlockHash(block_hash)
            if matches is None:
                failed.set()
            return matches

        start = time.time()
        with ThreadPoolExecutor(BLOCK_QUERY_WORKERS) as pool:
            for block_hash, matches in zip(missing, pool.map(lookup, missing)):
                if matches is not None:
                    self.parent.blockhash_matches[block_hash] = matches
        duration = time.time() - start
        print(f"[MCRIT] querying {len(missing)} blocks took {duration:5.3f} seconds.")

    def _showBlockMatches(self, pbh):
        for entry in pbh:
            self.parent.block_to_hash.setdefault(entry["offset"], entry["hash"])
        filter_library = self.cb_filter_library.isSelected()
        by_offset, families, samples, functions, all_functions = summarize_block_matches(
            pbh, self.parent.blockhash_matches, self.parent.family_infos, filter_library
        )
        offset = self.parent.current_function
        self.label_current_function_matches.setText(
            block_matches_headline(
                offset, families, samples, functions, all_functions, filter_library
            )
        )
        self._last_block_matches = by_offset
        self._shown_function = offset
        self.populateBlockSummaryTable(by_offset)
        self.populateBlockMatchTable(by_offset, self.last_viewed_block)

    def _summaryCell(self, column_type, block_offset, block_entry):
        if column_type == McritTableColumn.OFFSET:
            return "0x%x" % block_offset, block_offset
        if column_type == McritTableColumn.PIC_BLOCK_HASH:
            block_hash = block_entry["picblockhash"]["hash"]
            return "0x%x" % block_hash, block_hash
        if column_type == McritTableColumn.SIZE:
            size = block_entry["picblockhash"]["size"]
            return "%d" % size, size
        keys = {
            McritTableColumn.FAMILIES: "families",
            McritTableColumn.SAMPLES: "samples",
            McritTableColumn.FUNCTIONS: "functions",
        }
        if column_type in keys:
            count = block_entry["summary"][keys[column_type]]
            return "%d" % count, count
        if column_type == McritTableColumn.IS_LIBRARY:
            text = "YES" if block_entry["has_library_matches"] else "NO"
            return text, text
        return "", ""

    def populateBlockSummaryTable(self, block_matches):
        column_types = self.parent.config.BLOCK_SUMMARY_TABLE_COLUMNS
        rows = []
        for block_offset, block_entry in sorted(block_matches.items()):
            num_families = block_entry["summary"]["families"]
            background = (
                self.scp.frequencyToColor(num_families, opacity=1)[:3] if num_families > 0 else None
            )
            cells = [self._summaryCell(c, block_offset, block_entry) for c in column_types]
            rows.append(
                MatchRow(
                    len(rows),
                    block_offset,
                    [t for t, _ in cells],
                    [k for _, k in cells],
                    background,
                )
            )
        self.table_block_summary.reset(
            self._headers(column_types), rows, self.scp.textOnTintColor()
        )
        self.table_block_summary.fit_columns()

    def _matchCell(self, column_type, match):
        """A block match is (family id, sample id, function id, offset)."""
        if column_type == McritTableColumn.SHA256:
            sha256 = entry_field(self._get_sample_entry(match[1]), "sha256")
            text = sha256[:8] if sha256 else "unknown"
            return text, text
        if column_type == McritTableColumn.OFFSET:
            return "0x%x" % match[3], match[3]
        if column_type == McritTableColumn.FAMILY_NAME:
            name = entry_field(self._get_family_entry(match[0]), "family_name")
            text = name if name else "unknown"
            return text, text
        if column_type == McritTableColumn.FAMILY_ID:
            return "%d" % match[0], match[0]
        if column_type == McritTableColumn.SAMPLE_ID:
            return "%d" % match[1], match[1]
        if column_type == McritTableColumn.FUNCTION_ID:
            return "%d" % match[2], match[2]
        return "", ""

    def populateBlockMatchTable(self, block_matches, block_offset):
        self._shown_block = block_offset
        if block_offset is not None:
            self.label_block_matches.setText("Block Matches for: 0x%x" % block_offset)
        column_types = self.parent.config.BLOCK_MATCHES_TABLE_COLUMNS
        rows = []
        preselect = 0
        if block_matches and block_offset in block_matches:
            for match in sorted(
                block_matches[block_offset]["matches"], key=lambda x: (x[0], x[1], x[2])
            ):
                if block_offset == match[3]:
                    preselect = len(rows)
                cells = [self._matchCell(c, match) for c in column_types]
                rows.append(
                    MatchRow(len(rows), match, [t for t, _ in cells], [k for _, k in cells])
                )
        self.table_block_matches.reset(self._headers(column_types), rows)
        if rows:
            self.table_block_matches.selectEntireRow(self.table_block_matches.positionOf(preselect))
            self.table_block_matches.fit_columns()

    # interaction

    def _onBlockSummaryClicked(self, view_row, column, click_count):
        block_offset = self.table_block_summary.entryAt(view_row)
        if block_offset is None:
            return
        self.parent.current_block = block_offset
        self.populateBlockMatchTable(self._last_block_matches, block_offset)
        offset_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.OFFSET, self.parent.config.BLOCK_SUMMARY_TABLE_COLUMNS
        )
        if click_count == 2 and offset_column is not None and column == offset_column:
            self.cc.backend.jump_to(block_offset)

    def _onBlockMatchClicked(self, view_row, _column, click_count):
        """Double click: the matched remote function's graph, with the matched blocks tinted."""
        if click_count != 2:
            return
        match = self.table_block_matches.entryAt(view_row)
        if match is None:
            return
        _family_id, _sample_id, function_id_b, block_offset_b = match
        if function_id_b in self._graph_fetches:
            return
        self._graph_fetches.add(function_id_b)
        block_matches = self._last_block_matches
        function_offset_a = self._shown_function
        block_a = self._shown_block
        self.parent.local_widget.updateActivityInfo(
            f"Fetching function {function_id_b} for the graph viewer..."
        )

        def show(remote):
            self._graph_fetches.discard(function_id_b)
            if remote is None:
                return
            function_entry_b, smda_function_b, sample_entry_b = remote
            matched_color = packRgb(self.scp.roleColor(ThemeRole.CYAN, (0xC0, 0xF4, 0xFF)))
            current_color = packRgb(self.scp.roleColor(ThemeRole.CURRENT, (0x00, 0xDD, 0xFF)))
            coloring = {}
            for data in block_matches.values():
                for remote_match in data["matches"]:
                    if remote_match[2] == function_entry_b.function_id:
                        coloring[remote_match[3]] = matched_color
            coloring[block_offset_b] = current_color
            self._colorLocalBlocks(
                block_matches,
                function_entry_b.function_id,
                function_offset_a,
                block_a,
                matched_color,
                current_color,
            )
            self.cc.backend.show_function_graph(
                self, sample_entry_b, function_entry_b, smda_function_b, coloring
            )
            self.parent.local_widget.updateActivityInfo(
                f"Opened the graph of function {function_id_b}."
            )

        self.cc.backend.run_request(
            "MCRIT: fetching remote function %d" % function_id_b,
            lambda: self.parent.mcrit_interface.queryRemoteFunction(function_id_b),
            show,
        )

    def _colorLocalBlocks(
        self, block_matches, function_id_b, function_offset_a, block_a, matched_color, current_color
    ):
        smda_function_a = self.parent.local_smda_report.getFunction(function_offset_a)
        if smda_function_a is None:
            return
        local_coloring = {
            offset: matched_color
            for offset, data in block_matches.items()
            if any(match[2] == function_id_b for match in data["matches"])
        }
        if block_a in local_coloring:
            local_coloring[block_a] = current_color
        self.cc.backend.show_local_match_coloring(smda_function_a, local_coloring)

    def _onBlockMatchPopup(self, view_row, column):
        sha256_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SHA256, self.parent.config.BLOCK_MATCHES_TABLE_COLUMNS
        )
        if sha256_column is None or column != sha256_column:
            return
        match = self.table_block_matches.entryAt(view_row)
        sha256 = entry_field(self._get_sample_entry(match[1]), "sha256")
        if sha256:
            self.parent.copyStringToClipboard(sha256)
