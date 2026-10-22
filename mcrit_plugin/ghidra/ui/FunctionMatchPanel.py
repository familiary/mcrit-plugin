"""Function Scope tab: matches of the function under the cursor and the labels of the matched
functions. Ports the Qt FunctionMatchWidget; the request and caching logic is the same."""

import mcrit_plugin.core.McritTableColumn as McritTableColumn
from mcrit_plugin.core.minimcrit.matchers.FunctionCfgMatcher import FunctionCfgMatcher
from mcrit_plugin.core.minimcrit.storage.MatchingResult import MatchingResult
from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider
from mcrit_plugin.ghidra.ui.components import (
    Label,
    Spinner,
    button,
    checkbox,
    grid,
    separator,
    stack,
)
from mcrit_plugin.ghidra.ui.table import MatchRow, MatchTableView


def entry_field(entry, field):
    if entry is None:
        return None
    if hasattr(entry, field):
        return getattr(entry, field)
    if isinstance(entry, dict):
        return entry.get(field)
    return None


def block_coloring(node_colors):
    """Block offset -> 0xRRGGBB from the matcher's "Node0x<offset>" -> "#RRGGBB" mapping."""
    return {int(k[6:], 16): int(v[1:], 16) for k, v in node_colors.items()}


class FunctionMatchPanel:
    def __init__(self, parent):
        self.parent = parent
        self.cc = parent.cc
        self.scp = ScoreColorProvider(self.cc.backend)
        self.last_viewed = None
        self.name = "Function Scope"
        self.icon_file = "flag-triangle.png"
        self.current_function_offset = None
        self._graph_fetches = set()
        config = parent.config
        self.label_current_function_matches = Label("Matches for: <function_offset>")
        self.cb_filter_library = checkbox(
            "Filter out Library Matches",
            config.FUNCTION_FILTER_LIBRARY_FUNCTIONS,
            enabled=False,
            on_click=lambda: self.hook_refresh(None, use_current_function=True),
        )
        self.cb_activate_live_tracking = checkbox(
            "Live Function Queries",
            config.FUNCTION_LIVE_QUERY,
            enabled=False,
            on_click=self._onCbLiveClicked,
        )
        self.sb_score_threshold = Spinner(
            50, 100, config.FUNCTION_MIN_SCORE, on_change=self.updateViewWithCurrentFunction
        )
        self.b_query_single = button(
            "Query current function", self.queryCurrentFunction, enabled=False
        )
        self.label_function_matches = Label("Function Matches")
        self.table_function_matches = MatchTableView()
        self.table_function_matches.on_click(self._onFunctionMatchClicked)
        self.table_function_matches.on_popup(self._onFunctionMatchPopup)
        self.label_function_names = Label("Names from Matched Functions")
        self.table_function_names = MatchTableView()
        self.table_function_names.on_click(self._onFunctionNameClicked)
        controls = grid(
            [
                (self.cb_filter_library, Label("Min. Score:", wrap=False).component),
                (self.cb_activate_live_tracking, self.sb_score_threshold.component),
            ]
        )
        self.component = stack(
            self.label_current_function_matches.component,
            controls,
            self.b_query_single,
            separator(),
            self.label_function_matches.component,
            self.table_function_matches.component,
            self.label_function_names.component,
            self.table_function_names.component,
            fill=(self.table_function_matches.component, self.table_function_names.component),
        )
        self.clearTable()

    # state

    def _onCbLiveClicked(self):
        if self.cb_activate_live_tracking.isSelected():
            self.parent.main_widget.hideLocalWidget()
            self.updateViewWithCurrentFunction()

    def enable(self):
        for widget in (self.cb_filter_library, self.cb_activate_live_tracking, self.b_query_single):
            widget.setEnabled(True)
        self.label_current_function_matches.setText(
            "Move the cursor to a function, or query the current one."
        )

    def _get_sample_entry(self, sample_id):
        infos = self.parent.sample_infos
        return infos.get(sample_id) if isinstance(infos, dict) else None

    def _get_family_entry(self, family_id):
        infos = self.parent.family_infos
        return infos.get(family_id) if isinstance(infos, dict) else None

    def updateCurrentFunction(self, view):
        function_start = self.cc.backend.get_current_function(view)
        if function_start is not None:
            self.parent.current_function = function_start
        return function_start

    def queryCurrentFunction(self):
        self.parent.main_widget.hideLocalWidget()
        # current_function follows the cursor through the location hook; a double click in the
        # overview sets it before the listing has reported the jump
        if self.parent.current_function is None:
            self.label_current_function_matches.setText("Place the cursor in a function first.")
            return
        self.updateViewWithCurrentFunction()

    def hook_refresh(self, view, use_current_function=False):
        cursor_function = self.updateCurrentFunction(view)
        if self.parent.local_smda_report is None:
            self.label_current_function_matches.setText("Convert to SMDA report first.")
            return
        if cursor_function is None and not use_current_function:
            return
        if self.parent.current_function == self.last_viewed and not use_current_function:
            return
        if not self.cb_activate_live_tracking.isSelected():
            self.clearTable()
            self.label_current_function_matches.setText("Live Function Queries are deactivated.")
            return
        self.updateViewWithCurrentFunction()

    def _headers(self, column_types):
        return [McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col] for col in column_types]

    def clearTable(self):
        config = self.parent.config
        self.table_function_matches.reset(self._headers(config.FUNCTION_MATCHES_TABLE_COLUMNS), [])
        self.table_function_names.reset(self._headers(config.FUNCTION_NAMES_TABLE_COLUMNS), [])

    # queries

    def updateViewWithCurrentFunction(self):
        if self.parent.local_smda_report is None or self.parent.current_function is None:
            return
        self.last_viewed = self.parent.current_function
        smda_function = self.parent.local_smda_report.getFunction(self.parent.current_function)
        # MCRIT's default MINHASH_FN_MIN_INS, compared with >
        if smda_function is None or smda_function.num_instructions <= 10:
            self.clearTable()
            self.label_current_function_matches.setText(
                "Can only query functions with more than 10 instructions."
            )
            return
        function_offset = self.parent.current_function
        score_threshold = self.sb_score_threshold.value()
        outline = None
        if function_offset not in self.parent.function_matches:
            outline = self.parent.getLocalSmdaReportOutline()
            outline.xcfg = {smda_function.offset: smda_function}
            self.label_current_function_matches.setText(
                "Querying matches for function 0x%x..." % function_offset
            )

        def request():
            if self.parent.current_function != function_offset:
                return None
            if not self.parent.mcrit_interface.ensureRemoteInformation():
                return False
            if outline is not None:
                self.parent.mcrit_interface.querySmdaFunctionMatches(outline)
            missing_ids = self._missingMatchedFunctionIds(function_offset, score_threshold)
            if missing_ids:
                self.parent.mcrit_interface.queryFunctionEntriesById(missing_ids)
            return True

        def show(remote_cache_ready):
            if remote_cache_ready is None or self.parent.current_function != function_offset:
                return
            if not remote_cache_ready:
                self.last_viewed = None
                self.clearTable()
                self.label_current_function_matches.setText(
                    "Remote family/sample info unavailable. Check server connection."
                )
                return
            self._showFunctionMatches(smda_function)

        if (
            outline is None
            and self.parent.family_infos is not None
            and self.parent.sample_infos is not None
            and not self._missingMatchedFunctionIds(function_offset, score_threshold)
        ):
            show(True)
        else:
            self.cc.backend.run_request(
                "MCRIT: querying matches for function 0x%x" % function_offset, request, show
            )

    def _missingMatchedFunctionIds(self, function_offset, score_threshold):
        match_report_dict = self.parent.function_matches.get(function_offset)
        if not match_report_dict:
            return []
        match_report = MatchingResult.fromDict(match_report_dict)
        match_report.filterToFunctionScore(score_threshold)
        cached = self.parent.matched_function_entries or {}
        return [
            match.matched_function_id
            for match in match_report.filtered_function_matches
            if match.matched_function_id not in cached
        ]

    def _showFunctionMatches(self, smda_function):
        self.current_function_offset = self.parent.current_function
        offset = self.parent.current_function
        if smda_function.offset not in self.parent.function_matches:
            self.clearTable()
            self.label_current_function_matches.setText(
                "Match query for function 0x%x failed; check the server connection." % offset
            )
            return
        match_report = MatchingResult.fromDict(self.parent.function_matches[smda_function.offset])
        match_report.filterToFunctionScore(self.sb_score_threshold.value())
        num_all = len(match_report.function_matches)
        filtered = match_report.filtered_function_matches
        if self.cb_filter_library.isSelected():
            num_functions = len([m for m in filtered if not m.match_is_library])
            suffix = " (%d filtered)." % (num_all - num_functions)
        elif len(filtered) < num_all:
            num_functions = len(filtered)
            suffix = " (%d filtered)." % (num_all - num_functions)
        else:
            num_functions = num_all
            suffix = "."
        self.label_current_function_matches.setText(
            "Matches for Function: 0x%x -- %d families, %d samples, %d functions%s"
            % (
                offset,
                match_report.num_original_family_matches,
                match_report.num_original_sample_matches,
                num_functions,
                suffix,
            )
        )
        self.populateFunctionMatchTable(match_report)
        self.populateFunctionNameTable(match_report)

    # tables

    def _matchCell(self, column_type, match):
        if column_type == McritTableColumn.FUNCTION_ID:
            return "%d" % match.matched_function_id, match.matched_function_id
        if column_type == McritTableColumn.OFFSET:
            offset = self.parent.function_id_to_offset.get(match.matched_function_id, 0)
            return "0x%x" % offset, offset
        if column_type == McritTableColumn.SAMPLE_ID:
            return "%d" % match.matched_sample_id, match.matched_sample_id
        if column_type == McritTableColumn.SCORE:
            return "%d" % match.matched_score, match.matched_score
        if column_type == McritTableColumn.SHA256:
            sha256 = entry_field(self._get_sample_entry(match.matched_sample_id), "sha256")
            text = sha256[:8] if sha256 else "unknown"
        elif column_type == McritTableColumn.FAMILY_NAME:
            name = entry_field(self._get_family_entry(match.matched_family_id), "family_name")
            text = name if name else "unknown"
        elif column_type == McritTableColumn.VERSION:
            version = entry_field(self._get_sample_entry(match.matched_sample_id), "version")
            text = version if version else "-"
        elif column_type == McritTableColumn.PIC_HASH_MATCH:
            text = "YES" if match.match_is_pichash else "NO"
        elif column_type == McritTableColumn.IS_LIBRARY:
            text = "YES" if match.match_is_library else "NO"
        else:
            text = ""
        return text, text

    def populateFunctionMatchTable(self, match_report):
        column_types = self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS
        entries = sorted(
            match_report.filtered_function_matches,
            key=lambda x: (
                x.matched_score
                + (1 if x.match_is_pichash else 0)
                + (1 if x.match_is_library else 0)
            ),
            reverse=True,
        )
        rows = []
        for match in entries:
            if self.cb_filter_library.isSelected() and match.match_is_library:
                continue
            cells = [self._matchCell(column_type, match) for column_type in column_types]
            rows.append(
                MatchRow(
                    len(rows),
                    match,
                    [text for text, _ in cells],
                    [key for _, key in cells],
                    self.scp.scoreToColor(match.matched_score, opacity=1)[:3],
                )
            )
        self.table_function_matches.reset(
            self._headers(column_types), rows, self.scp.textOnTintColor()
        )
        self.table_function_matches.fit_columns()

    def _nameCell(self, column_type, label):
        if column_type == McritTableColumn.FUNCTION_ID:
            return "%d" % label.function_id, label.function_id
        if column_type == McritTableColumn.SCORE:
            return "%d" % label.score, label.score
        if column_type == McritTableColumn.USER:
            return label.username, label.username
        if column_type == McritTableColumn.FUNCTION_LABEL:
            return label.function_label, label.function_label
        if column_type == McritTableColumn.TIMESTAMP:
            text = label.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            return text, text
        return "", ""

    def populateFunctionNameTable(self, match_report):
        matches_by_id = {
            match.matched_function_id: match for match in match_report.filtered_function_matches
        }
        cached = self.parent.matched_function_entries or {}
        labels = []
        for function_id, match in matches_by_id.items():
            entry = cached.get(function_id)
            if entry is None:
                continue
            if self.cb_filter_library.isSelected() and match.match_is_library:
                continue
            for label in entry.function_labels or []:
                label.score = match.matched_score
                labels.append(label)
        column_types = self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS
        rows = []
        for label in sorted(labels, key=lambda x: (x.score, x.username, x.timestamp), reverse=True):
            cells = [self._nameCell(column_type, label) for column_type in column_types]
            rows.append(MatchRow(len(rows), label, [t for t, _ in cells], [k for _, k in cells]))
        self.table_function_names.reset(self._headers(column_types), rows)
        self.table_function_names.fit_columns()

    # interaction

    def _onFunctionMatchClicked(self, view_row, _column, click_count):
        """Double click: the remote function's graph against the current function."""
        if click_count != 2:
            return
        match = self.table_function_matches.entryAt(view_row)
        smda_function_a = self.parent.local_smda_report.getFunction(self.current_function_offset)
        if match is None or smda_function_a is None:
            self.parent.local_widget.updateActivityInfo(
                "Current function is unavailable; cannot open graph viewer."
            )
            return
        self._showMatchGraph(
            self.parent.local_smda_report, smda_function_a, match.matched_function_id
        )

    def _onFunctionMatchPopup(self, view_row, column):
        """Context click on the SHA256 column copies the full hash of the match's sample."""
        sha256_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SHA256, self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS
        )
        if sha256_column is None or column != sha256_column:
            return
        match = self.table_function_matches.entryAt(view_row)
        sha256 = entry_field(self._get_sample_entry(match.matched_sample_id), "sha256")
        if sha256:
            self.parent.copyStringToClipboard(sha256)

    def _onFunctionNameClicked(self, view_row, column, click_count):
        """Double click on a label's function id opens its graph; on the label, it names the
        current function after it."""
        if click_count != 2:
            return
        column_types = self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS
        id_column = McritTableColumn.columnTypeToIndex(McritTableColumn.FUNCTION_ID, column_types)
        label_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.FUNCTION_LABEL, column_types
        )
        label = self.table_function_names.entryAt(view_row)
        if label is None:
            return
        if id_column is not None and column == id_column:
            smda_function_a = self.parent.local_smda_report.getFunction(
                self.current_function_offset
            )
            if smda_function_a is None:
                self.parent.local_widget.updateActivityInfo(
                    "Current function is unavailable; cannot open graph viewer."
                )
                return
            self._showMatchGraph(self.parent.local_smda_report, smda_function_a, label.function_id)
        elif label_column is not None and column == label_column:
            with self.cc.backend.mutation("Apply MCRIT label"):
                named = self.cc.backend.set_function_name(
                    self.current_function_offset, label.function_label
                )
            self.parent.local_widget.updateActivityInfo(
                ("Named function 0x%x %s." if named else "Ghidra rejected the name for 0x%x: %s.")
                % (self.current_function_offset, label.function_label)
            )

    def _showMatchGraph(self, smda_report_a, smda_function_a, remote_function_id):
        if remote_function_id in self._graph_fetches:
            return
        self._graph_fetches.add(remote_function_id)
        self.parent.local_widget.updateActivityInfo(
            f"Fetching function {remote_function_id} for the graph viewer..."
        )

        def show(remote):
            self._graph_fetches.discard(remote_function_id)
            if remote is None:
                return
            function_entry_b, smda_function_b, sample_entry_b = remote
            matcher = FunctionCfgMatcher(
                smda_report_a, smda_function_a, sample_entry_b, smda_function_b
            )
            colorings = matcher.getColoredMatches()
            self.cc.backend.show_local_match_coloring(
                smda_function_a, block_coloring(colorings["a"])
            )
            self.cc.backend.show_function_graph(
                self,
                sample_entry_b,
                function_entry_b,
                smda_function_b,
                block_coloring(colorings["b"]),
            )
            self.parent.local_widget.updateActivityInfo(
                f"Opened the graph of function {remote_function_id}."
            )

        self.cc.backend.run_request(
            "MCRIT: fetching remote function %d" % remote_function_id,
            lambda: self.parent.mcrit_interface.queryRemoteFunction(remote_function_id),
            show,
        )
