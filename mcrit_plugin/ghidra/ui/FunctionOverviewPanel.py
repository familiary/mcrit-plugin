"""Function Overview tab: every local function with matches in the chosen matching result, the labels
of its matches, and label import with conflict resolution. Ports the Qt FunctionOverviewWidget and
OverviewTable; the aggregation and label fetching are the same.

The label column is a per-row drop-down (McritTableModel choices), tinted by how contested the
function's labels are. "-|-" opts a function out of the import.
"""

import time

import mcrit_plugin.core.McritTableColumn as McritTableColumn
from mcrit_plugin.core.presentation import label_criticality, match_sets, row_cells
from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider, ThemeRole
from mcrit_plugin.ghidra.ui.components import Label, Spinner, button, row, separator, stack

LABEL_FIRST_CHUNK_SIZE = 2000
LABEL_CHUNK_SIZE = 50000
LABEL_RENDER_INTERVAL = 2.0
OPT_OUT = "-|-"
NO_LABEL = "-"
CRITICALITY_ROLES = {
    1: (ThemeRole.BLUE, (70, 120, 220)),
    2: (ThemeRole.CYAN, (70, 180, 70)),
    3: (ThemeRole.GREEN, (100, 255, 100)),
    4: (ThemeRole.YELLOW, (255, 255, 100)),
    5: (ThemeRole.RED, (255, 100, 100)),
}
FILTERS = ("none", "labels", "applicable", "conflicted")


class OverviewRow:
    __slots__ = ("source_row", "offset", "label_entries", "criticality", "entry")

    def __init__(self, source_row, offset, label_entries, criticality):
        self.source_row = source_row
        self.offset = offset
        self.label_entries = label_entries
        self.criticality = criticality
        self.entry = offset

    @property
    def choices(self):
        return ["%d|%s" % (score, label) for score, label in self.label_entries] + [OPT_OUT]


class FunctionOverviewPanel:
    def __init__(self, parent):
        from javax.swing import ButtonGroup, JRadioButton

        from mcrit_plugin.ghidra import swing
        from mcrit_plugin.ghidra.ui.table import MatchTableView

        self.parent = parent
        self.cc = parent.cc
        self.name = "Function Overview"
        self.icon_file = "network.png"
        self.scp = ScoreColorProvider(self.cc.backend)
        self.last_selected_fields = {}
        self.resolved_function_labels = {}
        self._label_requested_ids = set()
        self._label_fetch_stopped = False
        self._label_fetch_generation = 0
        self._label_last_render = 0.0
        self._grouped_report = None
        self._grouped_matches = {}
        self._matches_by_remote_function = {}
        self._label_free_aggregates = {}
        self._aggregates = {}
        self._labeled_source = None
        self._labeled = ({}, 0)
        self._score_range_job_id = None
        self._sorted_once = False
        self.global_minimum_match_value = None
        self.global_maximum_match_value = None
        self.rows = []
        self.label_column = None
        self.dropdowns = False

        self.b_fetch_labels = button(
            "Fetch labels for matches", lambda: self.fetchLabels(force=True)
        )
        self.filter_buttons = {}
        group = ButtonGroup()
        for name in FILTERS:
            radio = JRadioButton(name)
            group.add(radio)
            radio.addActionListener(swing.ActionListener(lambda _e: self.update()))
            self.filter_buttons[name] = radio
        config = parent.config
        if config.OVERVIEW_FILTER_TO_CONFLICTS:
            self.filter_buttons["conflicted"].setSelected(True)
        elif config.OVERVIEW_FILTER_TO_LABELS:
            self.filter_buttons["labels"].setSelected(True)
        else:
            self.filter_buttons["none"].setSelected(True)
        self.b_select_deselect_all = button("(de)select all", self.selectDeselectAllLabels)
        self.b_import_labels = button(
            "Import all labels for unnamed functions", self.importSelectedLabels
        )
        self.sb_minhash_threshold = Spinner(100, 100, 100, on_change=self.update)
        self.label_local_functions = Label("Functions Matched")
        self.table = MatchTableView(centered=True)
        self.table.on_click(self._onClicked)
        self.table.on_popup(self._onPopup)
        filters = row(
            Label("Filter:", wrap=False).component,
            *[self.filter_buttons[name] for name in FILTERS],
        )
        self.component = stack(
            self.b_fetch_labels,
            filters,
            row(self.b_select_deselect_all, self.b_import_labels),
            row(Label("Min. Score:", wrap=False).component, self.sb_minhash_threshold.component),
            separator(),
            self.label_local_functions.component,
            self.table.component,
            fill=(self.table.component,),
        )

    # labels

    def fetchLabels(self, force=False):
        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        best_scores = {}
        for match in match_report.function_matches:
            best_scores[match.matched_function_id] = max(
                best_scores.get(match.matched_function_id, 0), match.matched_score
            )
        if force and not self._label_fetch_stopped:
            self._label_requested_ids = set()
        pending = [fid for fid in best_scores if fid not in self._label_requested_ids]
        if not pending:
            self.update()
            return
        pending.sort(key=lambda fid: best_scores[fid], reverse=True)
        chunks = [pending[:LABEL_FIRST_CHUNK_SIZE]]
        for start in range(LABEL_FIRST_CHUNK_SIZE, len(pending), LABEL_CHUNK_SIZE):
            chunks.append(pending[start : start + LABEL_CHUNK_SIZE])
        self._label_fetch_generation += 1
        self._label_last_render = 0.0
        self.b_fetch_labels.setEnabled(False)
        self._fetchLabelChunk(self._label_fetch_generation, chunks, 0, len(pending), 0)

    def _fetchLabelChunk(self, generation, chunks, index, total, requested):
        activity = self.parent.local_widget
        activity.updateActivityInfo(
            "Fetching labels: %d of %d matched functions..." % (requested, total)
        )

        def done(fetched):
            if generation != self._label_fetch_generation:
                return
            if fetched is None:
                self._label_fetch_stopped = True
                activity.updateActivityInfo(
                    "Fetching labels stopped after %d of %d matched functions; "
                    "fetch again for the rest." % (requested, total)
                )
                last = True
            else:
                self._label_requested_ids.update(chunks[index])
                last = index + 1 == len(chunks)
                if last:
                    self._label_fetch_stopped = False
                    activity.updateActivityInfo("Fetched labels for %d matched functions." % total)
                else:
                    self._fetchLabelChunk(
                        generation, chunks, index + 1, total, requested + len(chunks[index])
                    )
            if last or time.monotonic() - self._label_last_render >= LABEL_RENDER_INTERVAL:
                self._label_last_render = time.monotonic()
                self.update()
            if last:
                self.b_fetch_labels.setEnabled(True)

        self.cc.backend.run_request(
            "MCRIT: fetching labels for %d of %d matched functions" % (len(chunks[index]), total),
            lambda: self.parent.mcrit_interface.queryFunctionEntriesById(
                chunks[index], with_label_only=True
            ),
            done,
        )

    # aggregation (as in FunctionOverviewWidget)

    def getSelectedFilter(self):
        for name, radio in self.filter_buttons.items():
            if radio.isSelected():
                return name
        return "none"

    @staticmethod
    def _sortedLabels(info):
        if "sorted_labels" not in info:
            info["sorted_labels"] = sorted(info["labels"], reverse=True)
        return info["sorted_labels"]

    def _labeledEntries(self):
        entries = self.parent.matched_function_entries
        if self._labeled_source is not entries or self._labeled_source is None:
            labeled = {}
            num_labels = 0
            for function_id, entry in (entries or {}).items():
                if entry.function_labels:
                    labeled[function_id] = entry
                    num_labels += len(entry.function_labels)
            self._labeled_source = entries
            self._labeled = (labeled, num_labels)
        return self._labeled

    def _groupMatches(self, match_report):
        if self._grouped_report is not match_report:
            offsets = {}
            grouped = {}
            for match in match_report.function_matches:
                if match.function_id not in grouped:
                    grouped[match.function_id] = []
                    offsets[match.function_id] = match.offset
                grouped[match.function_id].append(
                    (
                        match.matched_score,
                        match.matched_family_id,
                        match.matched_sample_id,
                        match.matched_function_id,
                        match.match_is_library,
                    )
                )
            self._grouped_matches = {fid: (offsets[fid], m) for fid, m in grouped.items()}
            by_remote = {}
            for function_id, matches in grouped.items():
                for match in matches:
                    by_remote.setdefault(match[3], []).append((function_id, match))
            self._matches_by_remote_function = {k: tuple(v) for k, v in by_remote.items()}
            self._grouped_report = match_report
            self._label_free_aggregates = {}
            self._aggregates = {}
        return self._grouped_matches

    def _labelFreeAggregates(self, grouped, threshold):
        cached = self._label_free_aggregates.get(threshold)
        if cached is None:
            cached = {}
            for function_id, (offset, matches) in grouped.items():
                selected = [match for match in matches if match[0] >= threshold]
                if selected:
                    cached[function_id] = match_sets(offset, selected)
            self._label_free_aggregates = {threshold: cached}
        return cached

    def _aggregateMatches(self, match_report, threshold, filtered, labeled_entries):
        grouped = self._groupMatches(match_report)
        key = (threshold, filtered)
        cached = self._aggregates.get(key)
        if cached is not None and cached[0] is labeled_entries:
            return cached[1:] + (len(grouped),)
        labels_by_function = {}
        labeled_matches = {}
        for matched_function_id, entry in labeled_entries.items():
            for function_id, match in self._matches_by_remote_function.get(matched_function_id, ()):
                if match[0] < threshold:
                    continue
                labeled_matches.setdefault(function_id, []).append(match)
                labels = labels_by_function.setdefault(function_id, set())
                for label in entry.function_labels:
                    labels.add(
                        (int(match[0]), label.function_label, label.username, label.timestamp)
                    )
        if filtered:
            sets_by_function = {
                function_id: match_sets(grouped[function_id][0], selected)
                for function_id, selected in labeled_matches.items()
            }
        else:
            sets_by_function = self._labelFreeAggregates(grouped, threshold)
        aggregated = {}
        num_matches = 0
        for function_id, (sets, num_selected) in sets_by_function.items():
            num_matches += num_selected
            aggregated[function_id] = dict(sets, labels=labels_by_function.get(function_id, set()))
        result = (aggregated, num_matches, set(aggregated))
        if any(cached_threshold != threshold for cached_threshold, _ in self._aggregates):
            self._aggregates = {}
        self._aggregates[key] = (labeled_entries,) + result
        return result + (len(grouped),)

    def ensureSpinBoxRange(self, match_report):
        if self._score_range_job_id != self.parent.matching_job_id:
            self._score_range_job_id = self.parent.matching_job_id
            self.global_minimum_match_value = None
        if self.global_minimum_match_value is None:
            scores = [match.matched_score for match in match_report.function_matches] or [100]
            self.global_minimum_match_value = int(min(scores))
            self.global_maximum_match_value = int(max(scores))
            lower = max(self.parent.config.OVERVIEW_MIN_SCORE, self.global_minimum_match_value)
            upper = max(lower, self.global_maximum_match_value)
            self.sb_minhash_threshold.setRange(lower, upper, lower)

    # table

    def _selectedText(self, model_row):
        """The label chosen in a row's drop-down, read back from the Java model."""
        if self.label_column is None or not self.dropdowns:
            return NO_LABEL
        return self.table.cellText(model_row, self.label_column)

    def update(self, track_selection=True):
        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        self.ensureSpinBoxRange(match_report)
        threshold = self.sb_minhash_threshold.value()
        selected_filter = self.getSelectedFilter()
        labeled_entries, num_labels = self._labeledEntries()
        function_labels = [None] * num_labels
        aggregated, num_matches, shown_functions, num_matched_functions = self._aggregateMatches(
            match_report, threshold, selected_filter != "none", labeled_entries
        )
        critical = {}
        critical_matches = 0
        critical_labels = []
        for function_id, info in sorted(aggregated.items()):
            info["criticality"] = label_criticality(
                self._sortedLabels(info),
                has_function_name=not self.cc.backend.has_default_function_name(info["offset"]),
                is_resolved=info["offset"] in self.resolved_function_labels,
            )
            if info["criticality"] > 0:
                if selected_filter == "applicable" and info["criticality"] < 2:
                    continue
                if selected_filter == "conflicted" and info["criticality"] < 4:
                    continue
                critical[function_id] = info
                critical_matches += len(info["functions"])
                critical_labels.extend(label[1] for label in info["labels"])
        if selected_filter in ("applicable", "conflicted"):
            aggregated = critical
            shown_functions = set(critical)
            num_matches = critical_matches
            function_labels = critical_labels
        self.label_local_functions.setText(
            f"Showing {len(shown_functions)} functions with {num_matches} matches and "
            f"{len(function_labels)} labels ({num_matched_functions - len(shown_functions)} "
            f"functions and {len(match_report.function_matches) - num_matches} matches filtered)"
        )
        column_types = self.parent.config.OVERVIEW_TABLE_COLUMNS
        label_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SCORE_AND_LABEL, column_types
        )
        if track_selection:
            kept = {}
            for model_row, table_row in enumerate(self.rows):
                # a row without labels shows the opt-out only because it has nothing else; that
                # is no choice of the user's and must not opt the function out once labels arrive
                # (the Qt FunctionOverviewWidget records it and keeps such rows opted out)
                if not table_row.label_entries:
                    continue
                selected = self._selectedText(model_row)
                if table_row.offset in self.last_selected_fields and selected != OPT_OUT:
                    score = selected.split("|")[0] if "|" in selected else NO_LABEL
                    if not score.isdigit() or int(score) < threshold:
                        continue
                kept[table_row.offset] = selected
            self.last_selected_fields = kept
        dropdowns = bool(function_labels) and label_column is not None
        from mcrit_plugin.ghidra.ui.table import MatchRow

        rows, match_rows, choices, tints = [], [], [], []
        for index, (_function_id, info) in enumerate(sorted(aggregated.items())):
            label_entries = [(label[0], label[1]) for label in self._sortedLabels(info)]
            overview_row = OverviewRow(index, info["offset"], label_entries, info["criticality"])
            selected = self.resolved_function_labels.get(
                info["offset"], self.last_selected_fields.get(info["offset"])
            )
            if selected != OPT_OUT and selected not in overview_row.choices[:-1]:
                selected = overview_row.choices[0] if label_entries else OPT_OUT
            if not dropdowns:
                selected = NO_LABEL
            texts, keys = row_cells(info, column_types)
            if label_column is not None:
                texts[label_column] = selected
                keys[label_column] = int(selected.split("|")[0]) if selected[:1].isdigit() else -1
            rows.append(overview_row)
            match_rows.append(MatchRow(index, info["offset"], texts, keys))
            choices.append(overview_row.choices if dropdowns else None)
            tints.append(self._criticalityColor(info["criticality"]) if dropdowns else None)
        headers = [McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col] for col in column_types]
        self.rows = rows
        self.label_column = label_column
        self.dropdowns = dropdowns
        self.table.reset(headers, match_rows, self.scp.textOnTintColor())
        if dropdowns:
            self.table.set_choices(label_column, choices, tints)
        if not self._sorted_once and rows:
            # like the Qt table: ordered by offset until a header is clicked
            self.table.sort_by(0, True)
            self._sorted_once = True
        self.table.fit_columns(max_width=600)

    def _criticalityColor(self, criticality):
        if not criticality:
            return None
        role, default = CRITICALITY_ROLES[min(criticality, 5)]
        return self.scp.roleColor(role, default)

    # buttons

    def selectDeselectAllLabels(self):
        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        offsets = {match.offset for match in match_report.function_matches}
        any_selected = any(self.last_selected_fields.get(o, NO_LABEL) != OPT_OUT for o in offsets)
        if any_selected:
            for offset in offsets:
                self.last_selected_fields[offset] = OPT_OUT
            self.resolved_function_labels = {}
            self.parent.local_widget.updateActivityInfo(
                f"Deselected labels for {len(offsets)} functions."
            )
        else:
            self.last_selected_fields = {}
            self.parent.local_widget.updateActivityInfo(
                f"Reset label selection for {len(offsets)} functions."
            )
        self.update(track_selection=False)

    def importSelectedLabels(self):
        if self.label_column is None:
            self.parent.local_widget.updateActivityInfo(
                "No label column configured; cannot import labels."
            )
            return
        if not self.rows:
            self.parent.local_widget.updateActivityInfo("No labels loaded. Fetch labels first.")
            return
        applied = skipped = 0
        backend = self.cc.backend
        with backend.mutation("Import MCRIT labels"):
            for model_row, table_row in enumerate(self.rows):
                selected = self._selectedText(model_row)
                if selected == NO_LABEL:
                    continue
                if selected == OPT_OUT:
                    skipped += 1
                    continue
                fields = selected.split("|", 1)
                if len(fields) < 2:
                    continue
                if backend.has_default_function_name(table_row.offset):
                    if backend.set_function_name(table_row.offset, fields[1]):
                        applied += 1
                    else:
                        skipped += 1
        if applied:
            self.parent.local_widget.updateActivityInfo(
                f"Success! Imported {applied} function names (skipped: {skipped})."
            )
        else:
            self.parent.local_widget.updateActivityInfo(
                "No suitable function names found to import."
            )
        self.update()

    # clicks

    def _onPopup(self, view_row, column):
        """Context click on a label marks it resolved, or unmarks it."""
        if column != self.label_column:
            return
        model_row = self.table.modelRow(view_row)
        if model_row is None:
            return
        offset = self.rows[model_row].offset
        if offset in self.resolved_function_labels:
            self.resolved_function_labels.pop(offset)
        else:
            self.resolved_function_labels[offset] = self._selectedText(model_row)
        self.update()

    def _onClicked(self, view_row, column, click_count):
        if click_count != 2:
            return
        model_row = self.table.modelRow(view_row)
        if model_row is None:
            return
        offset = self.rows[model_row].offset
        offset_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.OFFSET, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        if column == offset_column:
            self.cc.backend.jump_to(offset)
        elif column != self.label_column:
            self.cc.backend.jump_to(offset)
            self.parent.current_function = offset
            self.parent.main_widget.setTabFocus(self.parent.function_match_widget.name)
            self.parent.function_match_widget.queryCurrentFunction()
