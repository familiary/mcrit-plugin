import time

import mcrit_plugin.core.McritTableColumn as McritTableColumn
import mcrit_plugin.ui_qt.QtShim as QtShim
from mcrit_plugin.ui_qt.widgets.OverviewTable import OverviewTableView, build_row

# ids in the first label request and in each later one, and the least time between two table
# renders while chunks arrive; each request adds a fixed server cost, so only the first is small
LABEL_FIRST_CHUNK_SIZE = 2000
LABEL_CHUNK_SIZE = 50000
LABEL_RENDER_INTERVAL = 2.0

QMainWindow = QtShim.get_QMainWindow()


class FunctionOverviewWidget(QMainWindow):
    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading FunctionOverviewWidget")
        self.last_selected_fields = {}  # offset -> selected label string
        self._label_requested_ids = set()
        self._label_fetch_generation = 0
        self._grouped_report = None
        self._labeled_source = None
        self._labeled = ({}, 0)
        self._grouped_matches = {}
        self._matches_by_remote_function = {}
        self._label_free_aggregates = {}
        self._aggregates = {}
        self._label_last_render = 0.0
        self._score_range_job_id = None
        self.resolved_function_labels = {}  # offset -> resolved label string
        self.parent = parent
        self.name = "Function Overview"
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "relationship.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.b_fetch_labels = self.cc.QPushButton("Fetch labels for matches")
        self.b_fetch_labels.clicked.connect(lambda: self.fetchLabels(force=True))

        # Create horizontal layout for filter options
        self.filter_container = self.cc.QWidget()
        self.filter_layout = self.cc.QHBoxLayout()
        self.filter_container.setLayout(self.filter_layout)

        # Filter label
        self.filter_label = self.cc.QLabel("Filter:")
        self.filter_layout.addWidget(self.filter_label)

        # Create radio buttons for filter options
        self.rb_filter_none = self.cc.QRadioButton("none")
        self.rb_filter_labels = self.cc.QRadioButton("labels")
        self.rb_filter_applicable = self.cc.QRadioButton("applicable")
        self.rb_filter_conflicted = self.cc.QRadioButton("conflicted")

        # Add radio buttons to layout
        self.filter_layout.addWidget(self.rb_filter_none)
        self.filter_layout.addWidget(self.rb_filter_labels)
        self.filter_layout.addWidget(self.rb_filter_applicable)
        self.filter_layout.addWidget(self.rb_filter_conflicted)
        self.filter_layout.addStretch()  # Add stretch to push everything to the left

        # Set default selection based on config
        if self.parent.config.OVERVIEW_FILTER_TO_CONFLICTS:
            self.rb_filter_conflicted.setChecked(True)
        elif self.parent.config.OVERVIEW_FILTER_TO_LABELS:
            self.rb_filter_labels.setChecked(True)
        else:
            self.rb_filter_none.setChecked(True)

        # Connect radio buttons to populate function
        self.rb_filter_none.toggled.connect(self._onFilterToggled)
        self.rb_filter_labels.toggled.connect(self._onFilterToggled)
        self.rb_filter_applicable.toggled.connect(self._onFilterToggled)
        self.rb_filter_conflicted.toggled.connect(self._onFilterToggled)

        # Create horizontal layout for button container
        self.button_container = self.cc.QWidget()
        self.button_layout = self.cc.QHBoxLayout()
        self.button_container.setLayout(self.button_layout)

        # Create buttons
        self.b_select_deselect_all = self.cc.QPushButton("(de)select all")
        self.b_select_deselect_all.clicked.connect(self.selectDeselectAllLabels)
        self.b_import_labels = self.cc.QPushButton("Import all labels for unnamed functions")
        # TODO implement an actual selective import function here
        self.b_import_labels.clicked.connect(self.importSelectedLabels)

        # Add buttons to horizontal layout
        self.button_layout.addWidget(self.b_select_deselect_all)
        self.button_layout.addWidget(self.b_import_labels)
        self.button_layout.addStretch()  # Add stretch to push buttons to the left
        self.sb_minhash_threshold = self.cc.QSpinBox()
        self.sb_minhash_threshold.setRange(100, 100)
        self.sb_minhash_threshold.valueChanged.connect(self.handleSpinThresholdChange)
        self.global_minimum_match_value = None
        self.global_maximum_match_value = None
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.cc.QFrameHLine)
        self.hline.setFrameShadow(self.cc.QFrameShadow.Sunken)
        # table
        self.label_local_functions = self.cc.QLabel("Functions Matched")
        self.table_local_functions = OverviewTableView(self.cc.backend)
        self.table_local_functions.doubleClicked.connect(self._onTableFunctionsDoubleClicked)
        self.table_local_functions.customContextMenuRequested.connect(
            self._onTableFunctionsRightClicked
        )
        # cache for function_names
        self.current_rows = []
        # static link to the shim to help IDA
        self._QtShim = QtShim
        self._createGui()

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # layout and fill the widget
        function_info_layout = self.cc.QVBoxLayout()
        function_info_layout.addWidget(self.b_fetch_labels)
        function_info_layout.addWidget(self.filter_container)
        function_info_layout.addWidget(self.button_container)
        function_info_layout.addWidget(self.sb_minhash_threshold)
        function_info_layout.addWidget(self.hline)
        function_info_layout.addWidget(self.label_local_functions)
        function_info_layout.addWidget(self.table_local_functions)
        self.central_widget.setLayout(function_info_layout)

    ################################################################################
    # Rendering and state keeping
    ################################################################################

    def fetchLabels(self, force=False):
        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        best_scores = {}
        for function_match in match_report.function_matches:
            function_id = function_match.matched_function_id
            best_scores[function_id] = max(
                best_scores.get(function_id, 0), function_match.matched_score
            )
        print("Number of matched remote functions: ", len(best_scores))
        if force:
            self._label_requested_ids = set()
        # with_label_only answers nothing for unlabeled functions, so the cache alone cannot tell
        # a pending id from one already known to be unlabeled
        pending_ids = [fid for fid in best_scores if fid not in self._label_requested_ids]
        if not pending_ids:
            self._showFetchedLabels()
            return
        # the server needs about a minute for a large result: ask for the best matches first and
        # show each chunk's labels as it arrives instead of after the last one
        pending_ids.sort(key=lambda fid: best_scores[fid], reverse=True)
        chunks = [pending_ids[:LABEL_FIRST_CHUNK_SIZE]]
        for start in range(LABEL_FIRST_CHUNK_SIZE, len(pending_ids), LABEL_CHUNK_SIZE):
            chunks.append(pending_ids[start : start + LABEL_CHUNK_SIZE])
        self._label_fetch_generation += 1
        self.b_fetch_labels.setEnabled(False)
        self._fetchLabelChunk(self._label_fetch_generation, chunks, 0, len(pending_ids), 0)

    def _fetchLabelChunk(self, generation, chunks, index, total, requested):
        self.parent.local_widget.updateActivityInfo(
            "Fetching labels: %d of %d matched functions..." % (requested, total)
        )

        def done(fetched):
            if generation != self._label_fetch_generation:
                return
            last = index + 1 == len(chunks)
            if fetched is None:
                last = True
            else:
                self._label_requested_ids.update(chunks[index])
            if last or time.monotonic() - self._label_last_render >= LABEL_RENDER_INTERVAL:
                self._label_last_render = time.monotonic()
                self._showFetchedLabels()
            if last:
                self.b_fetch_labels.setEnabled(True)
            else:
                self._fetchLabelChunk(
                    generation, chunks, index + 1, total, requested + len(chunks[index])
                )

        self.cc.backend.run_request(
            "MCRIT: fetching labels for %d of %d matched functions" % (len(chunks[index]), total),
            lambda: self.parent.mcrit_interface.queryFunctionEntriesById(
                chunks[index], with_label_only=True
            ),
            done,
        )

    def _showFetchedLabels(self):
        function_entries_with_labels = {}
        if self.parent.matched_function_entries:
            for function_id, function_entry in self.parent.matched_function_entries.items():
                if function_entry.function_labels:
                    function_entries_with_labels[function_id] = function_entry
        function_labels = []
        for function_id, entry in function_entries_with_labels.items():
            for label in entry.function_labels:
                function_labels.append(label)
        print("Fetched function entries, found labels for:", len(function_labels))
        self.update()

    def update(self):
        self.populateFunctionTable()

    def _onFilterToggled(self, checked):
        # the button losing its check emits toggled as well
        if checked:
            self.update()

    def handleSpinThresholdChange(self):
        self.update()

    def getSelectedFilter(self):
        """Get the currently selected filter option"""
        if self.rb_filter_none.isChecked():
            return "none"
        elif self.rb_filter_labels.isChecked():
            return "labels"
        elif self.rb_filter_applicable.isChecked():
            return "applicable"
        elif self.rb_filter_conflicted.isChecked():
            return "conflicted"
        return "none"  # fallback

    def _populatedRow(self, row):
        """The row a table row had when the table was filled. Sorting moves rows, but the label
        mappings and current_rows stay keyed by that row."""
        return self.table_local_functions.sourceRow(row)

    def getSelectedLabel(self, row, column):
        """The label entry selected in a table row of the label column"""
        index = self.table_local_functions.model().index(row, column)
        return index.data(self.cc.QtCore.Qt.DisplayRole) if index.isValid() else None

    def selectDeselectAllLabels(self):
        """Toggle between selecting all labels or deselecting all labels"""
        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return

        # Get all offsets from the current matching report
        current_offsets = set()
        for function_match in match_report.function_matches:
            current_offsets.add(function_match.offset)

        # Check current state: count how many are NOT set to the empty demarker "-|-"
        non_empty_count = 0
        total_count = len(current_offsets)

        for offset in current_offsets:
            selected_value = self.last_selected_fields.get(offset, "-")
            if selected_value != "-|-":
                non_empty_count += 1

        print(f"Current state: {non_empty_count}/{total_count} functions have labels selected")

        # Decision logic based on current state
        if non_empty_count > 0:
            # DESELECTION: At least one row is not set to empty demarker
            print("Performing deselection - setting all to empty demarker")
            for offset in current_offsets:
                self.last_selected_fields[offset] = "-|-"
            self.resolved_function_labels = {}  # Clear resolved labels as well
            self.parent.local_widget.updateActivityInfo(
                f"Deselected labels for {total_count} functions."
            )
        else:
            # SELECTION: All rows are currently set to empty demarker or unset
            print("Performing selection - resetting selection memory")
            self.last_selected_fields = {}  # Reset to forget chosen values
            self.parent.local_widget.updateActivityInfo(
                f"Reset label selection for {total_count} functions."
            )

        # Refresh the table to show the changes
        self.populateFunctionTable(track_selection=False)

    def importSelectedLabels(self):
        # get currently selected names from all dropdowns in the table
        label_score_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SCORE_AND_LABEL, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        if label_score_column_index is None:
            self.parent.local_widget.updateActivityInfo(
                "No label column configured; cannot import labels."
            )
            return
        if not self.table_local_functions.table_model.rows:
            self.parent.local_widget.updateActivityInfo("No labels loaded. Fetch labels first.")
            return
        num_names_applied = 0
        num_names_skipped = 0
        with self.cc.backend.mutation("Import MCRIT labels"):
            for table_row in self.table_local_functions.table_model.rows:
                offset = table_row.offset
                label_via_table = table_row.selected_text
                # we did not get a usable label, we continue to the next row
                if label_via_table == "-":
                    continue
                # we found a manually disabled label, we continue to the next row
                if label_via_table == "-|-":
                    num_names_skipped += 1
                    continue
                # extract the actual name from the score|name pair
                label_fields = label_via_table.split("|")
                if len(label_fields) < 2:
                    self.parent.local_widget.updateActivityInfo(
                        f"Error: Could not parse label '{label_via_table}' for function at 0x{offset:x}."
                    )
                    continue
                label_via_table = label_via_table.split("|")[1]
                if self.cc.backend.has_default_function_name(offset):
                    self.cc.backend.set_function_name(offset, label_via_table)
                    num_names_applied += 1
        if num_names_applied:
            self.parent.local_widget.updateActivityInfo(
                f"Success! Imported {num_names_applied} function names (skipped: {num_names_skipped})."
            )
        else:
            self.parent.local_widget.updateActivityInfo(
                "No suitable function names found to import."
            )

    def ensureSpinBoxRange(self, match_report):
        # a newly fetched result brings its own score range
        if self._score_range_job_id != self.parent.matching_job_id:
            self._score_range_job_id = self.parent.matching_job_id
            self.global_minimum_match_value = None
        if self.global_minimum_match_value is None:
            self.global_minimum_match_value = 100
            self.global_maximum_match_value = 0
            for function_match in match_report.function_matches:
                self.global_minimum_match_value = int(
                    min(self.global_minimum_match_value, function_match.matched_score)
                )
                self.global_maximum_match_value = int(
                    max(self.global_maximum_match_value, function_match.matched_score)
                )
            config_adjusted_lower_value = max(
                self.parent.config.OVERVIEW_MIN_SCORE, self.global_minimum_match_value
            )
            # the caller populates the table with the new value; signals would populate it again
            self.sb_minhash_threshold.blockSignals(True)
            self.sb_minhash_threshold.setRange(
                config_adjusted_lower_value, self.global_maximum_match_value
            )
            self.sb_minhash_threshold.setValue(config_adjusted_lower_value)
            self.sb_minhash_threshold.blockSignals(False)

    def _calculateLabelCriticality(self, label_list, has_function_name=False, is_resolved=False):
        criticality = 0
        if len(label_list) == 0:
            return criticality
        if has_function_name:
            criticality = 1
            return criticality
        if is_resolved:
            criticality = 2
            return criticality
        criticality = 3
        label_set = set([label_entry[1] for label_entry in label_list])
        top_score = max([label_entry[0] for label_entry in label_list])
        top_score_label_pool = [
            label_entry for label_entry in label_list if label_entry[0] == top_score
        ]
        if len(label_set) > 1:
            criticality += 1
            if len(set([label_entry[1] for label_entry in top_score_label_pool])) > 1:
                criticality += 1
        return criticality

    @staticmethod
    def _sortedLabels(function_info):
        """The labels of an aggregate, best first, sorted once for as long as the aggregate lives."""
        if "sorted_labels" not in function_info:
            function_info["sorted_labels"] = sorted(function_info["labels"], reverse=True)
        return function_info["sorted_labels"]

    def _labeledEntries(self):
        """The matched function entries that carry labels and the number of those labels. The
        cache of entries is replaced, never changed in place, so one pass serves until it is."""
        entries = self.parent.matched_function_entries
        if self._labeled_source is not entries or self._labeled_source is None:
            labeled = {}
            num_labels = 0
            for function_id, function_entry in (entries or {}).items():
                if function_entry.function_labels:
                    labeled[function_id] = function_entry
                    num_labels += len(function_entry.function_labels)
            self._labeled_source = entries
            self._labeled = (labeled, num_labels)
        return self._labeled

    def _groupMatches(self, match_report):
        """The matches of a result by local function, as tuples of what the aggregation reads.
        Grouping takes a pass over all matches, so a result is grouped once."""
        if self._grouped_report is not match_report:
            offsets = {}
            grouped = {}
            for function_match in match_report.function_matches:
                function_id = function_match.function_id
                if function_id not in grouped:
                    grouped[function_id] = []
                    offsets[function_id] = function_match.offset
                grouped[function_id].append(
                    (
                        function_match.matched_score,
                        function_match.matched_family_id,
                        function_match.matched_sample_id,
                        function_match.matched_function_id,
                        function_match.match_is_library,
                    )
                )
            self._grouped_matches = {
                function_id: (offsets[function_id], matches)
                for function_id, matches in grouped.items()
            }
            # labels belong to remote functions: this finds the matches a label applies to
            # without a pass over all of them
            by_remote_function = {}
            for function_id, matches in grouped.items():
                for match in matches:
                    by_remote_function.setdefault(match[3], []).append((function_id, match))
            # tuples of plain values drop out of the garbage collector's tracking, lists never do;
            # a full collection walks every tracked object, so 150,000 lists made each pause longer
            self._matches_by_remote_function = {
                remote_function_id: tuple(matches)
                for remote_function_id, matches in by_remote_function.items()
            }
            self._grouped_report = match_report
            self._label_free_aggregates = {}
            self._aggregates = {}
        return self._grouped_matches

    def _labelFreeAggregates(self, grouped, threshold_value):
        """Per local function the families, samples, functions and library matches of its matches
        at or above the threshold, and their number; labels do not change these."""
        cached = self._label_free_aggregates.get(threshold_value)
        if cached is None:
            cached = {}
            for function_id, (offset, matches) in grouped.items():
                selected = [match for match in matches if match[0] >= threshold_value]
                if selected:
                    cached[function_id] = _matchSets(offset, selected)
            self._label_free_aggregates[threshold_value] = cached
        return cached

    def _aggregateMatches(self, match_report, threshold_value, filtered, labeled_entries):
        """Per local function the families, samples, functions, library matches and labels of its
        matches at or above the threshold, and with a label if filtered.

        Returns the aggregates by function id, the number of matches and the functions they come
        from, and the number of functions with any match. Results are kept per threshold and
        filter until the result or the labels change, since clicking through the filters asks for
        the same ones again.
        """
        grouped = self._groupMatches(match_report)
        key = (threshold_value, filtered)
        cached = self._aggregates.get(key)
        if cached is not None and cached[0] is labeled_entries:
            return cached[1:] + (len(grouped),)
        # only the matches of labeled remote functions carry labels or pass the label filter
        labels_by_function = {}
        labeled_matches = {}
        for matched_function_id, entry in labeled_entries.items():
            for function_id, match in self._matches_by_remote_function.get(matched_function_id, ()):
                if match[0] < threshold_value:
                    continue
                labeled_matches.setdefault(function_id, []).append(match)
                labels = labels_by_function.setdefault(function_id, set())
                for label in entry.function_labels:
                    labels.add(
                        (int(match[0]), label.function_label, label.username, label.timestamp)
                    )
        if filtered:
            match_sets = {
                function_id: _matchSets(grouped[function_id][0], selected)
                for function_id, selected in labeled_matches.items()
            }
        else:
            match_sets = self._labelFreeAggregates(grouped, threshold_value)
        aggregated_matches = {}
        matches_beyond_filters = 0
        for function_id, (sets, num_selected) in match_sets.items():
            matches_beyond_filters += num_selected
            # a new dict per aggregation: populating the table adds keys to it
            aggregated_matches[function_id] = dict(
                sets, labels=labels_by_function.get(function_id, set())
            )
        result = (
            aggregated_matches,
            matches_beyond_filters,
            set(aggregated_matches),
        )
        self._aggregates[key] = (labeled_entries,) + result
        return result + (len(grouped),)

    def populateFunctionTable(self, track_selection=True):
        """
        Populate the function table with information about matches of local functions.
        """
        header_view = self._QtShim.get_QHeaderView()

        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        self.ensureSpinBoxRange(match_report)
        threshold_value = self.sb_minhash_threshold.value()

        function_entries_with_labels, num_labels = self._labeledEntries()
        function_labels = [None] * num_labels  # only counted

        # aggregate the matches of each local function
        (
            aggregated_matches,
            matches_beyond_filters,
            functions_beyond_filters,
            num_matched_functions,
        ) = self._aggregateMatches(
            match_report,
            threshold_value,
            self.getSelectedFilter() != "none",
            function_entries_with_labels,
        )

        # count filtered functions again
        filtered_list = {}
        crit_functions_beyond_filters = set()
        crit_matches_beyond_filters = 0
        crit_function_labels = []
        for function_id, function_info in sorted(aggregated_matches.items()):
            is_custom_name = not self.cc.backend.has_default_function_name(function_info["offset"])
            criticality = self._calculateLabelCriticality(
                self._sortedLabels(function_info),
                has_function_name=is_custom_name,
                is_resolved=function_info["offset"] in self.resolved_function_labels,
            )
            function_info["criticality"] = criticality
            if criticality > 0:
                if self.getSelectedFilter() == "applicable" and criticality < 2:
                    continue
                if self.getSelectedFilter() == "conflicted" and criticality < 4:
                    continue
                filtered_list[function_id] = function_info
                crit_functions_beyond_filters.add(function_id)
                crit_matches_beyond_filters += len(function_info["functions"])
                for label_entry in function_info["labels"]:
                    crit_function_labels.append(label_entry[1])
        if self.getSelectedFilter() in ["applicable", "conflicted"]:
            aggregated_matches = filtered_list
            functions_beyond_filters = crit_functions_beyond_filters
            matches_beyond_filters = crit_matches_beyond_filters
            function_labels = crit_function_labels

        # Update summary
        update_text = f"Showing {len(functions_beyond_filters)} functions with {matches_beyond_filters} matches and {len(function_labels)} labels ({num_matched_functions - len(functions_beyond_filters)} functions and {len(match_report.function_matches) - matches_beyond_filters} matches filtered)"
        self.label_local_functions.setText(update_text)

        label_score_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SCORE_AND_LABEL, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        self.local_function_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.OVERVIEW_TABLE_COLUMNS
        ]
        table_model = self.table_local_functions.table_model

        if track_selection:
            # keep what the user picked in the table that is being replaced
            new_selected_fields = {}
            for table_row in table_model.rows:
                selected_item = table_row.selected_text
                if table_row.offset in self.last_selected_fields and selected_item != "-|-":
                    score = selected_item.split("|")[0] if "|" in selected_item else "-"
                    if score == "-" or int(score) < threshold_value:
                        # below the threshold now, the highest label is selected instead
                        continue
                new_selected_fields[table_row.offset] = selected_item
            self.last_selected_fields = new_selected_fields

        self.current_rows = aggregated_matches
        # the drop-downs only exist when the server has labels for the matches
        dropdowns = bool(function_labels) and label_score_column_index is not None
        rows = []
        for row, (function_id, function_info) in enumerate(sorted(aggregated_matches.items())):
            label_entries = [
                (label_entry[0], label_entry[1])
                for label_entry in self._sortedLabels(function_info)
            ]
            # the label stored for this offset or resolved by the user stays selected as long as
            # the function still has it, else the best label does
            selected_text = self.resolved_function_labels.get(
                function_info["offset"], self.last_selected_fields.get(function_info["offset"])
            )
            if selected_text != "-|-" and not any(
                selected_text == "%d|%s" % entry for entry in label_entries
            ):
                selected_text = "%d|%s" % label_entries[0] if label_entries else "-|-"
            if not dropdowns:
                # a plain cell shows "-", which the label import passes over
                selected_text = "-"
            rows.append(
                build_row(
                    row,
                    function_info,
                    self.parent.config.OVERVIEW_TABLE_COLUMNS,
                    label_entries,
                    selected_text,
                )
            )

        table = self.table_local_functions
        table_model.reset(
            self.local_function_header_labels,
            self.parent.config.OVERVIEW_TABLE_COLUMNS,
            label_score_column_index,
            rows,
            dropdowns,
        )
        table.setLabelColumn(label_score_column_index)
        if rows:
            # a drop-down needs more room than the font alone asks for
            row_height = max(table.verticalHeader().defaultSectionSize(), 26)
            table.verticalHeader().setDefaultSectionSize(row_height)
        header = table.horizontalHeader()
        for header_id in range(len(self.local_function_header_labels)):
            # only the score/label column stretches; the rest stay as narrow as their content
            if header_id == label_score_column_index:
                header.setSectionResizeMode(header_id, header_view.Stretch)
            else:
                header.setSectionResizeMode(header_id, header_view.ResizeToContents)

        # Don't stretch the last section since we're handling it explicitly
        header.setStretchLastSection(False)

    ################################################################################
    # Buttons and Actions
    ################################################################################

    def _onTableFunctionsRightClicked(self, position):
        cell = self.table_local_functions.cellAtPosition(position)
        if cell is not None:
            self._handleRightClickOnRow(*cell)

    def _handleRightClickOnRow(self, row, column):
        """Handle right-click action for a specific row (as filled into the table) and column"""
        function_label_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SCORE_AND_LABEL, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        table_row = next(
            (r for r in self.table_local_functions.table_model.rows if r.source_row == row), None
        )
        if column == function_label_column and table_row is not None:
            function_offset = table_row.offset
            if function_offset in self.resolved_function_labels:
                self.resolved_function_labels.pop(function_offset)
            else:
                self.resolved_function_labels[function_offset] = table_row.selected_text
            self.update()

    def _onTableFunctionsDoubleClicked(self, mi):
        function_offset_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.OFFSET, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        function_label_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SCORE_AND_LABEL, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        table_rows = self.table_local_functions.table_model.rows
        if not 0 <= mi.row() < len(table_rows):
            return
        clicked_function_address = table_rows[mi.row()].offset
        if mi.column() not in [function_offset_column, function_label_column]:
            self.cc.backend.jump_to(clicked_function_address)
            # Binary Ninja reports the cursor move only after a delay, too late for this query
            self.parent.current_function = clicked_function_address
            # change to function scope tab
            self.parent.main_widget.setTabFocus(self.parent.function_match_widget.name)
            self.parent.function_match_widget.queryCurrentFunction()
        elif mi.column() == function_offset_column:
            self.cc.backend.jump_to(clicked_function_address)


def _matchSets(offset, selected):
    """The sets the overview shows for one local function's selected matches, and their number."""
    sets = {
        "offset": offset,
        "families": {match[1] for match in selected},
        "samples": {match[2] for match in selected},
        "functions": {match[3] for match in selected},
        "library_matches": {match[3] for match in selected if match[4]},
    }
    return sets, len(selected)
