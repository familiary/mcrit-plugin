import mcrit_plugin.core.McritTableColumn as McritTableColumn
import mcrit_plugin.ui_qt.QtShim as QtShim
from mcrit_plugin.core.minimcrit.matchers.FunctionCfgMatcher import FunctionCfgMatcher
from mcrit_plugin.core.minimcrit.storage.MatchedFunctionEntry import MatchedFunctionEntry
from mcrit_plugin.core.minimcrit.storage.MatchingResult import MatchingResult
from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider
from mcrit_plugin.ui_qt.widgets.NumberQTableWidgetItem import NumberQTableWidgetItem

QMainWindow = QtShim.get_QMainWindow()
QColor = QtShim.get_QColor()


class FunctionMatchWidget(QMainWindow):
    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading FunctionMatchWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.scp = ScoreColorProvider(self.cc.backend)
        self.last_viewed = None
        self.name = "Function Scope"
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "flag-triangle.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.current_function_offset = None
        self.label_current_function_matches = self.cc.QLabel("Matches for: <function_offset>")
        self.cb_filter_library = self.cc.QCheckBox("Filter out Library Matches")
        self.cb_filter_library.setEnabled(False)
        self.cb_filter_library.setChecked(self.parent.config.FUNCTION_FILTER_LIBRARY_FUNCTIONS)
        self.cb_filter_library.clicked.connect(self._onCbFilterLibraryClicked)
        self.cb_activate_live_tracking = self.cc.QCheckBox("Live Function Queries")
        self.cb_activate_live_tracking.setEnabled(False)
        self.cb_activate_live_tracking.setChecked(self.parent.config.FUNCTION_LIVE_QUERY)
        self.cb_activate_live_tracking.clicked.connect(self._onCbLiveClicked)
        # filter wheel
        self.sb_score_threshold = self.cc.QSpinBox()
        self.sb_score_threshold.setRange(50, 100)
        self.sb_score_threshold.setValue(self.parent.config.FUNCTION_MIN_SCORE)
        self.sb_score_threshold.valueChanged.connect(self.handleSpinThresholdChange)
        self.label_sb_threshold = self.cc.QLabel("Min. Score: ")
        self.b_query_single = self.cc.QPushButton("Query current function")
        self.b_query_single.clicked.connect(self.queryCurrentFunction)
        self.b_query_single.setEnabled(False)
        ### self.cb_filter_library.stateChanged.connect(self.populateBestMatchTable)
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.cc.QFrameHLine)
        self.hline.setFrameShadow(self.cc.QFrameShadow.Sunken)
        # upper table
        self.label_function_matches = self.cc.QLabel("Function Matches")
        self.table_function_matches = self.cc.QTableWidget()
        self.table_function_matches.doubleClicked.connect(self._onTableFunctionMatchDoubleClicked)
        self.table_function_matches.setContextMenuPolicy(self.cc.QtCore.Qt.CustomContextMenu)
        self.table_function_matches.customContextMenuRequested.connect(
            self._onTableFunctionMatchRightClicked
        )

        # lower table
        self.label_function_names = self.cc.QLabel("Names from Matched Functions")
        self.table_function_names = self.cc.QTableWidget()
        self.table_function_names.doubleClicked.connect(self._onTableFunctionNameDoubleClicked)
        ### self.table_picblockhash_matches.doubleClicked.connect(self._onTablePicBlockHashDoubleClicked)
        # static links to objects to help IDA
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
        self._QtShim = QtShim
        self._createGui()

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # layout and fill the widget
        sample_info_layout = self.cc.QVBoxLayout()
        self.controls_widget = self.cc.QWidget()
        controls_layout = self.cc.QGridLayout()
        controls_layout.setContentsMargins(0, 0, 0, 0)
        controls_layout.addWidget(self.cb_filter_library, 0, 0)
        controls_layout.addWidget(self.cb_activate_live_tracking, 1, 0)
        controls_layout.addWidget(self.label_sb_threshold, 0, 1)
        controls_layout.addWidget(self.sb_score_threshold, 1, 1)
        controls_layout.setColumnStretch(0, 1)
        self.controls_widget.setLayout(controls_layout)
        self.controls_widget.setSizePolicy(self.cc.QSizePolicy.Preferred, self.cc.QSizePolicy.Fixed)
        # glue all together
        sample_info_layout.addWidget(self.label_current_function_matches)
        sample_info_layout.addWidget(self.controls_widget)
        sample_info_layout.addWidget(self.b_query_single)
        sample_info_layout.addWidget(self.hline)
        sample_info_layout.addWidget(self.label_function_matches)
        sample_info_layout.addWidget(self.table_function_matches)
        sample_info_layout.addWidget(self.label_function_names)
        sample_info_layout.addWidget(self.table_function_names)
        self.central_widget.setLayout(sample_info_layout)

    def _onCbFilterLibraryClicked(self, mi):
        """
        If the filter is altered, we refresh the table.
        """
        self.hook_refresh(None, use_current_function=True)

    def _onCbLiveClicked(self, mi):
        if self.cb_activate_live_tracking.isChecked():
            self.parent.main_widget.hideLocalWidget()
            self.updateViewWithCurrentFunction()

    def handleSpinThresholdChange(self):
        self.updateViewWithCurrentFunction()

    def enable(self):
        self.cb_filter_library.setEnabled(True)
        self.cb_activate_live_tracking.setEnabled(True)
        self.b_query_single.setEnabled(True)
        self.label_current_function_matches.setText(
            "Move the cursor to a function, or query the current one."
        )

    def _get_entry_field(self, entry, field):
        if entry is None:
            return None
        if hasattr(entry, field):
            return getattr(entry, field)
        if isinstance(entry, dict):
            return entry.get(field)
        return None

    def _get_sample_entry(self, sample_id):
        sample_infos = self.parent.sample_infos
        if isinstance(sample_infos, dict):
            return sample_infos.get(sample_id)
        return None

    def _get_family_entry(self, family_id):
        family_infos = self.parent.family_infos
        if isinstance(family_infos, dict):
            return family_infos.get(family_id)
        return None

    def _ensure_remote_cache(self):
        if not self.parent.family_infos:
            self.parent.mcrit_interface.queryAllFamilyEntries()
        if not self.parent.sample_infos:
            self.parent.mcrit_interface.queryAllSampleEntries()
        if self.parent.family_infos is None or self.parent.sample_infos is None:
            self.clearTable()
            self.label_current_function_matches.setText(
                "Remote family/sample info unavailable. Check server connection."
            )
            return False
        return True

    def updateCurrentFunction(self, view):
        function_start = self.cc.backend.get_current_function(view)
        if function_start is not None:
            self.parent.current_function = function_start
        return function_start

    def queryCurrentFunction(self):
        self.parent.main_widget.hideLocalWidget()
        self.updateViewWithCurrentFunction()

    def hook_refresh(self, view, use_current_function=False):
        if self.parent.local_smda_report is None:
            self.label_current_function_matches.setText("Convert to SMDA report first.")
            return
        # get current function from cursor position
        if self.updateCurrentFunction(view) is None and not use_current_function:
            return
        if self.parent.current_function == self.last_viewed and not use_current_function:
            return
        if not self.cb_activate_live_tracking.isChecked():
            self.clearTable()
            self.label_current_function_matches.setText("Live Function Queries are deactivated.")
            return
        self.updateViewWithCurrentFunction()

    def clearTable(self):
        # upper table
        self.table_function_matches.clear()
        self.table_function_matches.setSortingEnabled(False)
        self.function_matches_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS
        ]
        self.table_function_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_function_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        self.table_function_matches.setRowCount(0)
        self.table_function_matches.resizeRowToContents(0)
        # lower table
        self.table_function_names.clear()
        self.table_function_names.setSortingEnabled(False)
        self.function_names_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS
        ]
        self.table_function_names.setColumnCount(len(self.function_names_header_labels))
        self.table_function_names.setHorizontalHeaderLabels(self.function_names_header_labels)
        self.table_function_names.setRowCount(0)
        self.table_function_names.resizeRowToContents(0)

    def updateViewWithCurrentFunction(self):
        self.last_viewed = self.parent.current_function
        smda_function = self.parent.local_smda_report.getFunction(self.parent.current_function)
        if smda_function is None or smda_function.num_instructions < 10:
            self.clearTable()
            self.label_current_function_matches.setText(
                "Can only query functions with 10 instructions or more."
            )
            return
        if not self._ensure_remote_cache():
            return
        self.current_function_offset = self.parent.current_function
        match_report = None
        single_function_smda_report = self.parent.getLocalSmdaReportOutline()
        single_function_smda_report.xcfg = {smda_function.offset: smda_function}
        # check if pichash match data is already available in local cache
        if smda_function.offset not in self.parent.function_matches:
            self.parent.mcrit_interface.querySmdaFunctionMatches(single_function_smda_report)
        if smda_function.offset in self.parent.function_matches:
            match_report = MatchingResult.fromDict(
                self.parent.function_matches[smda_function.offset]
            )
            match_report.filterToFunctionScore(int(self.sb_score_threshold.value()))
            num_all_functions = len(match_report.function_matches)
            if self.cb_filter_library.isChecked():
                num_functions = len(
                    [m for m in match_report.filtered_function_matches if not m.match_is_library]
                )
                self.label_current_function_matches.setText(
                    "Matches for Function: 0x%x -- %d families, %d samples, %d functions (%d filtered)."
                    % (
                        self.parent.current_function,
                        match_report.num_original_family_matches,
                        match_report.num_original_sample_matches,
                        num_functions,
                        num_all_functions - num_functions,
                    )
                )
            elif len(match_report.filtered_function_matches) < len(match_report.function_matches):
                self.label_current_function_matches.setText(
                    "Matches for Function: 0x%x -- %d families, %d samples, %d functions (%d filtered)."
                    % (
                        self.parent.current_function,
                        match_report.num_original_family_matches,
                        match_report.num_original_sample_matches,
                        len(match_report.filtered_function_matches),
                        num_all_functions - len(match_report.filtered_function_matches),
                    )
                )
                self.current_function_offset = self.parent.current_function
            else:
                self.label_current_function_matches.setText(
                    "Matches for Function: 0x%x -- %d families, %d samples, %d functions."
                    % (
                        self.parent.current_function,
                        match_report.num_original_family_matches,
                        match_report.num_original_sample_matches,
                        num_all_functions,
                    )
                )
                self.current_function_offset = self.parent.current_function
        if match_report is None:
            self.clearTable()
            self.label_current_function_matches.setText(
                "Match query for function 0x%x failed; check the server connection."
                % self.parent.current_function
            )
        else:
            # populate tables with data
            self.populateFunctionMatchTable(match_report)
            # TODO fetch all labels to populate lower table as soon as we support this
            self.populateFunctionNameTable(match_report)

    def generateMatchTableCellItem(self, column_type, function_match_entry: MatchedFunctionEntry):
        tmp_item = None
        if column_type == McritTableColumn.FUNCTION_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_match_entry.matched_function_id)
        elif column_type == McritTableColumn.OFFSET:
            function_offset = self.parent.function_id_to_offset.get(
                function_match_entry.matched_function_id, 0
            )
            tmp_item = self.NumberQTableWidgetItem("0x%x" % function_offset)
        elif column_type == McritTableColumn.SHA256:
            sample_info = self._get_sample_entry(function_match_entry.matched_sample_id)
            sample_sha256 = self._get_entry_field(sample_info, "sha256")
            tmp_item = self.cc.QTableWidgetItem(sample_sha256[:8] if sample_sha256 else "unknown")
        elif column_type == McritTableColumn.SAMPLE_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_match_entry.matched_sample_id)
        elif column_type == McritTableColumn.FAMILY_NAME:
            family_info = self._get_family_entry(function_match_entry.matched_family_id)
            family_name = self._get_entry_field(family_info, "family_name")
            tmp_item = self.cc.QTableWidgetItem(family_name if family_name else "unknown")
        elif column_type == McritTableColumn.VERSION:
            sample_info = self._get_sample_entry(function_match_entry.matched_sample_id)
            sample_version = self._get_entry_field(sample_info, "version")
            tmp_item = self.cc.QTableWidgetItem(sample_version if sample_version else "-")
        elif column_type == McritTableColumn.PIC_HASH_MATCH:
            tmp_item = self.cc.QTableWidgetItem(
                "YES" if function_match_entry.match_is_pichash else "NO"
            )
        elif column_type == McritTableColumn.SCORE:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_match_entry.matched_score)
        elif column_type == McritTableColumn.IS_LIBRARY:
            library_value = "YES" if function_match_entry.match_is_library else "NO"
            tmp_item = self.cc.QTableWidgetItem("%s" % library_value)
        return tmp_item

    def populateFunctionMatchTable(self, match_report: MatchingResult):
        """
        Populate the function match table with all matches for the selected function_id
        """
        self.table_function_matches.setSortingEnabled(False)
        self.function_matches_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS
        ]
        self.table_function_matches.clear()
        self.table_function_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_function_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        # Identify number of table entries and prepare addresses to display
        if self.cb_filter_library.isChecked():
            self.table_function_matches.setRowCount(
                len([m for m in match_report.filtered_function_matches if not m.match_is_library])
            )
        else:
            self.table_function_matches.setRowCount(len(match_report.filtered_function_matches))
        self.table_function_matches.resizeRowToContents(0)

        row = 0
        sorted_entries = sorted(
            match_report.filtered_function_matches,
            key=lambda x: (
                x.matched_score
                + (1 if x.match_is_pichash else 0)
                + (1 if x.match_is_library else 0)
            ),
            reverse=True,
        )
        for function_match_entry in sorted_entries:
            if self.cb_filter_library.isChecked() and function_match_entry.match_is_library:
                continue
            for column, column_name in enumerate(self.function_matches_header_labels):
                column_type = self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS[column]
                tmp_item = self.generateMatchTableCellItem(column_type, function_match_entry)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                # colorize by score
                row_color = self.scp.scoreToColor(function_match_entry.matched_score, opacity=1)
                tmp_item.setBackground(QColor(row_color[0], row_color[1], row_color[2]))
                text_color = self.scp.textOnTintColor()
                if text_color is not None:
                    tmp_item.setForeground(QColor(text_color[0], text_color[1], text_color[2]))
                self.table_function_matches.setItem(row, column, tmp_item)
            # self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_function_matches.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_function_matches.resizeColumnsToContents()
        self.table_function_matches.setSortingEnabled(True)
        header = self.table_function_matches.horizontalHeader()
        header.setStretchLastSection(True)

    def generateNameTableCellItem(self, column_type, function_label_entry):
        tmp_item = None
        if column_type == McritTableColumn.FUNCTION_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_label_entry.function_id)
        elif column_type == McritTableColumn.SCORE:
            tmp_item = self.NumberQTableWidgetItem("%d" % function_label_entry.score)
        elif column_type == McritTableColumn.USER:
            tmp_item = self.cc.QTableWidgetItem(function_label_entry.username)
        elif column_type == McritTableColumn.FUNCTION_LABEL:
            tmp_item = self.cc.QTableWidgetItem(function_label_entry.function_label)
        elif column_type == McritTableColumn.TIMESTAMP:
            timestamp = function_label_entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            tmp_item = self.cc.QTableWidgetItem(timestamp)
        return tmp_item

    def populateFunctionNameTable(self, match_report: MatchingResult):
        """
        Populate the function name table with all names for the matches we found
        """
        function_matches_by_id = {
            match.matched_function_id: match for match in match_report.filtered_function_matches
        }
        cached_entries = self.parent.matched_function_entries or {}
        missing_ids = [fid for fid in function_matches_by_id if fid not in cached_entries]
        if missing_ids:
            self.parent.mcrit_interface.queryFunctionEntriesById(missing_ids)
        cached_entries = self.parent.matched_function_entries or {}
        matched_entries = {}
        for function_id in function_matches_by_id.keys():
            matched_entry = cached_entries.get(function_id)
            if matched_entry is None:
                continue
            matched_entries[function_id] = matched_entry
        function_label_entries = []
        for function_id, entry in matched_entries.items():
            if (
                self.cb_filter_library.isChecked()
                and function_matches_by_id[entry.function_id].match_is_library
            ):
                continue
            if entry.function_labels:
                for function_label in entry.function_labels:
                    function_label.score = function_matches_by_id[function_id].matched_score
                    function_label_entries.append(function_label)

        self.table_function_names.setSortingEnabled(False)
        self.function_matches_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS
        ]
        self.table_function_names.clear()
        self.table_function_names.setColumnCount(len(self.function_matches_header_labels))
        self.table_function_names.setHorizontalHeaderLabels(self.function_matches_header_labels)
        # Identify number of table entries and prepare addresses to display
        self.table_function_names.setRowCount(len(function_label_entries))
        self.table_function_names.resizeRowToContents(0)

        row = 0
        sorted_entries = sorted(
            function_label_entries, key=lambda x: (x.score, x.username, x.timestamp), reverse=True
        )
        for function_label_entry in sorted_entries:
            for column, column_name in enumerate(self.function_matches_header_labels):
                column_type = self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS[column]
                tmp_item = self.generateNameTableCellItem(column_type, function_label_entry)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_function_names.setItem(row, column, tmp_item)
            # self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_function_names.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_function_names.resizeColumnsToContents()
        self.table_function_names.setSortingEnabled(True)
        header = self.table_function_names.horizontalHeader()
        header.setStretchLastSection(True)

    def _onTableFunctionMatchDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to import the function_name to the current function
        """
        function_id_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.FUNCTION_ID, self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS
        )
        if function_id_column_index is not None:
            remote_function_id = int(
                self.table_function_matches.item(mi.row(), function_id_column_index).text()
            )
            smda_function_a = self.parent.local_smda_report.getFunction(
                self.current_function_offset
            )
            if smda_function_a is None:
                self.parent.local_widget.updateActivityInfo(
                    "Current function is unavailable; cannot open graph viewer."
                )
                return
            smda_report_a = self.parent.local_smda_report
            function_entry_b = self.parent.mcrit_interface.queryFunctionEntryById(
                remote_function_id
            )
            if function_entry_b is None:
                self.parent.local_widget.updateActivityInfo(
                    f"Failed to fetch function entry {remote_function_id}."
                )
                return
            smda_function_b = function_entry_b.toSmdaFunction()
            sample_entry_b = self.parent.mcrit_interface.querySampleEntryById(
                function_entry_b.sample_id
            )
            if sample_entry_b is None:
                self.parent.local_widget.updateActivityInfo(
                    f"Failed to fetch sample entry {function_entry_b.sample_id}."
                )
                return
            fcm = FunctionCfgMatcher(
                smda_report_a, smda_function_a, sample_entry_b, smda_function_b
            )
            coloring = fcm.getColoredMatches()
            coloring = {int(k[6:], 16): int(v[1:], 16) for k, v in coloring["b"].items()}
            self.cc.backend.show_function_graph(
                self, sample_entry_b, function_entry_b, smda_function_b, coloring
            )

    def _onTableFunctionNameDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to import the function_name to the current function
        """
        function_id_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.FUNCTION_ID, self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS
        )
        function_label_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.FUNCTION_LABEL, self.parent.config.FUNCTION_NAMES_TABLE_COLUMNS
        )
        if function_id_column_index is not None and mi.column() == function_id_column_index:
            smda_function_a = self.parent.local_smda_report.getFunction(
                self.current_function_offset
            )
            if smda_function_a is None:
                self.parent.local_widget.updateActivityInfo(
                    "Current function is unavailable; cannot open graph viewer."
                )
                return
            smda_report_a = self.parent.local_smda_report
            remote_function_id = int(
                self.table_function_names.item(mi.row(), function_id_column_index).text()
            )
            function_entry_b = self.parent.mcrit_interface.queryFunctionEntryById(
                remote_function_id
            )
            if function_entry_b is None:
                self.parent.local_widget.updateActivityInfo(
                    f"Failed to fetch function entry {remote_function_id}."
                )
                return
            smda_function_b = function_entry_b.toSmdaFunction()
            sample_entry_b = self.parent.mcrit_interface.querySampleEntryById(
                function_entry_b.sample_id
            )
            if sample_entry_b is None:
                self.parent.local_widget.updateActivityInfo(
                    f"Failed to fetch sample entry {function_entry_b.sample_id}."
                )
                return
            fcm = FunctionCfgMatcher(
                smda_report_a, smda_function_a, sample_entry_b, smda_function_b
            )
            coloring = fcm.getColoredMatches()
            coloring = {int(k[6:], 16): int(v[1:], 16) for k, v in coloring["b"].items()}
            self.cc.backend.show_function_graph(
                self, sample_entry_b, function_entry_b, smda_function_b, coloring
            )
        elif function_label_column_index is not None and mi.column() == function_label_column_index:
            function_name = self.table_function_names.item(
                mi.row(), function_label_column_index
            ).text()
            with self.cc.backend.mutation("Apply MCRIT label"):
                self.cc.backend.set_function_name(self.last_viewed, function_name)

    def _onTableFunctionMatchRightClicked(self, position):
        """
        Right click context menu for function matches
        """
        sha256_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SHA256, self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS
        )
        sample_id_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SAMPLE_ID, self.parent.config.FUNCTION_MATCHES_TABLE_COLUMNS
        )
        if (
            sha256_column_index is not None
            and self.table_function_matches.currentColumn() == sha256_column_index
        ):
            if sample_id_column_index is None:
                # TODO possibly can reconstruct clicked row from matching data, but let's keep it simple for now
                print("Need a column with sample IDs to copy SHA256 to clipboard.")
            # copy to clipboard
            sample_id_item = self.table_function_matches.item(
                self.table_function_matches.currentRow(), sample_id_column_index
            )
            if sample_id_item is None:
                return
            sample_id = sample_id_item.text()
            sample_info = self._get_sample_entry(int(sample_id))
            sample_sha256 = self._get_entry_field(sample_info, "sha256")
            if sample_sha256:
                self.parent.copyStringToClipboard(sample_sha256)
