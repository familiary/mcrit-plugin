import mcrit_plugin.core.McritTableColumn as McritTableColumn
import mcrit_plugin.ui_qt.QtShim as QtShim
from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider, ThemeRole
from mcrit_plugin.ui_qt.widgets.NumberQTableWidgetItem import NumberQTableWidgetItem

QMainWindow = QtShim.get_QMainWindow()
QStyledItemDelegate = QtShim.get_QStyledItemDelegate()
QComboBox = QtShim.get_QComboBox()
QColor = QtShim.get_QColor()
QPalette = QtShim.get_QPalette()


class ColoredComboBox(QComboBox):
    criticality_roles = {
        1: (ThemeRole.BLUE, (70, 120, 220)),
        2: (ThemeRole.CYAN, (70, 180, 70)),
        3: (ThemeRole.GREEN, (100, 255, 100)),
        4: (ThemeRole.YELLOW, (255, 255, 100)),
        5: (ThemeRole.RED, (255, 100, 100)),
    }

    def __init__(self, parent=None, criticality=0, backend=None):
        super().__init__(parent)
        self.criticality = criticality
        self.user_has_interacted = False
        self.user_made_selection = False
        self.programmatic_change = False

        # Connect signals to track user interaction
        self.activated.connect(self._on_user_activated)
        self.currentTextChanged.connect(self._on_text_changed)

        # Set colors immediately in constructor
        scp = ScoreColorProvider(backend)
        color_rgb = None
        if criticality:
            role, default = self.criticality_roles[min(criticality, 5)]
            color_rgb = "%d, %d, %d" % scp.roleColor(role, default)

        if color_rgb:
            text_color = scp.textOnTintColor()
            text_rule = "color: rgb(%d, %d, %d);" % text_color if text_color else ""
            # Use more aggressive stylesheet targeting all parts of the combobox
            stylesheet = f"""
                QComboBox {{
                    background-color: rgb({color_rgb});
                    {text_rule}
                    border: 1px solid gray;
                }}
                QComboBox:drop-down {{
                    background-color: rgb({color_rgb});
                }}
                QComboBox:disabled {{
                    background-color: rgb({color_rgb});
                    {text_rule}
                }}
                QComboBox QAbstractItemView {{
                    background-color: rgb({color_rgb});
                    {text_rule}
                }}
            """

            self.setStyleSheet(stylesheet)
            self.setAutoFillBackground(True)

    def _on_user_activated(self, index):
        """Called when user actively selects an item from dropdown"""
        if not self.programmatic_change:
            self.user_has_interacted = True
            self.user_made_selection = True

    def _on_text_changed(self, text):
        """Called when text changes - but this can be misleading for dropdowns"""
        # For QComboBox, text changes can happen without user selection
        # We rely more on the activated signal for true user interaction
        if not self.programmatic_change and hasattr(self, "user_has_interacted"):
            # Only mark as interacted if text actually changed to something different
            if not hasattr(self, "_last_known_text") or self._last_known_text != text:
                self.user_has_interacted = True
                self._last_known_text = text

    def showPopup(self):
        """Override to track when dropdown is opened"""
        self.dropdown_was_opened = True
        super().showPopup()

    def hidePopup(self):
        """Override to track when dropdown is closed"""
        super().hidePopup()
        # If dropdown was opened but no selection was made via activated signal,
        # and text didn't change, then user just clicked away
        if hasattr(self, "dropdown_was_opened") and self.dropdown_was_opened:
            self.dropdown_was_opened = False

    def setCurrentText(self, text):
        """Override to mark programmatic changes"""
        self.programmatic_change = True
        super().setCurrentText(text)
        self.programmatic_change = False

    def setCurrentIndex(self, index):
        """Override to mark programmatic changes"""
        self.programmatic_change = True
        super().setCurrentIndex(index)
        self.programmatic_change = False

    def hasUserInteracted(self):
        """Check if user has ever interacted with this combobox"""
        return self.user_has_interacted

    def hasUserMadeSelection(self):
        """Check if user has actively selected an item from dropdown"""
        return self.user_made_selection

    def hasUserOpenedDropdown(self):
        """Check if user has opened the dropdown (even without selecting)"""
        return hasattr(self, "dropdown_was_opened") and self.dropdown_was_opened

    def getUserInteractionType(self):
        """Get detailed info about user interaction"""
        if self.user_made_selection:
            return "SELECTED"  # User made an actual selection
        elif self.user_has_interacted:
            return "INTERACTED"  # User changed text somehow but didn't use dropdown
        elif hasattr(self, "dropdown_was_opened"):
            return "OPENED"  # User opened dropdown but didn't select
        else:
            return "NONE"  # No user interaction at all


class DropdownDelegate(QStyledItemDelegate):
    def __init__(
        self, function_name_mapping, row_criticality_mapping=None, parent_widget=None, backend=None
    ):
        super().__init__()
        self.backend = backend
        self.function_name_mapping = function_name_mapping
        self.row_criticality_mapping = (
            row_criticality_mapping if row_criticality_mapping is not None else {}
        )
        self.parent_widget = parent_widget
        # Store references to created editors
        self.editors_by_row = {}  # row -> ColoredComboBox

    def createEditor(self, parent, option, index):
        criticality = self.row_criticality_mapping.get(index.row(), 0)
        editor = ColoredComboBox(parent, criticality, self.backend)
        choices = self.function_name_mapping.get((index.row(), index.column()), [])
        choice_items = [entry["text"] for entry in choices]
        editor.addItems(choice_items)
        editor.setCurrentText(
            next((entry["text"] for entry in choices if entry["preselected"]), choice_items[0])
        )

        # Store editor reference by row
        self.editors_by_row[index.row()] = editor

        # Store row information for right-click handling
        editor.table_row = index.row()
        editor.table_column = index.column()

        # Enable context menu for the combo box to handle right-clicks
        editor.setContextMenuPolicy(QtShim.get_Qt().CustomContextMenu)
        editor.customContextMenuRequested.connect(
            lambda pos: self._handleComboBoxRightClick(editor, pos)
        )

        return editor

    def getEditorForRow(self, row):
        """Get the ColoredComboBox editor for a specific row"""
        return self.editors_by_row.get(row, None)

    def getUserInteractionTypeForRow(self, row):
        """Get interaction type for a specific row"""
        editor = self.getEditorForRow(row)
        if editor:
            return editor.getUserInteractionType()
        return "NONE"

    def _handleComboBoxRightClick(self, combo_box, position):
        """Handle right-click events on combo box"""
        if self.parent_widget and hasattr(combo_box, "table_row"):
            row = combo_box.table_row
            column = combo_box.table_column

            # Call the parent widget's right-click handler directly
            if hasattr(self.parent_widget, "_handleRightClickOnRow"):
                self.parent_widget._handleRightClickOnRow(row, column)

    def setEditorData(self, editor, index):
        value = index.data()
        editor.setCurrentText(value)

    def setModelData(self, editor, model, index):
        value = editor.currentText()
        model.setData(index, value)


class FunctionOverviewWidget(QMainWindow):
    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading FunctionOverviewWidget")
        self.last_selected_fields = {}  # offset -> selected label string
        self._label_requested_ids = set()
        self._score_range_job_id = None
        self.resolved_function_labels = {}  # offset -> resolved label string
        # enable access to shared MCRIT4IDA modules
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
        self.rb_filter_none.toggled.connect(self.update)
        self.rb_filter_labels.toggled.connect(self.update)
        self.rb_filter_applicable.toggled.connect(self.update)
        self.rb_filter_conflicted.toggled.connect(self.update)

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
        self.table_local_functions = self.cc.QTableWidget()
        self.table_local_functions.doubleClicked.connect(self._onTableFunctionsDoubleClicked)
        # Enable context menu for right-click handling -> we need to do that in the delegate now
        # self.table_local_functions.setContextMenuPolicy(self.cc.QtCore.Qt.CustomContextMenu)
        # self.table_local_functions.customContextMenuRequested.connect(self._onTableFunctionsRightClicked)
        # cache for function_names
        self.function_name_mapping = None
        self.current_rows = []
        # static links to objects to help IDA
        self.NumberQTableWidgetItem = NumberQTableWidgetItem
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
        matched_function_ids = set()
        for function_match in match_report.function_matches:
            matched_function_ids.add(function_match.matched_function_id)
        print("Number of matched remote functions: ", len(matched_function_ids))
        if force:
            self._label_requested_ids = set()
        # with_label_only answers nothing for unlabeled functions, so the cache alone cannot tell
        # a pending id from one already known to be unlabeled
        pending_ids = matched_function_ids - self._label_requested_ids
        if pending_ids:
            fetched = self.parent.mcrit_interface.queryFunctionEntriesById(
                list(pending_ids), with_label_only=True
            )
            if fetched is not None:
                self._label_requested_ids |= pending_ids
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

    def getSelectedLabel(self, row, column):
        """Get the currently selected label value from a ComboBox editor or table item"""
        # Get the actual selected value from the ComboBox editor, not the table item
        selected_item_value = None
        delegate = self.table_local_functions.itemDelegateForColumn(column)
        if hasattr(delegate, "getEditorForRow"):
            editor = delegate.getEditorForRow(row)
            if editor:
                selected_item_value = editor.currentText()

        # Fallback to table item if no editor found
        if selected_item_value is None:
            selected_item_value = (
                self.table_local_functions.item(row, column).text() if column is not None else None
            )

        return selected_item_value

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
        if not self.function_name_mapping:
            self.parent.local_widget.updateActivityInfo("No labels loaded. Fetch labels first.")
            return
        num_names_applied = 0
        num_names_skipped = 0
        with self.cc.backend.mutation("Import MCRIT labels"):
            for row_id in range(self.table_local_functions.rowCount()):
                offset = int(self.table_local_functions.item(row_id, 0).text(), 16)
                label_via_table = self.getSelectedLabel(row_id, label_score_column_index)
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
            self.sb_minhash_threshold.setRange(
                config_adjusted_lower_value, self.global_maximum_match_value
            )
            self.sb_minhash_threshold.setValue(config_adjusted_lower_value)

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

    def generateFunctionTableCellItem(self, column_type, function_info):
        tmp_item = None
        if column_type == McritTableColumn.OFFSET:
            tmp_item = self.cc.QTableWidgetItem("0x%x" % function_info["offset"])
        elif column_type == McritTableColumn.FAMILIES:
            tmp_item = self.NumberQTableWidgetItem("%d" % len(function_info["families"]))
        elif column_type == McritTableColumn.SAMPLES:
            tmp_item = self.NumberQTableWidgetItem("%d" % len(function_info["samples"]))
        elif column_type == McritTableColumn.FUNCTIONS:
            tmp_item = self.NumberQTableWidgetItem("%d" % len(function_info["functions"]))
        elif column_type == McritTableColumn.IS_LIBRARY:
            library_value = "YES" if len(function_info["library_matches"]) > 0 else "NO"
            tmp_item = self.cc.QTableWidgetItem("%s" % library_value)
        elif column_type == McritTableColumn.SCORE_AND_LABEL:
            label_value = "-"
            tmp_item = self.cc.QTableWidgetItem("%s" % label_value)
        return tmp_item

    def populateFunctionTable(self, track_selection=True):
        """
        Populate the function table with information about matches of local functions.
        """
        header_view = self._QtShim.get_QHeaderView()
        qt = self._QtShim.get_Qt()

        match_report = self.parent.getMatchingReport()
        if match_report is None:
            return
        self.ensureSpinBoxRange(match_report)
        threshold_value = self.sb_minhash_threshold.value()

        # count matched functions with labels
        function_entries_with_labels = {}
        if self.parent.matched_function_entries:
            for function_id, function_entry in self.parent.matched_function_entries.items():
                if function_entry.function_labels:
                    function_entries_with_labels[function_id] = function_entry

        # count labels
        function_labels = []
        for function_id, entry in function_entries_with_labels.items():
            for label in entry.function_labels:
                function_labels.append(label)

        # count matched functions
        matched_function_ids_per_function_id = {}
        matches_beyond_filters = 0
        functions_beyond_filters = set()
        aggregated_matches = {}
        for function_match in match_report.function_matches:
            if function_match.function_id not in matched_function_ids_per_function_id:
                matched_function_ids_per_function_id[function_match.function_id] = []
            if (
                function_match.matched_function_id
                not in matched_function_ids_per_function_id[function_match.function_id]
            ):
                matched_function_ids_per_function_id[function_match.function_id].append(
                    function_match.matched_function_id
                )
            if function_match.matched_score >= threshold_value:
                if (
                    self.getSelectedFilter() != "none"
                    and function_match.matched_function_id not in function_entries_with_labels
                ):
                    continue
                matches_beyond_filters += 1
                functions_beyond_filters.add(function_match.function_id)
                if function_match.function_id not in aggregated_matches:
                    aggregated_matches[function_match.function_id] = {
                        "offset": function_match.offset,
                        "families": set(),
                        "samples": set(),
                        "functions": set(),
                        "library_matches": set(),
                        "labels": set(),
                    }
                aggregated_matches[function_match.function_id]["families"].add(
                    function_match.matched_family_id
                )
                aggregated_matches[function_match.function_id]["samples"].add(
                    function_match.matched_sample_id
                )
                aggregated_matches[function_match.function_id]["functions"].add(
                    function_match.matched_function_id
                )
                if function_match.match_is_library:
                    aggregated_matches[function_match.function_id]["library_matches"].add(
                        function_match.matched_function_id
                    )
                if function_match.matched_function_id in function_entries_with_labels:
                    for label in function_entries_with_labels[
                        function_match.matched_function_id
                    ].function_labels:
                        aggregated_matches[function_match.function_id]["labels"].add(
                            (
                                int(function_match.matched_score),
                                label.function_label,
                                label.username,
                                label.timestamp,
                            )
                        )

        # count filtered functions again
        filtered_list = {}
        crit_functions_beyond_filters = set()
        crit_matches_beyond_filters = 0
        crit_function_labels = []
        for function_id, function_info in sorted(aggregated_matches.items()):
            is_custom_name = not self.cc.backend.has_default_function_name(function_info["offset"])
            criticality = self._calculateLabelCriticality(
                list(sorted(function_info["labels"], reverse=True)),
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
        update_text = f"Showing {len(functions_beyond_filters)} functions with {matches_beyond_filters} matches and {len(function_labels)} labels ({len(matched_function_ids_per_function_id) - len(functions_beyond_filters)} functions and {len(match_report.function_matches) - matches_beyond_filters} matches filtered)"
        self.label_local_functions.setText(update_text)

        label_score_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SCORE_AND_LABEL, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        offset_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.OFFSET, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        self.local_function_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.OVERVIEW_TABLE_COLUMNS
        ]
        self.table_local_functions.setSortingEnabled(False)

        if track_selection:
            # maintain a registry of current selections made by the user
            new_selected_fields = {}
            for row in range(self.table_local_functions.rowCount()):
                offset = (
                    int(self.table_local_functions.item(row, offset_column_index).text(), 16)
                    if offset_column_index is not None
                    else None
                )
                item = (
                    self.table_local_functions.item(row, label_score_column_index).text()
                    if label_score_column_index is not None
                    else None
                )
                selected_item = None
                if item is not None:
                    if offset is not None:
                        if offset in self.last_selected_fields:
                            if item == "-":
                                selected_item = self.last_selected_fields[offset]
                            elif item != self.last_selected_fields[offset]:
                                selected_item = item
                            else:
                                selected_item = self.last_selected_fields[offset]
                            score = selected_item.split("|")[0] if "|" in selected_item else "-"
                            if score != "-":
                                if int(score) >= threshold_value:
                                    # selection is fine, keep it
                                    pass
                                else:
                                    # set to highest value instead
                                    selected_item = "-"
                            else:
                                selected_item = "-|-"
                        else:
                            selected_item = item
                if selected_item == "-" and self.function_name_mapping:
                    selected_item = self.function_name_mapping[(row, label_score_column_index)][0][
                        "text"
                    ]
                new_selected_fields[offset] = selected_item
            self.last_selected_fields = new_selected_fields

        self.table_local_functions.clear()
        self.table_local_functions.setColumnCount(len(self.local_function_header_labels))
        self.table_local_functions.setHorizontalHeaderLabels(self.local_function_header_labels)
        # Identify number of table entries and prepare addresses to display
        self.table_local_functions.setRowCount(len(aggregated_matches))
        self.table_local_functions.resizeRowToContents(0)
        row = 0
        self.function_name_mapping = {}
        self.row_criticality_mapping = {}
        self.current_rows = aggregated_matches

        if label_score_column_index is not None:
            for function_id, function_info in sorted(aggregated_matches.items()):
                # set label based on stored selection if available
                rows_labels = []
                preselected_label = self.last_selected_fields.get(function_info["offset"], None)
                if function_info["offset"] in self.resolved_function_labels:
                    resolved_label = self.resolved_function_labels[function_info["offset"]]
                    preselected_label = resolved_label
                label_assigned = False
                for label_entry in sorted(function_info["labels"], reverse=True):
                    formatted_label_entry = f"{label_entry[0]}|{label_entry[1]}"
                    if formatted_label_entry == preselected_label and not label_assigned:
                        rows_labels.append({"text": formatted_label_entry, "preselected": True})
                        label_assigned = True
                    else:
                        rows_labels.append({"text": formatted_label_entry, "preselected": False})
                rows_labels.append({"text": "-|-", "preselected": preselected_label == "-|-"})
                self.function_name_mapping[(row, label_score_column_index)] = rows_labels
                self.row_criticality_mapping[row] = function_info.get("criticality", 0)
                for column, column_name in enumerate(self.local_function_header_labels):
                    column_type = self.parent.config.OVERVIEW_TABLE_COLUMNS[column]
                    tmp_item = self.generateFunctionTableCellItem(column_type, function_info)
                    tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                    tmp_item.setTextAlignment(qt.AlignHCenter)
                    self.table_local_functions.setItem(row, column, tmp_item)
                self.table_local_functions.resizeRowToContents(row)
                row += 1
            # we need to set up rendering delegates for function names only if we have names at all
            if function_labels:
                # Set the delegate to create dropdown menus in the second column
                delegate = DropdownDelegate(
                    self.function_name_mapping,
                    self.row_criticality_mapping,
                    self,
                    self.cc.backend,
                )
                self.table_local_functions.setItemDelegateForColumn(
                    label_score_column_index, delegate
                )

                # Show the dropdown menus immediately
                for row in range(self.table_local_functions.rowCount()):
                    item = self.table_local_functions.item(
                        row, label_score_column_index
                    )  # Get the QTableWidgetItem for the cell
                    self.table_local_functions.openPersistentEditor(item)

        self.table_local_functions.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_local_functions.resizeColumnsToContents()
        self.table_local_functions.setSortingEnabled(True)
        header = self.table_local_functions.horizontalHeader()

        for header_id in range(0, len(self.local_function_header_labels), 1):
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

    def _handleRightClickOnRow(self, row, column):
        """Handle right-click action for a specific row and column"""
        function_label_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SCORE_AND_LABEL, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        if column == function_label_column and row >= 0:
            # For this column, get the specific function's labels from the current row
            function_ids = list(sorted(self.current_rows.keys()))
            if row < len(function_ids):
                function_id = function_ids[row]
                aggregated_result = self.current_rows[function_id]
                function_offset = aggregated_result["offset"]
                if function_offset in self.resolved_function_labels:
                    self.resolved_function_labels.pop(function_offset)
                    self.update()
                else:
                    label_score_column_index = McritTableColumn.columnTypeToIndex(
                        McritTableColumn.SCORE_AND_LABEL, self.parent.config.OVERVIEW_TABLE_COLUMNS
                    )
                    offset_column_index = McritTableColumn.columnTypeToIndex(
                        McritTableColumn.OFFSET, self.parent.config.OVERVIEW_TABLE_COLUMNS
                    )
                    for row in range(self.table_local_functions.rowCount()):
                        offset = (
                            int(
                                self.table_local_functions.item(row, offset_column_index).text(), 16
                            )
                            if offset_column_index is not None
                            else None
                        )

                        if offset == function_offset:
                            selected_item_value = self.getSelectedLabel(
                                row, label_score_column_index
                            )
                            if selected_item_value is not None:
                                self.resolved_function_labels[function_offset] = selected_item_value
                                self.update()
                                break

    def _onTableFunctionsDoubleClicked(self, mi):
        function_offset_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.OFFSET, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        function_label_column = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SCORE_AND_LABEL, self.parent.config.OVERVIEW_TABLE_COLUMNS
        )
        offset_item = self.table_local_functions.item(mi.row(), function_offset_column)
        if offset_item is None:
            return
        clicked_function_address = offset_item.text()
        if mi.column() not in [function_offset_column, function_label_column]:
            self.cc.backend.jump_to(int(clicked_function_address, 16))
            # change to function scope tab
            self.parent.main_widget.setTabFocus(self.parent.function_match_widget.name)
            self.parent.function_match_widget.queryCurrentFunction()
        elif mi.column() == function_offset_column:
            self.cc.backend.jump_to(int(clicked_function_address, 16))
