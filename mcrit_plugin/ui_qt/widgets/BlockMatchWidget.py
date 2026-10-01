import threading
import time
from concurrent.futures import ThreadPoolExecutor

import mcrit_plugin.core.McritTableColumn as McritTableColumn
import mcrit_plugin.ui_qt.QtShim as QtShim
from mcrit_plugin.core.minimcrit.matchers.FunctionCfgMatcher import FunctionCfgMatcher
from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider, ThemeRole
from mcrit_plugin.ui_qt.widgets.NumberQTableWidgetItem import NumberQTableWidgetItem

QMainWindow = QtShim.get_QMainWindow()
QColor = QtShim.get_QColor()
BLOCK_QUERY_WORKERS = 8


def packRgb(rgb):
    return (rgb[0] << 16) | (rgb[1] << 8) | rgb[2]


class BlockMatchWidget(QMainWindow):
    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading BlockMatchWidget")
        self.parent = parent
        self.scp = ScoreColorProvider(self.cc.backend)
        self.last_viewed_function = None
        self.last_viewed_block = None
        self._last_block_matches = None
        self.name = "Block Scope"
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "puzzle.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.label_current_function_matches = self.cc.QLabel("Block Matches for: <function_offset>")
        self.cb_filter_library = self.cc.QCheckBox("Filter out Library Matches")
        self.cb_filter_library.setEnabled(False)
        self.cb_filter_library.setChecked(self.parent.config.BLOCKS_FILTER_LIBRARY_FUNCTIONS)
        self.cb_filter_library.clicked.connect(self._onCbFilterLibraryClicked)
        self.cb_activate_live_tracking = self.cc.QCheckBox("Live Block Queries")
        self.cb_activate_live_tracking.setEnabled(False)
        self.cb_activate_live_tracking.setChecked(self.parent.config.BLOCKS_LIVE_QUERY)
        self.cb_activate_live_tracking.clicked.connect(self._onCbLiveClicked)
        # filter wheel
        self.sb_blocksize_threshold = self.cc.QSpinBox()
        self.sb_blocksize_threshold.setRange(4, 20)
        self.sb_blocksize_threshold.setValue(self.parent.config.BLOCKS_MIN_SIZE)
        self.sb_blocksize_threshold.valueChanged.connect(self.handleSpinThresholdChange)
        self.label_sb_threshold = self.cc.QLabel("Min. Block Size: ")
        # query button
        self.b_query_single = self.cc.QPushButton("Query current basic block")
        self.b_query_single.clicked.connect(self.queryCurrentBlock)
        self.b_query_single.setEnabled(False)
        ### self.cb_filter_library.stateChanged.connect(self.populateBestMatchTable)
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.cc.QFrameHLine)
        self.hline.setFrameShadow(self.cc.QFrameShadow.Sunken)
        # upper table
        self.label_block_summary = self.cc.QLabel("Blocks Summary")
        self.table_block_summary = self.cc.QTableWidget()
        self.table_block_summary.clicked.connect(self._onTableBlockSummaryClicked)
        self.table_block_summary.doubleClicked.connect(self._onTableBlockSummaryDoubleClicked)
        # lower table
        self.label_block_matches = self.cc.QLabel("Block Matches for <block_offset>")
        self.table_block_matches = self.cc.QTableWidget()
        self.table_block_matches.doubleClicked.connect(self._onTableBlockMatchesDoubleClicked)
        self.table_block_matches.setContextMenuPolicy(self.cc.QtCore.Qt.CustomContextMenu)
        self.table_block_matches.customContextMenuRequested.connect(
            self._onTableBlockMatchesRightClicked
        )
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
        block_info_layout = self.cc.QVBoxLayout()
        self.controls_widget = self.cc.QWidget()
        controls_layout = self.cc.QGridLayout()
        controls_layout.setContentsMargins(0, 0, 0, 0)
        controls_layout.addWidget(self.cb_filter_library, 0, 0)
        controls_layout.addWidget(self.cb_activate_live_tracking, 1, 0)
        controls_layout.addWidget(self.label_sb_threshold, 0, 1)
        controls_layout.addWidget(self.sb_blocksize_threshold, 1, 1)
        controls_layout.setColumnStretch(0, 1)
        self.controls_widget.setLayout(controls_layout)
        self.controls_widget.setSizePolicy(self.cc.QSizePolicy.Preferred, self.cc.QSizePolicy.Fixed)
        # glue all together
        block_info_layout.addWidget(self.label_current_function_matches)
        block_info_layout.addWidget(self.controls_widget)
        block_info_layout.addWidget(self.b_query_single)
        block_info_layout.addWidget(self.hline)
        block_info_layout.addWidget(self.label_block_summary)
        block_info_layout.addWidget(self.table_block_summary)
        block_info_layout.addWidget(self.label_block_matches)
        block_info_layout.addWidget(self.table_block_matches)
        self.central_widget.setLayout(block_info_layout)

    def _onCbLiveClicked(self, mi):
        if self.cb_activate_live_tracking.isChecked():
            self.queryCurrentBlock()

    def _onCbFilterLibraryClicked(self, mi):
        """
        If the filter is altered, we refresh the table.
        """
        self.hook_refresh(None, use_current_block=True)

    def enable(self):
        self.cb_filter_library.setEnabled(True)
        self.cb_activate_live_tracking.setEnabled(True)
        self.b_query_single.setEnabled(True)
        self.label_current_function_matches.setText(
            "Move the cursor to a basic block, or query the current one."
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

    def _fetch_remote_cache(self):
        """Request the family and sample lists if they are missing; touches no widget."""
        return self.parent.mcrit_interface.ensureRemoteInformation()

    def _show_remote_cache_unavailable(self):
        self.clearTable()
        self.label_current_function_matches.setText(
            "Remote family/sample info unavailable. Check server connection."
        )

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

    def handleSpinThresholdChange(self):
        self.updateViewWithCurrentBlock()

    def queryCurrentBlock(self):
        self.parent.main_widget.hideLocalWidget()
        # the refresh hook sets current_block only once a report exists, so take it from the cursor
        address = self.cc.backend.get_cursor_address()
        if address is not None and self.parent.local_smda_report is not None:
            block = self.parent.local_smda_report.findBlockByContainedAddress(address)
            if block:
                self.parent.current_block = block.offset
                # the Function Scope hook may not have seen this cursor move yet
                self.parent.current_function = block.smda_function.offset
        self.updateViewWithCurrentBlock()

    def hook_refresh(self, view, use_current_block=False):
        if self.parent.local_smda_report is None:
            self.label_current_function_matches.setText("Convert to SMDA report first.")
            return
        # get current function from cursor position
        if self.updateCurrentBlock(view) is None and not use_current_block:
            return
        if self.parent.current_function == self.last_viewed_function and not use_current_block:
            return
        if not self.cb_activate_live_tracking.isChecked():
            self.clearTable()
            self.label_current_function_matches.setText("Live Block Queries are deactivated.")
            return
        self.updateViewWithCurrentBlock()

    def clearTable(self):
        # upper table
        self.table_block_summary.clear()
        self.table_block_summary.setSortingEnabled(False)
        self.function_matches_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.BLOCK_SUMMARY_TABLE_COLUMNS
        ]
        self.table_block_summary.setColumnCount(len(self.function_matches_header_labels))
        self.table_block_summary.setHorizontalHeaderLabels(self.function_matches_header_labels)
        self.table_block_summary.setRowCount(0)
        self.table_block_summary.resizeRowToContents(0)
        # lower table
        self.table_block_matches.clear()
        self.table_block_matches.setSortingEnabled(False)
        self.function_matches_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.BLOCK_MATCHES_TABLE_COLUMNS
        ]
        self.table_block_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_block_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        self.table_block_matches.setRowCount(0)
        self.table_block_matches.resizeRowToContents(0)

    def updateViewWithCurrentBlock(self):
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
        # calculate all block pichashes
        min_block_size = self.sb_blocksize_threshold.value()
        pbh = FunctionCfgMatcher.getPicBlockHashesForFunction(
            self.parent.local_smda_report, smda_function, min_size=min_block_size
        )

        def request():
            if self.parent.current_function != function_offset:
                return None
            if not self._fetch_remote_cache():
                return False
            self._lookupBlockHashes(
                [entry["hash"] for entry in pbh],
                stop=lambda: self.parent.current_function != function_offset,
            )
            return True

        def show(remote_cache_ready):
            # a live query answered after the cursor moved on; its results stay cached
            if remote_cache_ready is None or self.parent.current_function != function_offset:
                return
            if not remote_cache_ready:
                # the next cursor move in this function tries again
                self.last_viewed_function = None
                self._show_remote_cache_unavailable()
                return
            if self.parent.current_block:
                self.label_block_matches.setText(
                    "No Block Matches for: 0x%x" % self.parent.current_block
                )
            self._showBlockMatches(pbh)

        # with every block cached, e.g. after a filter change, no request delays the table
        if (
            self.parent.family_infos is not None
            and self.parent.sample_infos is not None
            and all(entry["hash"] in self.parent.blockhash_matches for entry in pbh)
        ):
            show(True)
        else:
            self.cc.backend.run_request(
                "MCRIT: querying block matches for function 0x%x" % function_offset, request, show
            )

    def _lookupBlockHashes(self, hashes, stop=None):
        """Query the uncached hashes concurrently; MCRIT answers one block hash per request.

        Lookups not yet started are skipped once stop() is true; they stay uncached."""
        missing = [h for h in dict.fromkeys(hashes) if h not in self.parent.blockhash_matches]
        if not missing:
            return
        failed = threading.Event()

        def lookup(block_hash):
            # after a failure the remaining lookups would each wait out the same timeout
            if failed.is_set() or (stop is not None and stop()):
                return None
            matches = self.parent.mcrit_interface.getMatchesForPicBlockHash(block_hash)
            if matches is None:
                failed.set()
            return matches

        start = time.time()
        with ThreadPoolExecutor(BLOCK_QUERY_WORKERS) as pool:
            for block_hash, matches in zip(missing, pool.map(lookup, missing)):
                # a failed query stays uncached so the next visit retries it
                if matches is not None:
                    self.parent.blockhash_matches[block_hash] = matches
        duration = time.time() - start
        print(
            f"Querying {len(missing)} blocks took {duration:5.3f} seconds, "
            f"or {duration / len(missing):5.3f} seconds per block."
        )

    def _showBlockMatches(self, pbh):
        block_matches_by_offset = {}
        for entry in pbh:
            pichash_matches = self.parent.blockhash_matches.get(entry["hash"]) or []
            # cache this so we only query once per block
            if entry["offset"] not in self.parent.block_to_hash:
                self.parent.block_to_hash[entry["offset"]] = entry["hash"]
            summary = {
                "families": len(set([e[0] for e in pichash_matches])),
                "samples": len(set([e[1] for e in pichash_matches])),
                "functions": len(set([e[2] for e in pichash_matches])),
                "offsets": len(pichash_matches),
            }
            block_matches_by_offset[entry["offset"]] = {
                "picblockhash": entry,
                "matches": pichash_matches,
                "summary": summary,
                "has_library_matches": False,
            }
        if block_matches_by_offset:
            # TODO when filtering, we should actually fully remove them by offset here, as we don't want to see such blocks in the summary later on
            set_families = set([])
            set_samples = set([])
            set_all_functions = set([])
            set_functions = set([])
            library_families = []
            for k, v in self.parent.family_infos.items():
                if v.num_samples and v.num_library_samples == v.num_samples:
                    library_families.append(k)
            offsets_to_drop = set([])
            for offset, data in block_matches_by_offset.items():
                set_all_functions.update([entry[2] for entry in data["matches"]])
                filtered_matches = [
                    entry for entry in data["matches"] if entry[0] not in library_families
                ]
                if len(filtered_matches) < len(data["matches"]):
                    block_matches_by_offset[offset]["has_library_matches"] = True
                    offsets_to_drop.add(offset)
                # reduce matches if we actually have matched some blocks against libraries
                if (
                    self.cb_filter_library.isChecked()
                    and block_matches_by_offset[offset]["has_library_matches"]
                ):
                    block_matches_by_offset[offset]["matches"] = filtered_matches
                    continue
                block_matches_by_offset[offset]["summary"] = {
                    "families": len(set([e[0] for e in filtered_matches])),
                    "samples": len(set([e[1] for e in filtered_matches])),
                    "functions": len(set([e[2] for e in filtered_matches])),
                    "offsets": len(filtered_matches),
                }
                set_families.update([entry[0] for entry in filtered_matches])
                set_samples.update([entry[1] for entry in filtered_matches])
                set_functions.update([entry[2] for entry in filtered_matches])
            if self.cb_filter_library.isChecked():
                for offset in offsets_to_drop:
                    block_matches_by_offset.pop(offset, None)
                self.label_current_function_matches.setText(
                    "Block Matches for Function: 0x%x -- %d families, %d samples, %d functions (%d filtered)."
                    % (
                        self.parent.current_function,
                        len(set_families),
                        len(set_samples),
                        len(set_functions),
                        len(set_all_functions) - len(set_functions),
                    )
                )
            else:
                self.label_current_function_matches.setText(
                    "Block Matches for Function: 0x%x -- %d families, %d samples, %d functions."
                    % (
                        self.parent.current_function,
                        len(set_families),
                        len(set_samples),
                        len(set_all_functions),
                    )
                )
        else:
            self.label_current_function_matches.setText(
                "No Block Matches for Function: 0x%x" % self.parent.current_function
            )
            if self.parent.current_block:
                self.label_block_matches.setText(
                    "No Block Matches for: 0x%x" % self.parent.current_block
                )
        self._last_block_matches = block_matches_by_offset
        # populate tables with data
        self.populateBlockSummaryTable(block_matches_by_offset)
        self.populateBlockMatchTable(block_matches_by_offset, self.last_viewed_block)

    def generateSummaryTableCellItem(self, column_type, block_offset, block_entry):
        tmp_item = None
        if column_type == McritTableColumn.OFFSET:
            tmp_item = self.cc.QTableWidgetItem("0x%x" % block_offset)
        elif column_type == McritTableColumn.PIC_BLOCK_HASH:
            tmp_item = self.cc.QTableWidgetItem("0x%x" % block_entry["picblockhash"]["hash"])
        elif column_type == McritTableColumn.SIZE:
            tmp_item = self.NumberQTableWidgetItem("%d" % block_entry["picblockhash"]["size"])
        elif column_type == McritTableColumn.FAMILIES:
            tmp_item = self.NumberQTableWidgetItem("%d" % block_entry["summary"]["families"])
        elif column_type == McritTableColumn.SAMPLES:
            tmp_item = self.NumberQTableWidgetItem("%d" % block_entry["summary"]["samples"])
        elif column_type == McritTableColumn.FUNCTIONS:
            tmp_item = self.NumberQTableWidgetItem("%d" % block_entry["summary"]["functions"])
        elif column_type == McritTableColumn.IS_LIBRARY:
            tmp_item = self.cc.QTableWidgetItem(
                "YES" if block_entry["has_library_matches"] else "NO"
            )
        return tmp_item

    def populateBlockSummaryTable(self, block_matches):
        """
        Populate the function match table with all matches for the selected function_id
        """
        self.table_block_summary.setSortingEnabled(False)
        self.function_matches_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.BLOCK_SUMMARY_TABLE_COLUMNS
        ]
        self.table_block_summary.clear()
        self.table_block_summary.setColumnCount(len(self.function_matches_header_labels))
        self.table_block_summary.setHorizontalHeaderLabels(self.function_matches_header_labels)
        # Identify number of table entries and prepare addresses to display
        self.table_block_summary.setRowCount(len(block_matches))
        self.table_block_summary.resizeRowToContents(0)
        row = 0
        for block_offset, block_entry in sorted(block_matches.items(), key=lambda x: x[0]):
            for column, column_name in enumerate(self.function_matches_header_labels):
                column_type = self.parent.config.BLOCK_SUMMARY_TABLE_COLUMNS[column]
                tmp_item = self.generateSummaryTableCellItem(column_type, block_offset, block_entry)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                # Set background color and font color
                if block_entry["summary"]["families"] > 0:
                    row_color = self.scp.frequencyToColor(
                        block_entry["summary"]["families"], opacity=1
                    )
                    tmp_item.setBackground(QColor(row_color[0], row_color[1], row_color[2]))
                    text_color = self.scp.textOnTintColor()
                    if text_color is not None:
                        tmp_item.setForeground(QColor(text_color[0], text_color[1], text_color[2]))
                self.table_block_summary.setItem(row, column, tmp_item)
            # self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_block_summary.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_block_summary.resizeColumnsToContents()
        self.table_block_summary.setSortingEnabled(True)
        header = self.table_block_summary.horizontalHeader()
        header.setStretchLastSection(True)

    def generateMatchTableCellItem(self, column_type, match_entry):
        tmp_item = None
        if column_type == McritTableColumn.SHA256:
            sample_info = self._get_sample_entry(match_entry[1])
            sample_sha256 = self._get_entry_field(sample_info, "sha256")
            tmp_item = self.cc.QTableWidgetItem(sample_sha256[:8] if sample_sha256 else "unknown")
        elif column_type == McritTableColumn.OFFSET:
            tmp_item = self.cc.QTableWidgetItem("0x%x" % match_entry[3])
        elif column_type == McritTableColumn.FAMILY_NAME:
            family_info = self._get_family_entry(match_entry[0])
            family_name = self._get_entry_field(family_info, "family_name")
            tmp_item = self.cc.QTableWidgetItem(family_name if family_name else "unknown")
        elif column_type == McritTableColumn.FAMILY_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % match_entry[0])
        elif column_type == McritTableColumn.SAMPLE_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % match_entry[1])
        elif column_type == McritTableColumn.FUNCTION_ID:
            tmp_item = self.NumberQTableWidgetItem("%d" % match_entry[2])
        return tmp_item

    def populateBlockMatchTable(self, block_matches, block_offset):
        """
        Populate the function name table with all names for the matches we found
        """
        if block_offset is not None:
            self.label_block_matches.setText("Block Matches for: 0x%x" % block_offset)
        self.table_block_matches.setSortingEnabled(False)
        self.function_matches_header_labels = [
            McritTableColumn.MAP_COLUMN_TO_HEADER_STRING[col]
            for col in self.parent.config.BLOCK_MATCHES_TABLE_COLUMNS
        ]
        self.table_block_matches.clear()
        self.table_block_matches.setColumnCount(len(self.function_matches_header_labels))
        self.table_block_matches.setHorizontalHeaderLabels(self.function_matches_header_labels)
        self.table_block_matches.setRowCount(0)
        if block_offset not in block_matches:
            return
        self.table_block_matches.setRowCount(len(block_matches[block_offset]["matches"]))
        self.table_block_matches.resizeRowToContents(0)

        preselect_row = 0
        row = 0
        for match_entry in sorted(
            block_matches[block_offset]["matches"], key=lambda x: (x[0], x[1], x[2])
        ):
            for column, column_name in enumerate(self.function_matches_header_labels):
                if block_offset == match_entry[3]:
                    preselect_row = row
                column_type = self.parent.config.BLOCK_MATCHES_TABLE_COLUMNS[column]
                tmp_item = self.generateMatchTableCellItem(column_type, match_entry)
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_block_matches.setItem(row, column, tmp_item)
            # self.table_function_matches.resizeRowToContents(row)
            row += 1
        self.table_block_matches.selectRow(preselect_row)
        self.table_block_matches.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_block_matches.resizeColumnsToContents()
        self.table_block_matches.setSortingEnabled(True)
        header = self.table_block_matches.horizontalHeader()
        header.setStretchLastSection(True)

    def _onTableBlockSummaryClicked(self, mi):
        """
        Use the row with that was clicked to show block matches corresponding to the current block
        """
        clicked_block_address = None
        for index, column_type in enumerate(self.parent.config.BLOCK_SUMMARY_TABLE_COLUMNS):
            if column_type == McritTableColumn.OFFSET:
                clicked_block_address = self.table_block_summary.item(mi.row(), index).text()
        # print("clicked_block_address", clicked_block_address)
        if clicked_block_address is not None:
            self.parent.current_block = int(clicked_block_address, 16)
            self.populateBlockMatchTable(self._last_block_matches, self.parent.current_block)

    def _onTableBlockSummaryDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to jump to that block
        """
        offset_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.OFFSET, self.parent.config.BLOCK_SUMMARY_TABLE_COLUMNS
        )
        if offset_column_index is not None and mi.column() == offset_column_index:
            clicked_block_address = self.table_block_summary.item(
                mi.row(), offset_column_index
            ).text()
            # print("double clicked_block_address", clicked_block_address)
            self.cc.backend.jump_to(int(clicked_block_address, 16))
            self.parent.current_block = int(clicked_block_address, 16)
            self.populateBlockMatchTable(self._last_block_matches, self.parent.current_block)

    def _onTableBlockMatchesDoubleClicked(self, mi):
        """
        Use the row with that was double clicked to show the matched remote function in a graph viewer
        """
        block_offset_b = None
        function_id_b = None
        for index, column_type in enumerate(self.parent.config.BLOCK_MATCHES_TABLE_COLUMNS):
            if column_type == McritTableColumn.OFFSET:
                block_offset_b = int(self.table_block_matches.item(mi.row(), index).text(), 16)
            elif column_type == McritTableColumn.FUNCTION_ID:
                function_id_b = int(self.table_block_matches.item(mi.row(), index).text())
        # print("double clicked row for function_id", function_id_b)
        if block_offset_b is not None and function_id_b is not None:
            block_matches = self._last_block_matches
            # the remote function arrives later; the tint is for the function and block clicked
            function_offset_a = self.parent.current_function
            block_a = self.parent.current_block
            self.parent.local_widget.updateActivityInfo(
                f"Fetching function {function_id_b} for the graph viewer..."
            )

            def show(remote):
                if remote is None:
                    return
                function_entry_b, smda_function_b, sample_entry_b = remote
                matched_color = packRgb(self.scp.roleColor(ThemeRole.CYAN, (0xC0, 0xF4, 0xFF)))
                current_color = packRgb(self.scp.roleColor(ThemeRole.CURRENT, (0x00, 0xDD, 0xFF)))
                coloring = {}
                for offset, data in block_matches.items():
                    for match in data["matches"]:
                        if match[2] == function_entry_b.function_id:
                            coloring[match[3]] = matched_color
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

            self.cc.backend.run_request(
                "MCRIT: fetching remote function %d" % function_id_b,
                lambda: self.parent.mcrit_interface.queryRemoteFunction(function_id_b),
                show,
            )

    def _colorLocalBlocks(
        self, block_matches, function_id_b, function_offset_a, block_a, matched_color, current_color
    ):
        """Tint the local blocks that matched the remote function in the disassembler's own views."""
        smda_function_a = self.parent.local_smda_report.getFunction(function_offset_a)
        if smda_function_a is None:
            return
        local_coloring = {}
        for offset, data in block_matches.items():
            if any(match[2] == function_id_b for match in data["matches"]):
                local_coloring[offset] = matched_color
        if block_a in local_coloring:
            local_coloring[block_a] = current_color
        self.cc.backend.show_local_match_coloring(smda_function_a, local_coloring)

    def _onTableBlockMatchesRightClicked(self, position):
        sha256_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SHA256, self.parent.config.BLOCK_MATCHES_TABLE_COLUMNS
        )
        sample_id_column_index = McritTableColumn.columnTypeToIndex(
            McritTableColumn.SAMPLE_ID, self.parent.config.BLOCK_MATCHES_TABLE_COLUMNS
        )
        if (
            sha256_column_index is not None
            and self.table_block_matches.currentColumn() == sha256_column_index
        ):
            if sample_id_column_index is None:
                # TODO possibly can reconstruct clicked row from matching data, but let's keep it simple for now
                print("Need a column with sample IDs to copy SHA256 to clipboard.")
            # copy to clipboard
            sample_id_item = self.table_block_matches.item(
                self.table_block_matches.currentRow(), sample_id_column_index
            )
            if sample_id_item is None:
                return
            sample_id = sample_id_item.text()
            sample_info = self._get_sample_entry(int(sample_id))
            sample_sha256 = self._get_entry_field(sample_info, "sha256")
            if sample_sha256:
                self.parent.copyStringToClipboard(sample_sha256)
