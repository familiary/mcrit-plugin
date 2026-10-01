import mcrit_plugin.ui_qt.QtShim as QtShim
from mcrit_plugin.ui_qt.widgets.NumberQTableWidgetItem import NumberQTableWidgetItem

QMainWindow = QtShim.get_QMainWindow()


class SampleInfoWidget(QMainWindow):
    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading SampleInfoWidget")
        self.parent = parent
        self.name = "Sample Match Summary"
        self.last_family_selected = None
        self._matching_data = None
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "puzzle.png")
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.cb_filter_library = self.cc.QCheckBox("Filter out Library Matches")
        self.cb_filter_library.setChecked(False)
        self.cb_filter_library.stateChanged.connect(self.populateBestMatchTable)
        # horizontal line
        self.hline = self.cc.QFrame()
        self.hline.setFrameShape(self.cc.QFrameHLine)
        self.hline.setFrameShadow(self.cc.QFrameShadow.Sunken)
        # upper table
        self.label_best_matches = self.cc.QLabel("Best Matches per Family")
        self.table_best_family_matches = self.cc.QTableWidget()
        self.table_best_family_matches.selectionModel().selectionChanged.connect(
            self._onTableBestFamilySelectionChanged
        )
        self.table_best_family_matches.doubleClicked.connect(self._onTableBestFamilyDoubleClicked)
        # lower table
        self.label_sample_matches_family = self.cc.QLabel(
            "All Sample Matches within Family: <family_name>"
        )
        self.table_family_sample_matches = self.cc.QTableWidget()
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
        sample_info_layout.addWidget(self.cb_filter_library)
        sample_info_layout.addWidget(self.hline)
        sample_info_layout.addWidget(self.label_best_matches)
        sample_info_layout.addWidget(self.table_best_family_matches)
        sample_info_layout.addWidget(self.label_sample_matches_family)
        sample_info_layout.addWidget(self.table_family_sample_matches)
        self.central_widget.setLayout(sample_info_layout)

    ################################################################################
    # Rendering and state keeping
    ################################################################################

    def update(self):
        self.populateBestMatchTable()
        self.updateFunctionsLabel()

    def updateFunctionsLabel(self):
        pass

    def _updateLabelBestMatches(self, text):
        self.label_best_matches.setText(text)

    def _updateLabelSampleMatches(self, text):
        self.label_sample_matches_family.setText(text)

    def _aggregatedMatchingData(self):
        match_report = self.parent.getMatchingReport()
        if not match_report:
            return {}
        sample_matches = match_report.filtered_sample_matches
        if self.cb_filter_library.isChecked():
            sample_matches = [entry for entry in sample_matches if not entry.is_library]
        return {
            sample_match.sample_id: {
                "family": sample_match.family,
                "version": sample_match.version,
                "sha256": sample_match.sha256,
                "filename": sample_match.filename,
                "sample_id": sample_match.sample_id,
                "minhash_matches": sample_match.matched_functions_minhash,
                "pichash_matches": sample_match.matched_functions_pichash,
                "combined_matches": sample_match.matched_functions_combined,
                "library_matches": sample_match.matched_functions_library,
                "bytescore": sample_match.matched_bytes_unweighted,
                "bytescore_adjusted": sample_match.matched_bytes_score_weighted,
                "percent": sample_match.matched_percent_unweighted,
                "percent_adjusted": sample_match.matched_percent_score_weighted,
            }
            for sample_match in sample_matches
        }

    def populateBestMatchTable(self, *_args):
        """
        Populate the function table with information from the last scan of I{SemanticIdentifier}.
        """
        header_view = self._QtShim.get_QHeaderView()
        qt = self._QtShim.get_Qt()

        self._matching_data = self._aggregatedMatchingData()
        matching_data = self._matching_data
        self.table_best_family_matches.setSortingEnabled(False)
        self.best_family_matches_header_labels = [
            "ID",
            "Samples",
            "Family",
            "Version",
            "PicHash",
            "MinHash",
            "Combined",
            "Library",
            "Score",
            "Percent",
        ]
        self.table_best_family_matches.clear()
        self.table_best_family_matches.setColumnCount(len(self.best_family_matches_header_labels))
        self.table_best_family_matches.setHorizontalHeaderLabels(
            self.best_family_matches_header_labels
        )
        # Identify number of table entries and prepare addresses to display
        families_to_samples = {}
        for sample_id, sample_entry in matching_data.items():
            if sample_entry["family"] not in families_to_samples:
                families_to_samples[sample_entry["family"]] = 0
            families_to_samples[sample_entry["family"]] += 1
        self._updateLabelBestMatches("Best Matches per Family (%d)" % len(families_to_samples))
        self.table_best_family_matches.setRowCount(len(families_to_samples))
        self.table_best_family_matches.resizeRowToContents(0)
        row = 0
        families_covered = set([])
        best_family = ""
        for sample_id, sample_entry in sorted(
            matching_data.items(), key=lambda x: x[1]["bytescore"], reverse=True
        ):
            if sample_entry["family"] in families_covered:
                continue
            if not best_family:
                best_family = sample_entry["family"]
            families_covered.add(sample_entry["family"])
            for column, column_name in enumerate(self.best_family_matches_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_id)
                elif column == 1:
                    tmp_item = self.NumberQTableWidgetItem(
                        "%d" % families_to_samples[sample_entry["family"]]
                    )
                elif column == 2:
                    tmp_item = self.cc.QTableWidgetItem(sample_entry["family"])
                elif column == 3:
                    tmp_item = self.cc.QTableWidgetItem(sample_entry["version"])
                elif column == 4:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["pichash_matches"])
                elif column == 5:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["minhash_matches"])
                elif column == 6:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["combined_matches"])
                elif column == 7:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["library_matches"])
                elif column == 8:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["bytescore"])
                elif column == 9:
                    tmp_item = self.NumberQTableWidgetItem("%5.2f" % sample_entry["percent"])
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                tmp_item.setTextAlignment(qt.AlignHCenter)
                self.table_best_family_matches.setItem(row, column, tmp_item)
            self.table_best_family_matches.resizeRowToContents(row)
            row += 1
        self.table_best_family_matches.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_best_family_matches.resizeColumnsToContents()
        self.table_best_family_matches.setSortingEnabled(True)
        header = self.table_best_family_matches.horizontalHeader()
        for header_id in range(0, len(self.best_family_matches_header_labels), 1):
            header.setSectionResizeMode(header_id, header_view.Stretch)
        # propagate family selection to family match table
        # a family picked for an earlier result may have no matches in this one
        if self.last_family_selected in families_to_samples:
            selected_family = self.last_family_selected
        else:
            selected_family = best_family
        self._updateLabelSampleMatches("All Sample Matches within Family: %s" % selected_family)
        self.populateFamilyMatchTable(selected_family)

    def populateFamilyMatchTable(self, family):
        """
        Populate the function table with information from the last scan of I{SemanticIdentifier}.
        """
        if self._matching_data is None:
            self._matching_data = self._aggregatedMatchingData()
        matching_data = self._matching_data
        self.table_family_sample_matches.setSortingEnabled(False)
        self.family_sample_matches_header_labels = [
            "ID",
            "SHA256",
            "Version",
            "PicHash",
            "MinHash",
            "Combined",
            "Library",
            "Score",
            "Percent",
        ]
        self.table_family_sample_matches.clear()
        self.table_family_sample_matches.setColumnCount(
            len(self.family_sample_matches_header_labels)
        )
        self.table_family_sample_matches.setHorizontalHeaderLabels(
            self.family_sample_matches_header_labels
        )
        # Identify number of table entries and prepare addresses to display
        num_entries = len(
            set([v["sample_id"] for k, v in matching_data.items() if v["family"] == family])
        )
        self._updateLabelSampleMatches(
            'All Sample Matches within Family: "%s" (%d)' % (family, num_entries)
        )
        self.table_family_sample_matches.setRowCount(num_entries)
        self.table_family_sample_matches.resizeRowToContents(0)
        row = 0
        for sample_id, sample_entry in sorted(
            matching_data.items(), key=lambda x: x[1]["bytescore"], reverse=True
        ):
            if sample_entry["family"] != family:
                continue
            for column, column_name in enumerate(self.family_sample_matches_header_labels):
                tmp_item = None
                if column == 0:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_id)
                elif column == 1:
                    tmp_item = self.cc.QTableWidgetItem("%s" % sample_entry["sha256"])
                elif column == 2:
                    tmp_item = self.cc.QTableWidgetItem(sample_entry["version"])
                elif column == 3:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["pichash_matches"])
                elif column == 4:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["minhash_matches"])
                elif column == 5:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["combined_matches"])
                elif column == 6:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["library_matches"])
                elif column == 7:
                    tmp_item = self.NumberQTableWidgetItem("%d" % sample_entry["bytescore"])
                elif column == 8:
                    tmp_item = self.NumberQTableWidgetItem("%5.2f" % sample_entry["percent"])
                tmp_item.setFlags(tmp_item.flags() & ~self.cc.QtCore.Qt.ItemIsEditable)
                self.table_family_sample_matches.setItem(row, column, tmp_item)
            self.table_family_sample_matches.resizeRowToContents(row)
            row += 1
        self.table_family_sample_matches.setSelectionMode(self.cc.QAbstractItemView.SingleSelection)
        self.table_family_sample_matches.resizeColumnsToContents()
        self.table_family_sample_matches.setSortingEnabled(True)
        header_view = self._QtShim.get_QHeaderView()
        header = self.table_family_sample_matches.horizontalHeader()
        for header_id in range(0, len(self.family_sample_matches_header_labels), 1):
            header.setSectionResizeMode(header_id, header_view.Stretch)

    ################################################################################
    # Buttons and Actions
    ################################################################################

    def _onTableBestFamilySelectionChanged(self, selected, deselected):
        if not self.table_best_family_matches.selectedItems():
            return
        selected_row = self.table_best_family_matches.selectedItems()[0].row()
        family = self.table_best_family_matches.item(selected_row, 2).text()
        self.last_family_selected = family
        self.populateFamilyMatchTable(family)

    def _onTableBestFamilyDoubleClicked(self, mi):
        """
        TODO: open a popup with the detailed sample info
        """
        pass
