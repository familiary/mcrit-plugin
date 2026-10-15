import mcrit_plugin.ui_qt.QtShim as QtShim
from mcrit_plugin.ui_qt.widgets.MatchTable import MatchRow, MatchTableView

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
        self.table_best_family_matches = MatchTableView()
        self.table_best_family_matches.selectionModel().selectionChanged.connect(
            self._onTableBestFamilySelectionChanged
        )
        self.table_best_family_matches.doubleClicked.connect(self._onTableBestFamilyDoubleClicked)
        # lower table
        self.label_sample_matches_family = self.cc.QLabel(
            "All Sample Matches within Family: <family_name>"
        )
        self.table_family_sample_matches = MatchTableView()
        # static links to objects to help IDA
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
        """Fill the upper table with the best matching sample of each family."""
        self._matching_data = self._aggregatedMatchingData()
        matching_data = self._matching_data
        families_to_samples = {}
        for sample_entry in matching_data.values():
            family = sample_entry["family"] or ""
            families_to_samples[family] = families_to_samples.get(family, 0) + 1
        self._updateLabelBestMatches("Best Matches per Family (%d)" % len(families_to_samples))
        rows = []
        families_covered = set()
        for sample_id, sample_entry in sorted(
            matching_data.items(), key=lambda x: x[1]["bytescore"], reverse=True
        ):
            family = sample_entry["family"] or ""
            if family in families_covered:
                continue
            families_covered.add(family)
            cells = [
                (sample_id, sample_id),
                (families_to_samples[family], families_to_samples[family]),
                (family, family),
                (sample_entry["version"] or "", sample_entry["version"] or ""),
            ] + self._scoreCells(sample_entry)
            rows.append(self._row(len(rows), family, cells))
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
        # rows are in byte score order until the model applies the user's sort to them
        best_family = rows[0].entry if rows else ""
        self._fill(
            self.table_best_family_matches,
            self.best_family_matches_header_labels,
            rows,
            alignment=self._QtShim.get_Qt().AlignHCenter,
        )
        # propagate family selection to family match table
        # a family picked for an earlier result may have no matches in this one
        if self.last_family_selected in families_to_samples:
            selected_family = self.last_family_selected
        else:
            selected_family = best_family
        self._updateLabelSampleMatches("All Sample Matches within Family: %s" % selected_family)
        self.populateFamilyMatchTable(selected_family)

    def populateFamilyMatchTable(self, family):
        """Fill the lower table with the matched samples of one family."""
        if self._matching_data is None:
            self._matching_data = self._aggregatedMatchingData()
        rows = []
        for sample_id, sample_entry in sorted(
            self._matching_data.items(), key=lambda x: x[1]["bytescore"], reverse=True
        ):
            if (sample_entry["family"] or "") != family:
                continue
            cells = [
                (sample_id, sample_id),
                (sample_entry["sha256"] or "", sample_entry["sha256"] or ""),
                (sample_entry["version"] or "", sample_entry["version"] or ""),
            ] + self._scoreCells(sample_entry)
            rows.append(self._row(len(rows), sample_id, cells))
        self._updateLabelSampleMatches(
            'All Sample Matches within Family: "%s" (%d)' % (family, len(rows))
        )
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
        self._fill(self.table_family_sample_matches, self.family_sample_matches_header_labels, rows)

    @staticmethod
    def _scoreCells(sample_entry):
        """The match counts, byte score and percentage of a sample, as (value, sort value)."""
        cells = [
            (sample_entry[key], sample_entry[key])
            for key in (
                "pichash_matches",
                "minhash_matches",
                "combined_matches",
                "library_matches",
                "bytescore",
            )
        ]
        return cells + [("%5.2f" % sample_entry["percent"], sample_entry["percent"])]

    @staticmethod
    def _row(source_row, entry, cells):
        return MatchRow(
            source_row,
            entry,
            [value if isinstance(value, str) else "%d" % value for value, _key in cells],
            [key for _value, key in cells],
        )

    def _fill(self, table, headers, rows, alignment=None):
        table.table_model.reset(headers, rows, alignment=alignment)
        # every column stretches, so nothing is sized to its contents
        header = table.horizontalHeader()
        for header_id in range(len(headers)):
            header.setSectionResizeMode(header_id, self._QtShim.get_QHeaderView().Stretch)

    ################################################################################
    # Buttons and Actions
    ################################################################################

    def _onTableBestFamilySelectionChanged(self, selected, deselected):
        indexes = self.table_best_family_matches.selectionModel().selectedIndexes()
        if not indexes:
            return
        family = self.table_best_family_matches.table_model.entryAt(indexes[0].row())
        self.last_family_selected = family
        self.populateFamilyMatchTable(family)

    def _onTableBestFamilyDoubleClicked(self, mi):
        """
        TODO: open a popup with the detailed sample info
        """
        pass
