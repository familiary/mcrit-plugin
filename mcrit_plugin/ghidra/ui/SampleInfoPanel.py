"""Sample Match Summary tab: best matching sample per family and all samples of one family. Ports
the Qt SampleInfoWidget."""

from mcrit_plugin.core.presentation import aggregate_sample_matches
from mcrit_plugin.ghidra.ui.components import Label, checkbox, separator, stack
from mcrit_plugin.ghidra.ui.table import MatchRow, MatchTableView

BEST_HEADERS = [
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
FAMILY_HEADERS = [
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


def _score_cells(entry):
    cells = [
        (entry[key], entry[key])
        for key in (
            "pichash_matches",
            "minhash_matches",
            "combined_matches",
            "library_matches",
            "bytescore",
        )
    ]
    return cells + [("%5.2f" % entry["percent"], entry["percent"])]


def _row(source_row, entry, cells):
    return MatchRow(
        source_row,
        entry,
        [value if isinstance(value, str) else "%d" % value for value, _ in cells],
        [key for _, key in cells],
    )


class SampleInfoPanel:
    def __init__(self, parent):
        self.parent = parent
        self.name = "Sample Match Summary"
        self.icon_file = "puzzle.png"
        self.last_family_selected = None
        self._matching_data = None
        self._populating = False
        self.cb_filter_library = checkbox(
            "Filter out Library Matches", False, on_click=self.populateBestMatchTable
        )
        self.label_best_matches = Label("Best Matches per Family")
        self.table_best_family_matches = MatchTableView(centered=True)
        self.table_best_family_matches.on_selection(self._onBestFamilySelected)
        self.label_sample_matches_family = Label("All Sample Matches within Family: <family_name>")
        self.table_family_sample_matches = MatchTableView()
        self.component = stack(
            self.cb_filter_library,
            separator(),
            self.label_best_matches.component,
            self.table_best_family_matches.component,
            self.label_sample_matches_family.component,
            self.table_family_sample_matches.component,
            fill=(
                self.table_best_family_matches.component,
                self.table_family_sample_matches.component,
            ),
        )

    def update(self):
        self.populateBestMatchTable()

    def populateBestMatchTable(self):
        self._matching_data = aggregate_sample_matches(
            self.parent.getMatchingReport(), self.cb_filter_library.isSelected()
        )
        samples_per_family = {}
        for entry in self._matching_data.values():
            family = entry["family"] or ""
            samples_per_family[family] = samples_per_family.get(family, 0) + 1
        self.label_best_matches.setText("Best Matches per Family (%d)" % len(samples_per_family))
        rows = []
        covered = set()
        for sample_id, entry in sorted(
            self._matching_data.items(), key=lambda x: x[1]["bytescore"], reverse=True
        ):
            family = entry["family"] or ""
            if family in covered:
                continue
            covered.add(family)
            cells = [
                (sample_id, sample_id),
                (samples_per_family[family], samples_per_family[family]),
                (family, family),
                (entry["version"] or "", entry["version"] or ""),
            ] + _score_cells(entry)
            rows.append(_row(len(rows), family, cells))
        best_family = rows[0].entry if rows else ""
        # filling the table fires a selection change; the family table is filled below instead
        self._populating = True
        try:
            self.table_best_family_matches.reset(BEST_HEADERS, rows)
        finally:
            self._populating = False
        if self.last_family_selected in samples_per_family:
            selected_family = self.last_family_selected
        else:
            selected_family = best_family
        self.populateFamilyMatchTable(selected_family)

    def populateFamilyMatchTable(self, family):
        if self._matching_data is None:
            self._matching_data = aggregate_sample_matches(
                self.parent.getMatchingReport(), self.cb_filter_library.isSelected()
            )
        rows = []
        for sample_id, entry in sorted(
            self._matching_data.items(), key=lambda x: x[1]["bytescore"], reverse=True
        ):
            if (entry["family"] or "") != family:
                continue
            cells = [
                (sample_id, sample_id),
                (entry["sha256"] or "", entry["sha256"] or ""),
                (entry["version"] or "", entry["version"] or ""),
            ] + _score_cells(entry)
            rows.append(_row(len(rows), sample_id, cells))
        self.label_sample_matches_family.setText(
            'All Sample Matches within Family: "%s" (%d)' % (family, len(rows))
        )
        self.table_family_sample_matches.reset(FAMILY_HEADERS, rows)

    def _onBestFamilySelected(self, view_row):
        if self._populating or view_row < 0:
            return
        family = self.table_best_family_matches.entryAt(view_row)
        if family is None:
            return
        self.last_family_selected = family
        self.populateFamilyMatchTable(family)
