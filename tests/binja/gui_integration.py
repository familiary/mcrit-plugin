"""Binary Ninja GUI integration test, installed as startup.py of a throwaway user directory.

scripts/binja/run_gui_integration.py prepares that directory and launches Binary Ninja on the query
sample. Checks run as chained event-loop callbacks so the UI thread is never blocked; the
outcome is written to gui-integration.log in the user directory.

One helper per widget exercises every interactive element of that widget and asserts its effect.
"""

import os
import threading
import time
import traceback

import binaryninja
from binaryninjaui import (
    UIAction,
    UIActionContext,
    UIActionHandler,
    UIContext,
    UIContextNotification,
)
from PySide6.QtCore import QPoint, QTimer
from PySide6.QtWidgets import QApplication

# startup.py is executed without __file__
LOG = os.path.join(binaryninja.user_directory(), "gui-integration.log")
TIMEOUT = int(os.environ.get("MCRIT_BN_INTEGRATION_TIMEOUT", "120"))
# the sidebar coalesces cursor moves for 150 ms before it queries
NAVIGATION_SETTLE_MS = 400


def log(message):
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(f"{time.strftime('%H:%M:%S')} {message}\n")


class IntegrationTest:
    def __init__(self, context, bv):
        self.context = context
        self.bv = bv
        self.widget = None
        self.session = None
        self.job_id = None
        self.target = None
        self.second_target = None
        self.graph_calls = []

    ################################################################################
    # harness
    ################################################################################

    def finish(self, ok, message=""):
        log("MCRIT_BN_INTEGRATION_OK" if ok else f"MCRIT_BN_INTEGRATION_FAILURE: {message}")
        if os.environ.get("MCRIT_BN_INTEGRATION_KEEP_OPEN") != "1":
            QTimer.singleShot(1000, QApplication.instance().quit)

    def step(self, func, delay=0):
        def run():
            try:
                func()
            except Exception as exc:
                self.finish(False, f"{exc}\n{traceback.format_exc()}")

        QTimer.singleShot(delay, run)

    def wait(self, predicate, then, what):
        deadline = time.time() + TIMEOUT

        def poll():
            if predicate():
                log(f"PASS {what}")
                then()
            elif time.time() > deadline:
                raise AssertionError(f"timed out: {what}")
            else:
                self.step(poll, 250)

        self.step(poll)

    def sequence(self, steps, then, delay=10):
        """Run synchronous steps one per event-loop turn so the UI can repaint between them."""
        pending = list(steps)

        def run_next():
            if not pending:
                then()
                return
            pending.pop(0)()
            self.step(run_next, delay)

        self.step(run_next)

    def check(self, condition, what):
        if not condition:
            raise AssertionError(what)
        log(f"PASS {what}")

    def double_click(self, table, row, column):
        table.setCurrentCell(row, column)
        table.doubleClicked.emit(table.model().index(row, column))

    def single_click(self, table, row, column):
        table.setCurrentCell(row, column)
        table.clicked.emit(table.model().index(row, column))

    def count_graphs(self):
        """Wrap the backend's graph viewer once so every widget's graph action is observable."""
        backend = self.session.cc.backend
        if getattr(backend, "_integration_graph_hook", False):
            return
        original = backend.show_function_graph

        def counting(*args, **kwargs):
            self.graph_calls.append(args[2])
            return original(*args, **kwargs)

        backend.show_function_graph = counting
        backend._integration_graph_hook = True

    def action_context(self):
        frame = self.widget.backend.view_frame
        view = frame.getCurrentViewInterface() if frame is not None else None
        for source in (frame, view):
            getter = getattr(source, "actionContext", None)
            if getter is None:
                continue
            context = getter()
            if context is not None and context.binaryView is not None:
                return context
        context = UIActionContext()
        context.context = self.context
        context.binaryView = self.bv
        context.view = view
        return context

    ################################################################################
    # setup, conversion, upload, matching
    ################################################################################

    def start(self):
        from mcrit_plugin.binja import McritSidebar

        self.sidebar_module = McritSidebar
        self.check(
            binaryninja.Settings().contains("mcrit.mcrit_server"), "MCRIT settings registered"
        )
        for name, _handler, _enabled in McritSidebar._ACTIONS:
            self.check(UIAction.isActionRegistered(name), f"action registered: {name}")
        self.check(
            UIAction.isActionRegistered("MCRIT\\Clear Stored API Token"),
            "action registered: MCRIT\\Clear Stored API Token",
        )
        # the window may not be active (no activeContext) when started from a script
        self.context.sidebar().activate(McritSidebar.SIDEBAR_NAME)
        self.wait(self.find_widget, self.convert, "MCRIT sidebar created for the binary view")

    def find_widget(self):
        # one sidebar widget per view type shares the file's session_id; actions dispatch on both
        for widget in self.sidebar_module._SIDEBAR_WIDGETS:
            if (
                widget.backend.bv.file.session_id == self.bv.file.session_id
                and widget.backend.bv.view_type == self.bv.view_type
            ):
                self.widget = widget
                self.session = widget.session
                return True
        return False

    def convert(self):
        main_widget = self.session.main_widget
        expected_sha256 = os.environ["MCRIT_BN_INTEGRATION_SHA256"]
        self.check(
            self.session.cc.backend.get_input_sha256() == expected_sha256,
            "input sha256 matches file",
        )
        self.count_graphs()
        for action, name in (
            (main_widget.uploadSmdaAction, "Upload"),
            (main_widget.getMatchResultAction, "Fetch Matching Result"),
            (main_widget.exportSmdaAction, "Export"),
            (main_widget.buildYaraStringAction, "Build YARA String"),
        ):
            self.check(not action.isEnabled(), f"toolbar {name} disabled before conversion")
        for widget, label in (
            (self.session.block_match_widget, "Block Scope"),
            (self.session.function_match_widget, "Function Scope"),
        ):
            self.check(
                not widget.b_query_single.isEnabled()
                and not widget.cb_filter_library.isEnabled()
                and not widget.cb_activate_live_tracking.isEnabled(),
                f"{label} controls disabled before conversion",
            )

        class InfoDialog(main_widget.SmdaInfoDialog):
            def exec_(dialog):
                dialog.edit_family.setText("binja-integration")
                dialog.edit_version.setText("fixture-query")
                dialog._cb_is_library.setChecked(False)
                dialog.ok_button.click()
                return 1

        main_widget.SmdaInfoDialog = InfoDialog
        main_widget.parseSmdaAction.trigger()
        self.wait(
            lambda: self.session.local_smda_report is not None,
            self.upload,
            "Convert action produced an SMDA report in the background",
        )

    def upload(self):
        main_widget = self.session.main_widget
        report = self.session.local_smda_report
        self.check(len(list(report.getFunctions())) > 0, "SMDA report contains functions")
        self.check(
            report.smda_version.startswith("MCRIT4BinaryNinja"),
            "report records the Binary Ninja producer",
        )
        self.check(
            report.family
            == (
                self.session.remote_sample_entry.family
                if self.session.remote_sample_entry is not None
                else "binja-integration"
            ),
            "the report carries the family from the dialog, or from the known remote sample",
        )
        self.check(
            main_widget.uploadSmdaAction.isEnabled()
            and main_widget.exportSmdaAction.isEnabled()
            and main_widget.buildYaraStringAction.isEnabled(),
            "Upload/Export/YARA actions enabled after conversion",
        )
        self.check(
            main_widget.getMatchResultAction.isEnabled()
            == (self.session.remote_sample_entry is not None),
            "Fetch Matching Result is enabled exactly when the sample is already on the server",
        )
        for widget, label in (
            (self.session.block_match_widget, "Block Scope"),
            (self.session.function_match_widget, "Function Scope"),
        ):
            self.check(
                widget.b_query_single.isEnabled()
                and widget.cb_filter_library.isEnabled()
                and widget.cb_activate_live_tracking.isEnabled(),
                f"{label} controls enabled after conversion",
            )
        main_widget.uploadSmdaAction.trigger()
        client = self.session.mcrit_interface.mcrit_client
        self.wait(
            lambda: (
                self.session.remote_sample_id is not None
                and bool(client.getFunctionsBySampleId(self.session.remote_sample_id))
            ),
            self.request_matching,
            "upload finished and the server indexed the functions",
        )

    def request_matching(self):
        interface = self.session.mcrit_interface
        client = interface.mcrit_client
        main_widget = self.session.main_widget
        self.check(
            main_widget.getMatchResultAction.isEnabled(),
            "Fetch Matching Result enabled after upload",
        )
        interface.querySampleSha256(self.session.local_smda_report.sha256)
        interface.queryAllFamilyEntries()
        interface.queryAllSampleEntries()
        self.check(self.session.remote_sample_entry is not None, "uploaded sample found by sha256")

        job_ids = []
        original_request = client.requestMatchesForSample

        def capture_request(*args, **kwargs):
            job_id = original_request(*args, **kwargs)
            job_ids.append(job_id)
            return job_id

        original_dialog = main_widget.ResultChooserDialog

        class RequestDialog(original_dialog):
            def exec_(dialog):
                dialog.create_button.click()
                return 1

        client.requestMatchesForSample = capture_request
        main_widget.ResultChooserDialog = RequestDialog
        try:
            main_widget.getMatchResultAction.trigger()
        finally:
            client.requestMatchesForSample = original_request
            main_widget.ResultChooserDialog = original_dialog
        self.check(bool(job_ids and job_ids[-1]), "Create Matching Job returned a job id")
        self.job_id = job_ids[-1]
        self.wait(
            lambda: client.getResultForJob(self.job_id) is not None,
            self.select_matching,
            "matching job finished",
        )

    def select_matching(self):
        client = self.session.mcrit_interface.mcrit_client
        main_widget = self.session.main_widget
        reference_sha256 = os.environ.get("MCRIT_BN_INTEGRATION_REFERENCE_SHA256")
        if reference_sha256:
            result = client.getResultForJob(self.job_id)
            reference = client.getSampleBySha256(reference_sha256)
            matched_samples = {
                match.get("sample_id")
                for match in (result.get("matches", {}).get("samples") or [])
                if isinstance(match, dict)
            }
            self.check(
                reference is not None and reference.sample_id in matched_samples,
                "Binary Ninja report matches the reference sample",
            )

        target_job = str(self.job_id)
        original_dialog = main_widget.ResultChooserDialog

        class SelectDialog(original_dialog):
            def exec_(dialog):
                rows = [
                    row
                    for row, info in enumerate(dialog.job_infos)
                    if str(info.job_id) == target_job
                ]
                if not rows:
                    raise AssertionError(f"matching job {target_job} was not listed")
                dialog.table_jobs.selectRow(rows[0])
                dialog.select_button.click()
                return 1

        main_widget.ResultChooserDialog = SelectDialog
        try:
            main_widget.getMatchResultAction.trigger()
        finally:
            main_widget.ResultChooserDialog = original_dialog
        self.check(
            self.session.matching_report is not None, "result chooser loaded the MatchingResult"
        )
        self.check(
            main_widget.tabs.currentWidget() is self.session.function_widget,
            "Function Overview shown with results",
        )
        self.step(self.exercise_function_overview)

    ################################################################################
    # Function Overview tab
    ################################################################################

    def exercise_function_overview(self):
        widget = self.session.function_widget
        table = widget.table_local_functions
        label_column = len(self.session.config.OVERVIEW_TABLE_COLUMNS) - 1

        def fetch_labels():
            widget.b_fetch_labels.click()
            self.check(
                table.rowCount() > 0, "Fetch labels for matches populated the Function Overview"
            )
            self.check(
                any(
                    entry.function_labels
                    for entry in (self.session.matched_function_entries or {}).values()
                ),
                "Fetch labels for matches returned labels from the server",
            )

        def filter_radios():
            baseline = table.rowCount()
            widget.rb_filter_labels.setChecked(True)
            self.check(
                table.rowCount() <= baseline, "filter 'labels' does not widen the Function Overview"
            )
            widget.rb_filter_applicable.setChecked(True)
            applicable = table.rowCount()
            widget.rb_filter_conflicted.setChecked(True)
            self.check(
                table.rowCount() <= applicable,
                "filter 'conflicted' is a subset of filter 'applicable'",
            )
            widget.rb_filter_none.setChecked(True)
            self.check(
                table.rowCount() == baseline, "filter 'none' restores the full Function Overview"
            )

        def score_spinbox():
            spinbox = widget.sb_minhash_threshold
            baseline = table.rowCount()
            spinbox.setValue(spinbox.maximum())
            self.check(
                table.rowCount() <= baseline,
                "Function Overview min-score spinbox narrows the table",
            )
            spinbox.setValue(spinbox.minimum())
            self.check(
                table.rowCount() == baseline,
                "Function Overview min-score spinbox restores the table",
            )

        def column_sorting():
            rows = table.rowCount()
            for column in range(table.columnCount()):
                table.sortByColumn(column, self.session.cc.QtCore.Qt.AscendingOrder)
                self.check(
                    table.rowCount() == rows,
                    f"Function Overview keeps all rows sorting column {column} ascending",
                )
                table.sortByColumn(column, self.session.cc.QtCore.Qt.DescendingOrder)
                self.check(
                    table.rowCount() == rows,
                    f"Function Overview keeps all rows sorting column {column} descending",
                )
            table.sortByColumn(0, self.session.cc.QtCore.Qt.AscendingOrder)
            offsets = [int(table.item(row, 0).text(), 16) for row in range(rows)]
            self.check(offsets == sorted(offsets), "Function Overview sorts offsets ascending")

        def label_dropdown():
            delegate = table.itemDelegateForColumn(label_column)
            self.check(
                hasattr(delegate, "getEditorForRow"), "Function Overview installed label dropdowns"
            )
            editor = delegate.getEditorForRow(0)
            self.check(editor is not None, "label dropdown editor exists for the first row")
            self.check(editor.count() > 1, "label dropdown offers a label and the '-|-' opt-out")
            editor.setCurrentIndex(0)
            editor.activated.emit(0)
            self.check(
                editor.hasUserMadeSelection(), "label dropdown records an explicit user selection"
            )

        def right_click_resolves():
            offset = int(table.item(0, 0).text(), 16)
            widget._handleRightClickOnRow(0, label_column)
            self.check(
                offset in widget.resolved_function_labels,
                "right click on a label dropdown marks the function resolved",
            )
            widget._handleRightClickOnRow(0, label_column)
            self.check(
                offset not in widget.resolved_function_labels,
                "right click again clears the resolved marker",
            )

        def select_deselect_all():
            widget.b_select_deselect_all.click()
            self.check(
                all(
                    widget.getSelectedLabel(row, label_column) == "-|-"
                    for row in range(table.rowCount())
                ),
                "(de)select all sets every label dropdown to the opt-out entry",
            )
            widget.b_select_deselect_all.click()
            # a dropdown whose matches carry no label on the server only offers the opt-out entry
            rows_with_labels = [
                row
                for row in range(table.rowCount())
                if len(widget.function_name_mapping[(row, label_column)]) > 1
            ]
            self.check(
                bool(rows_with_labels), "(de)select all has at least one labelled row to restore"
            )
            self.check(
                all(
                    widget.getSelectedLabel(row, label_column) != "-|-" for row in rows_with_labels
                ),
                "(de)select all restores a real label in every dropdown that offers one",
            )

        def import_labels():
            backend = self.session.cc.backend
            offsets = [int(table.item(row, 0).text(), 16) for row in range(table.rowCount())]
            importable = [offset for offset in offsets if backend.has_default_function_name(offset)]
            self.check(bool(importable), "Function Overview lists functions without a custom name")
            before = {offset: backend.get_function_name(offset) for offset in importable}
            widget.b_import_labels.click()
            renamed = [
                offset
                for offset in importable
                if backend.get_function_name(offset) != before[offset]
            ]
            self.check(bool(renamed), "Import labels renamed at least one function")
            self.check(
                "Imported" in self.session.local_widget.label_mcrit_activity_info.text(),
                "Import labels reports the import in the activity info",
            )
            self.bv.undo()
            self.check(
                all(backend.get_function_name(offset) == before[offset] for offset in renamed),
                "Import labels is undoable in one step",
            )

        def table_clicks():
            offset = int(table.item(0, 0).text(), 16)
            self.single_click(table, 0, 0)
            self.check(
                table.currentRow() == 0,
                "clicking a Function Overview row selects it",
            )
            self.double_click(table, 0, 0)
            self.check(
                self.session.cc.backend.get_cursor_address() == offset,
                "double clicking the offset column jumps the cursor",
            )
            self.double_click(table, 0, 1)
            self.check(
                self.session.main_widget.tabs.currentWidget() is self.session.function_match_widget,
                "double clicking a match column switches to Function Scope",
            )
            self.session.main_widget.tabs.setCurrentIndex(2)

        self.sequence(
            [
                fetch_labels,
                filter_radios,
                score_spinbox,
                column_sorting,
                label_dropdown,
                right_click_resolves,
                select_deselect_all,
                import_labels,
                table_clicks,
            ],
            self.exercise_sample_summary,
        )

    ################################################################################
    # Sample Match Summary tab
    ################################################################################

    def exercise_sample_summary(self):
        widget = self.session.sample_widget
        families = widget.table_best_family_matches
        samples = widget.table_family_sample_matches

        def populated():
            self.session.main_widget.setTabFocus(widget.name)
            self.check(
                self.session.main_widget.tabs.currentWidget() is widget,
                "setTabFocus reaches the Sample Match Summary tab",
            )
            self.check(
                families.rowCount() > 0,
                "Sample Match Summary lists best matches once a result is loaded",
            )

        def filter_checkbox():
            baseline = families.rowCount()
            widget.cb_filter_library.setChecked(True)
            self.check(
                families.rowCount() <= baseline,
                "Sample Match Summary library filter does not widen the table",
            )
            widget.cb_filter_library.setChecked(False)
            self.check(
                families.rowCount() == baseline,
                "Sample Match Summary library filter restores the table",
            )

        def family_selection():
            family = families.item(0, 2).text()
            self.single_click(families, 0, 2)
            self.check(
                widget.last_family_selected == family,
                "clicking a family row selects that family",
            )
            self.check(
                f'"{family}"' in widget.label_sample_matches_family.text(),
                "the sample table header names the selected family",
            )
            self.check(samples.rowCount() > 0, "the selected family lists its sample matches")

        def sorting():
            rows = families.rowCount()
            for column in range(families.columnCount()):
                families.sortByColumn(column, self.session.cc.QtCore.Qt.DescendingOrder)
                self.check(
                    families.rowCount() == rows,
                    f"Sample Match Summary keeps all rows sorting column {column}",
                )

        def double_click_is_inert():
            before = families.rowCount()
            self.double_click(families, 0, 2)
            self.check(
                families.rowCount() == before,
                "double clicking a family row leaves the table untouched",
            )

        self.sequence(
            [populated, filter_checkbox, family_selection, sorting, double_click_is_inert],
            self.exercise_navigation,
        )

    ################################################################################
    # cursor navigation reaching both cursor-following tabs
    ################################################################################

    def exercise_navigation(self):
        candidates = sorted(
            (
                function
                for function in self.bv.functions
                if self.session.local_smda_report.getFunction(function.start) is not None
                and self.session.local_smda_report.getFunction(function.start).num_instructions
                >= 10
            ),
            key=lambda function: len(function.basic_blocks),
            reverse=True,
        )
        self.check(len(candidates) >= 2, "the query sample has two functions large enough to match")
        self.target, self.second_target = candidates[0], candidates[1]

        block_widget = self.session.block_match_widget
        function_widget = self.session.function_match_widget
        for widget, name in ((block_widget, "Block Scope"), (function_widget, "Function Scope")):
            widget.cb_activate_live_tracking.setChecked(False)
            widget.cb_activate_live_tracking.click()
            self.check(
                widget.cb_activate_live_tracking.isChecked(),
                f"{name} live query checkbox turns live tracking on",
            )
        self.step(lambda: self.navigate_to(self.target, self.navigate_second), 10)

    def navigate_to(self, function, then):
        frame = self.widget.backend.view_frame
        self.check(frame is not None, "the sidebar knows its view frame")
        frame.navigate(self.bv, function.start)

        def verify():
            expected = "0x%x" % function.start
            block_label = self.session.block_match_widget.label_current_function_matches.text()
            function_label = (
                self.session.function_match_widget.label_current_function_matches.text()
            )
            self.check(
                expected in block_label,
                f"Block Scope header follows the cursor to {expected} ({block_label!r})",
            )
            self.check(
                expected in function_label,
                f"Function Scope header follows the cursor to {expected} ({function_label!r})",
            )
            then()

        self.step(verify, NAVIGATION_SETTLE_MS)

    def navigate_second(self):
        self.navigate_to(self.second_target, self.after_second_navigation)

    def after_second_navigation(self):
        widget = self.session.function_match_widget
        self.check(
            widget.table_function_matches.rowCount() > 0,
            "the second function queried successfully and lists matches",
        )
        self.step(self.exercise_function_scope)

    ################################################################################
    # Function Scope tab
    ################################################################################

    def exercise_function_scope(self):
        widget = self.session.function_match_widget
        matches = widget.table_function_matches
        names = widget.table_function_names
        self.session.main_widget.setTabFocus(widget.name)

        def query_button():
            widget.b_query_single.click()
            self.check(
                matches.rowCount() > 0, "Query current function lists matches for the cursor"
            )
            self.check(
                "0x%x" % self.second_target.start in widget.label_current_function_matches.text(),
                "Function Scope header names the queried function",
            )

        def score_spinbox():
            baseline = matches.rowCount()
            widget.sb_score_threshold.setValue(100)
            self.check(
                matches.rowCount() <= baseline, "Function Scope min-score spinbox narrows matches"
            )
            widget.sb_score_threshold.setValue(widget.sb_score_threshold.minimum())
            self.check(
                matches.rowCount() == baseline, "Function Scope min-score spinbox restores matches"
            )

        def library_filter():
            baseline = matches.rowCount()
            widget.cb_filter_library.setChecked(False)
            widget.cb_filter_library.click()
            self.check(
                widget.cb_filter_library.isChecked(),
                "Function Scope library filter checkbox toggles on",
            )
            self.check(
                matches.rowCount() <= baseline,
                "Function Scope library filter does not widen the matches",
            )
            widget.cb_filter_library.click()
            self.check(
                matches.rowCount() == baseline,
                "Function Scope library filter restores the matches",
            )

        def match_double_click():
            before = len(self.graph_calls)
            self.double_click(matches, 0, 0)
            self.check(
                len(self.graph_calls) == before + 1,
                "double clicking a function match opens the CFG graph",
            )

        def match_right_click():
            columns = self.session.config.FUNCTION_MATCHES_TABLE_COLUMNS
            import mcrit_plugin.core.McritTableColumn as McritTableColumn

            sha256_column = McritTableColumn.columnTypeToIndex(McritTableColumn.SHA256, columns)
            sample_column = McritTableColumn.columnTypeToIndex(McritTableColumn.SAMPLE_ID, columns)
            matches.setCurrentCell(0, sha256_column)
            sample_id = int(matches.item(0, sample_column).text())
            matches.customContextMenuRequested.emit(QPoint(0, 0))
            expected = self.session.sample_infos[sample_id].sha256
            self.check(
                self.session.cc.QApplication.clipboard().text() == expected,
                "right clicking the SHA256 column copies the full hash to the clipboard",
            )

        def name_table():
            self.check(
                names.rowCount() > 0, "Names from Matched Functions lists labels for the matches"
            )
            import mcrit_plugin.core.McritTableColumn as McritTableColumn

            columns = self.session.config.FUNCTION_NAMES_TABLE_COLUMNS
            id_column = McritTableColumn.columnTypeToIndex(McritTableColumn.FUNCTION_ID, columns)
            label_column = McritTableColumn.columnTypeToIndex(
                McritTableColumn.FUNCTION_LABEL, columns
            )
            before = len(self.graph_calls)
            self.double_click(names, 0, id_column)
            self.check(
                len(self.graph_calls) == before + 1,
                "double clicking a name's function id opens the CFG graph",
            )
            backend = self.session.cc.backend
            original_name = backend.get_function_name(self.second_target.start)
            label = names.item(0, label_column).text()
            self.double_click(names, 0, label_column)
            self.check(
                backend.get_function_name(self.second_target.start) == label,
                "double clicking a label renames the current function",
            )
            self.bv.undo()
            self.check(
                backend.get_function_name(self.second_target.start) == original_name,
                "the label rename is undoable",
            )

        self.sequence(
            [
                query_button,
                score_spinbox,
                library_filter,
                match_double_click,
                match_right_click,
                name_table,
            ],
            self.exercise_block_scope,
        )

    ################################################################################
    # Block Scope tab
    ################################################################################

    def exercise_block_scope(self):
        widget = self.session.block_match_widget
        summary = widget.table_block_summary
        matches = widget.table_block_matches
        self.session.main_widget.setTabFocus(widget.name)

        def query_button():
            widget.b_query_single.click()
            self.check(summary.rowCount() > 0, "Query current basic block lists the blocks")
            self.check(
                "0x%x" % self.second_target.start in widget.label_current_function_matches.text(),
                "Block Scope header names the queried function",
            )

        def size_spinbox():
            baseline = summary.rowCount()
            widget.sb_blocksize_threshold.setValue(widget.sb_blocksize_threshold.maximum())
            self.check(
                summary.rowCount() <= baseline,
                "Block Scope min-size spinbox narrows the block summary",
            )
            widget.sb_blocksize_threshold.setValue(4)
            self.check(
                summary.rowCount() == baseline,
                "Block Scope min-size spinbox restores the block summary",
            )

        def library_filter():
            baseline = summary.rowCount()
            widget.cb_filter_library.setChecked(False)
            widget.cb_filter_library.click()
            self.check(
                widget.cb_filter_library.isChecked(),
                "Block Scope library filter checkbox toggles on",
            )
            self.check(
                summary.rowCount() <= baseline,
                "Block Scope library filter does not widen the block summary",
            )
            widget.cb_filter_library.click()
            self.check(
                summary.rowCount() == baseline, "Block Scope library filter restores the blocks"
            )

        def summary_click():
            matched_row = next(
                (row for row in range(summary.rowCount()) if int(summary.item(row, 5).text()) > 0),
                None,
            )
            self.check(matched_row is not None, "at least one block of the function has matches")
            self.summary_row = matched_row
            offset = int(summary.item(matched_row, 0).text(), 16)
            self.single_click(summary, matched_row, 0)
            self.check(
                self.session.current_block == offset,
                "clicking a block summary row selects that block",
            )
            self.check(
                "0x%x" % offset in widget.label_block_matches.text(),
                "the block matches header names the selected block",
            )
            self.check(matches.rowCount() > 0, "the selected block lists its matches")

        def summary_double_click():
            offset = int(summary.item(self.summary_row, 0).text(), 16)
            self.double_click(summary, self.summary_row, 0)
            self.check(
                self.session.cc.backend.get_cursor_address() == offset,
                "double clicking a block summary row jumps the cursor to the block",
            )

        def matches_double_click():
            before = len(self.graph_calls)
            self.double_click(matches, 0, 0)
            self.check(
                len(self.graph_calls) == before + 1,
                "double clicking a block match opens the CFG graph",
            )

        def matches_right_click():
            import mcrit_plugin.core.McritTableColumn as McritTableColumn

            columns = self.session.config.BLOCK_MATCHES_TABLE_COLUMNS
            sha256_column = McritTableColumn.columnTypeToIndex(McritTableColumn.SHA256, columns)
            clipboard = self.session.cc.QApplication.clipboard()
            before = clipboard.text()
            matches.setCurrentCell(0, 0)
            matches.customContextMenuRequested.emit(QPoint(0, 0))
            self.check(
                sha256_column is None and clipboard.text() == before,
                "the block match context menu stays inert without a SHA256 column",
            )

        self.sequence(
            [
                query_button,
                size_spinbox,
                library_filter,
                summary_click,
                summary_double_click,
                matches_double_click,
                matches_right_click,
            ],
            self.exercise_export_and_yara,
        )

    ################################################################################
    # Export and YARA toolbar actions
    ################################################################################

    def exercise_export_and_yara(self):
        main_widget = self.session.main_widget
        backend = self.session.cc.backend
        export_path = os.path.join(binaryninja.user_directory(), "exported.smda")
        backend.ask_save_file = lambda default_name, prompt: export_path
        main_widget.exportSmdaAction.trigger()

        def exported():
            self.check(
                os.path.isfile(export_path) and os.path.getsize(export_path) > 0,
                "Export SMDA report wrote the report to the chosen path",
            )
            self.check(
                "exported to" in self.session.local_widget.label_mcrit_activity_info.text(),
                "Export SMDA report reports the path in the activity info",
            )
            self.build_yara_string()

        self.wait(
            lambda: os.path.isfile(export_path) and not main_widget._building,
            exported,
            "Export SMDA report finished in the background",
        )

    def build_yara_string(self):
        main_widget = self.session.main_widget
        clipboard = self.session.cc.QApplication.clipboard()
        test = self

        class YaraDialog(main_widget.YaraStringBuilderDialog):
            def exec_(dialog):
                test.check(
                    dialog.radio_function.isEnabled(),
                    "YARA builder offers the current function as scope",
                )
                dialog.radio_function.setChecked(True)
                dialog.cb_wildcards.setChecked(False)
                dialog.copy_escaped_button.click()
                test.check(
                    bool(clipboard.text()) and " " in clipboard.text(),
                    "Copy Escaped Bytes puts the instruction bytes on the clipboard",
                )
                dialog.cb_wildcards.setChecked(True)
                dialog.copy_yara_button.click()
                test.check(
                    clipboard.text().startswith("rule ") and "condition:" in clipboard.text(),
                    "Copy YARA Rule puts a complete rule on the clipboard",
                )
                dialog.ok_button.click()
                return 1

        self.widget.backend.view_frame.navigate(self.bv, self.second_target.start)
        # the patch stays installed so the Plugins menu action below cannot open a blocking dialog
        main_widget.YaraStringBuilderDialog = YaraDialog

        def trigger():
            main_widget.buildYaraStringAction.trigger()
            self.check(
                "YARA rule copied to clipboard"
                in self.session.local_widget.label_mcrit_activity_info.text(),
                "the YARA builder reports the copy in the activity info",
            )
            self.step(self.exercise_plugin_actions)

        self.step(trigger, NAVIGATION_SETTLE_MS)

    ################################################################################
    # Plugins -> MCRIT menu actions
    ################################################################################

    def exercise_plugin_actions(self):
        handler = UIActionHandler.globalActions()
        context = self.action_context()
        main_widget = self.session.main_widget
        expected_validity = {
            "MCRIT\\Show Sidebar": True,
            "MCRIT\\Convert to SMDA Report": True,
            "MCRIT\\Upload SMDA Report": main_widget.uploadSmdaAction.isEnabled(),
            "MCRIT\\Fetch Matching Result": main_widget.getMatchResultAction.isEnabled(),
            "MCRIT\\Export SMDA Report...": main_widget.exportSmdaAction.isEnabled(),
            "MCRIT\\Build YARA String from Selection": main_widget.buildYaraStringAction.isEnabled(),
            "MCRIT\\Query Current Function": True,
            "MCRIT\\Query Current Block": True,
        }
        names = [name for name, _handler, _enabled in self.sidebar_module._ACTIONS]
        for name in names:
            self.check(
                handler.isValidAction(name, context) == expected_validity[name],
                f"menu action validity matches the toolbar state: {name}",
            )

        target_job = str(self.job_id)

        class SelectDialog(main_widget.ResultChooserDialog):
            def exec_(dialog):
                rows = [
                    row
                    for row, info in enumerate(dialog.job_infos)
                    if str(info.job_id) == target_job
                ]
                dialog.table_jobs.selectRow(rows[0])
                dialog.select_button.click()
                return 1

        main_widget.ResultChooserDialog = SelectDialog
        # each action must leave a trace that only its handler can produce
        activity = self.session.local_widget.label_mcrit_activity_info
        backend = self.session.cc.backend
        background_runs = []
        original_run_background = backend.run_background

        def counted_run_background(*args, **kwargs):
            background_runs.append(args[0] if args else kwargs.get("title"))
            return original_run_background(*args, **kwargs)

        backend.run_background = counted_run_background
        runs_before = {"count": 0}

        def started_background():
            # the export may already have finished; the start of a background run is the stable trace
            return len(background_runs) > runs_before["count"]

        effects = {
            "MCRIT\\Show Sidebar": lambda: self.find_widget(),
            "MCRIT\\Convert to SMDA Report": started_background,
            "MCRIT\\Upload SMDA Report": started_background,
            "MCRIT\\Export SMDA Report...": started_background,
            "MCRIT\\Fetch Matching Result": lambda: (
                main_widget.tabs.currentWidget() is self.session.function_widget
            ),
            "MCRIT\\Build YARA String from Selection": lambda: (
                "YARA rule copied" in activity.text()
            ),
            "MCRIT\\Query Current Function": lambda: (
                self.session.function_match_widget.table_function_matches.rowCount() > 0
            ),
            "MCRIT\\Query Current Block": lambda: (
                self.session.block_match_widget.table_block_summary.rowCount() > 0
            ),
        }
        pending = list(names)

        def run_next():
            if not pending:
                self.step(self.exercise_close_prompt)
                return
            name = pending.pop(0)
            self.session.local_widget.updateActivityInfo("menu action pending")
            self.session.function_match_widget.clearTable()
            self.session.block_match_widget.clearTable()
            runs_before["count"] = len(background_runs)
            handler.executeAction(name, self.action_context())
            # the header leaves it open whether executeAction runs the handler synchronously
            self.wait(
                effects[name],
                lambda: self.wait(
                    lambda: not main_widget._building,
                    lambda: self.step(run_next, 10),
                    f"menu action settled: {name}",
                ),
                f"menu action took effect: {name}",
            )

        self.step(run_next)

    def clear_stored_token(self):
        settings = binaryninja.Settings()
        settings.set_string("mcrit.mcritweb_api_token", "integration-token")
        UIActionHandler.globalActions().executeAction(
            "MCRIT\\Clear Stored API Token", self.action_context()
        )
        self.check(
            not settings.get_string("mcrit.mcritweb_api_token"),
            "Clear Stored API Token removes the stored token",
        )

    ################################################################################
    # close-time upload prompt
    ################################################################################

    def exercise_close_prompt(self):
        self.clear_stored_token()
        backend = self.session.cc.backend
        binaryninja.Settings().set_bool("mcrit.submit_function_names_on_close", True)
        self.check(
            self.session.config.SUBMIT_FUNCTION_NAMES_ON_CLOSE,
            "submit_function_names_on_close is enabled for the close prompt",
        )
        backend.set_function_name(self.target.start, "mcrit_integration_renamed")
        self.check(
            bool(self.session.findUnsyncedFunctionNames()),
            "renaming a function makes the report look out of sync",
        )
        prompts = []
        uploads = []
        backend.ask_yes_no = lambda prompt: prompts.append(prompt) or True
        original_upload = self.session.mcrit_interface.uploadReport

        def capture_upload(report):
            uploads.append(report)
            return original_upload(report)

        self.session.mcrit_interface.uploadReport = capture_upload
        try:
            file_context = self.widget.backend.view_frame.getFileContext()
            self.sidebar_module._context_notification.OnBeforeCloseFile(
                self.context, file_context, self.widget.backend.view_frame
            )
        finally:
            self.session.mcrit_interface.uploadReport = original_upload
        self.check(len(prompts) == 1, "closing the file asks once about the renamed functions")
        self.check(
            "Upload an updated report" in prompts[0],
            "the close prompt explains that the report is uploaded",
        )
        self.check(len(uploads) == 1, "answering yes uploads the updated report")
        self.check(
            any(
                function.function_name == "mcrit_integration_renamed"
                for function in uploads[0].getFunctions()
            ),
            "the uploaded report carries the new function name",
        )
        self.bv.undo()
        self.finish(True)


class IntegrationNotification(UIContextNotification):
    def __init__(self):
        UIContextNotification.__init__(self)
        self.started = False

    def OnAfterOpenFile(self, context, file, frame):
        if self.started:
            return
        self.started = True
        bv = frame.getCurrentBinaryView()
        log(f"opened {bv.file.filename} ({bv.view_type})")
        integration = IntegrationTest(context, bv)

        def analyze():
            bv.update_analysis_and_wait()
            binaryninja.execute_on_main_thread(lambda: integration.step(integration.start))

        threading.Thread(target=analyze, daemon=True).start()


if os.environ.get("MCRIT_BN_INTEGRATION_SHA256"):
    open(LOG, "w").close()
    _integration_notification = IntegrationNotification()
    UIContext.registerNotification(_integration_notification)
