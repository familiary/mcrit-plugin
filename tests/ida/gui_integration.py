#!/usr/bin/env python3
"""Headless IDA test for the installed MCRIT4IDA plugin.

This intentionally drives the same Qt actions and signals a user would use in
IDA.  The only adapters are deterministic answers for modal dialogs and the
IDA graph window, which cannot be interacted with in a headless process.

One helper per widget exercises every interactive element of that widget and
asserts its effect, mirroring tests/binja/gui_integration.py.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

PLUGIN_ROOT = Path(os.environ["MCRIT_IDA_PLUGIN_ROOT"]).resolve()
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def _check(condition, message):
    _assert(condition, message)
    print(f"PASS {message}")


def _is_live() -> bool:
    return os.environ.get("MCRIT_IDA_INTEGRATION_LIVE", "1") == "1"


def _qexit(code: int) -> None:
    try:
        import ida_pro

        ida_pro.qexit(code)
    except Exception:
        import idaapi

        idaapi.qexit(code)


def _artifact_dir():
    value = os.environ.get("MCRIT_IDA_INTEGRATION_ARTIFACT_DIR")
    if not value:
        return None
    artifact_dir = Path(value).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir


def _write_report_artifact(report, filename="generated-smda.json"):
    artifact_dir = _artifact_dir()
    if artifact_dir is None:
        return
    with (artifact_dir / filename).open("w", encoding="utf-8") as output:
        json.dump(report.toDict(), output, indent=1, sort_keys=True)


def _process_events(qt_application, rounds=1):
    for _ in range(rounds):
        qt_application.processEvents()


def _release_qt_objects(form, qt_application):
    # qexit() calls exit() without returning to Qt's event loop; deferred deletes still queued
    # then run during C++ static destruction and abort IDA (seen with macOS style animations).
    import mcrit_plugin.ui_qt.QtShim as QtShim

    qt_core = QtShim.get_QtCore()
    if form is not None and form.parent is not None:
        form.parent.close()
        form.parent.deleteLater()
        form.parent = None
    for _ in range(3):
        qt_application.processEvents()
        qt_core.QCoreApplication.sendPostedEvents(None, qt_core.QEvent.Type.DeferredDelete)


def _emit_table_signal(table, signal_name, row=0, column=0):
    index = table.model().index(row, column)
    getattr(table, signal_name).emit(index)


def _single_click(table, row, column):
    table.setCurrentCell(row, column)
    _emit_table_signal(table, "clicked", row, column)


def _double_click(table, row, column):
    table.setCurrentCell(row, column)
    _emit_table_signal(table, "doubleClicked", row, column)


def _has_disassembly_view():
    """IDA only tracks a screen address while a disassembly view exists (not in batch mode)."""
    import ida_kernwin

    widget = ida_kernwin.get_current_widget()
    return widget is not None and ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM


def _expect_jump(form, action, offset, message):
    """Assert that action() navigates to offset, through IDA's cursor or through the backend."""
    if _has_disassembly_view():
        action()
        _check(form.cc.backend.get_cursor_address() == offset, message)
        return
    jumped = []
    form.cc.backend.jump_to = lambda address: jumped.append(address)
    try:
        action()
    finally:
        del form.cc.backend.jump_to
    _check(jumped == [offset], message)


def _qt_order(form, descending=False):
    qt = form.cc.QtCore.Qt
    return qt.DescendingOrder if descending else qt.AscendingOrder


def _wait_for_functions(client, sample_id, qt_application=None):
    timeout = int(os.environ.get("MCRIT_IDA_INTEGRATION_TIMEOUT", "30"))
    deadline = time.monotonic() + timeout
    last_functions = None
    while time.monotonic() < deadline:
        last_functions = client.getFunctionsBySampleId(sample_id) or []
        if last_functions:
            return last_functions
        if qt_application is not None:
            _process_events(qt_application)
        time.sleep(2)
    raise TimeoutError(
        f"MCRIT did not finish processing query sample {sample_id} "
        f"within {timeout}s (functions={last_functions!r})"
    )


def _matches_sample(matches, sample_id):
    for sample_match in matches.get("samples", []) or []:
        if isinstance(sample_match, dict) and sample_match.get("sample_id") == sample_id:
            return True

    function_summaries = matches.get("functions", {}) or {}
    if isinstance(function_summaries, dict):
        function_summaries = function_summaries.values()
    for function_summary in function_summaries:
        for match_tuple in function_summary.get("matches", []) or []:
            if len(match_tuple) > 1 and match_tuple[1] == sample_id:
                return True
    return False


def _run_plugin_lifecycle(module):
    plugin = module.PLUGIN_ENTRY()
    _check(plugin.wanted_name == "MCRIT4IDA", "plugin registers as MCRIT4IDA")
    _check(plugin.wanted_hotkey == "Ctrl-F4", "plugin registers the Ctrl-F4 hotkey")
    plugmod = plugin.init()
    _check(plugmod is not None, "plugin init returned a plugmod")

    original_show = module.show_mcrit_form
    sentinel = object()
    module.show_mcrit_form = lambda: sentinel
    try:
        _check(plugmod.run(0) is True, "plugmod.run succeeds")
        _check(plugmod.form is sentinel, "plugmod.run retains the form it opened")
    finally:
        module.show_mcrit_form = original_show
        # the sentinel is not a form; keep plugmod.__del__ from releasing it
        plugmod.form = None
    return plugin, plugmod


def _exercise_cursor_tracking(form, qt_application):
    import ida_funcs
    import ida_hexrays
    import ida_kernwin

    backend = form.cc.backend
    function = ida_funcs.getn_func(0)
    _check(function is not None, "database has functions for cursor tracking")
    ida_kernwin.jumpto(function.start_ea)
    _process_events(qt_application, rounds=2)
    disassembly = ida_kernwin.get_current_widget()
    if (
        disassembly is not None
        and ida_kernwin.get_widget_type(disassembly) == ida_kernwin.BWN_DISASM
    ):
        _check(
            backend.get_current_function(disassembly) == function.start_ea,
            "disassembly cursor resolves to its function",
        )
    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays unavailable; skipping pseudocode cursor tracking check")
        return
    vdui = ida_hexrays.open_pseudocode(function.start_ea, ida_hexrays.OPF_REUSE)
    _check(vdui is not None, "a pseudocode view can be opened")
    _process_events(qt_application, rounds=2)
    _check(
        backend.get_current_function(vdui.ct) == function.start_ea,
        "pseudocode view resolves to its function",
    )
    ida_kernwin.close_widget(vdui.ct, 0)
    _process_events(qt_application)


def _create_form(module):
    """Open the real plugin form; fall back to a standalone form when IDA cannot show one."""
    import mcrit_plugin.ui_qt.QtShim as QtShim

    qt_widgets = QtShim.get_QtWidgets()
    qt_application = qt_widgets.QApplication.instance()
    if qt_application is None:
        qt_application = qt_widgets.QApplication([])

    form = module.show_mcrit_form()
    if form is not None:
        _check(form.view_hook is not None, "the shown form hooked the IDA views")
    else:
        print("[!] PluginForm could not be shown; using a standalone form with manual view hooks")
        form = module.Mcrit4IdaForm()
        form.parent = qt_widgets.QWidget()
        form.setupWidgets()
        form.view_hook = module.IdaViewHooks(form)
        form.view_hook.hook()
    _process_events(qt_application, rounds=2)
    return form, qt_application


@contextmanager
def _smda_info_adapter(main_widget, family="mcrit-plugin-ci", version="fixture-query"):
    original_dialog = main_widget.SmdaInfoDialog
    base_dialog = original_dialog

    class DeterministicSmdaInfoDialog(base_dialog):
        def exec_(self):
            self.edit_family.setText(family)
            self.edit_version.setText(version)
            self._cb_is_library.setChecked(False)
            self.ok_button.click()
            return 1

    main_widget.SmdaInfoDialog = DeterministicSmdaInfoDialog
    try:
        yield
    finally:
        main_widget.SmdaInfoDialog = original_dialog


@contextmanager
def _result_dialog_adapter(main_widget, mode, target_job_id=None):
    original_dialog = main_widget.ResultChooserDialog
    base_dialog = original_dialog
    target_text = str(target_job_id) if target_job_id is not None else None

    class DeterministicResultChooserDialog(base_dialog):
        def exec_(self):
            if mode == "request":
                self.create_button.click()
                return 1

            _assert(self.job_infos, "result chooser had no jobs for selection")
            selected_row = None
            for row, job_info in enumerate(self.job_infos):
                if str(job_info.job_id) == target_text:
                    selected_row = row
                    break
            _assert(selected_row is not None, f"matching job {target_text} was not listed")
            self.table_jobs.selectRow(selected_row)
            self.select_button.click()
            return 1

    main_widget.ResultChooserDialog = DeterministicResultChooserDialog
    try:
        yield
    finally:
        main_widget.ResultChooserDialog = original_dialog


@contextmanager
def _capture_graph_show(module_name="mcrit_plugin.ida.SmdaGraphViewer"):
    module = importlib.import_module(module_name)
    original_show = module.SmdaGraphViewer.Show
    captured = []

    def capture_show(viewer):
        callback_text = None
        callback_hint = None
        if viewer.smda_function is not None:
            blocks = list(viewer.smda_function.getBlocks())
            if blocks:
                block_offset = blocks[0].offset
                viewer._offset_to_node_id = {block_offset: 0}
                viewer._node_id_to_offset = {0: block_offset}
                callback_text = viewer.OnGetText(0)
                callback_hint = viewer.OnHint(0)
        captured.append((viewer, callback_text, callback_hint))
        return True

    module.SmdaGraphViewer.Show = capture_show
    try:
        yield captured
    finally:
        module.SmdaGraphViewer.Show = original_show


################################################################################
# setup, conversion, upload, matching
################################################################################


def _check_disabled_before_conversion(form):
    main_widget = form.main_widget
    for action, name in (
        (main_widget.uploadSmdaAction, "Upload"),
        (main_widget.getMatchResultAction, "Fetch Matching Result"),
        (main_widget.exportSmdaAction, "Export"),
        (main_widget.buildYaraStringAction, "Build YARA String"),
    ):
        _check(not action.isEnabled(), f"toolbar {name} disabled before conversion")
    for widget, label in (
        (form.block_match_widget, "Block Scope"),
        (form.function_match_widget, "Function Scope"),
    ):
        _check(
            not widget.b_query_single.isEnabled()
            and not widget.cb_filter_library.isEnabled()
            and not widget.cb_activate_live_tracking.isEnabled(),
            f"{label} controls disabled before conversion",
        )


def _check_input_sha256(form):
    import ida_nalt

    input_path = Path(ida_nalt.get_input_file_path())
    if not input_path.is_file():
        return
    expected = hashlib.sha256(input_path.read_bytes()).hexdigest()
    _check(form.cc.backend.get_input_sha256() == expected, "input sha256 matches file")


def _convert(form, qt_application):
    main_widget = form.main_widget
    with _smda_info_adapter(main_widget):
        main_widget.parseSmdaAction.trigger()
    _process_events(qt_application, rounds=2)
    report = form.local_smda_report
    _check(report is not None, "Convert action produced an SMDA report")
    _check(len(list(report.getFunctions())) > 0, "SMDA report contains functions")
    _check(report.smda_version.startswith("MCRIT4IDA"), "report records the IDA producer")
    _check(
        report.family
        == (
            form.remote_sample_entry.family
            if form.remote_sample_entry is not None
            else "mcrit-plugin-ci"
        ),
        "the report carries the family from the dialog, or from the known remote sample",
    )
    _write_report_artifact(report)
    _check(
        main_widget.uploadSmdaAction.isEnabled()
        and main_widget.exportSmdaAction.isEnabled()
        and main_widget.buildYaraStringAction.isEnabled(),
        "Upload/Export/YARA actions enabled after conversion",
    )
    _check(
        main_widget.getMatchResultAction.isEnabled() == (form.remote_sample_entry is not None),
        "Fetch Matching Result is enabled exactly when the sample is already on the server",
    )
    for widget, label in (
        (form.block_match_widget, "Block Scope"),
        (form.function_match_widget, "Function Scope"),
    ):
        _check(
            widget.b_query_single.isEnabled()
            and widget.cb_filter_library.isEnabled()
            and widget.cb_activate_live_tracking.isEnabled(),
            f"{label} controls enabled after conversion",
        )
    return report


def _upload_and_match(form, report, qt_application):
    interface = form.mcrit_interface
    client = interface.mcrit_client
    main_widget = form.main_widget

    main_widget.uploadSmdaAction.trigger()
    _check(form.remote_sample_id is not None, "Upload SMDA action returned a sample id")
    _wait_for_functions(client, form.remote_sample_id, qt_application)
    _check(
        main_widget.getMatchResultAction.isEnabled(), "Fetch Matching Result enabled after upload"
    )
    interface.querySampleSha256(report.sha256)
    interface.queryAllFamilyEntries()
    interface.queryAllSampleEntries()
    interface.queryFunctionEntriesBySampleId(form.remote_sample_id)
    _check(form.remote_sample_entry is not None, "uploaded sample found by sha256")

    job_ids = []
    original_request = client.requestMatchesForSample

    def request_and_capture(*args, **kwargs):
        job_id = original_request(*args, **kwargs)
        job_ids.append(job_id)
        return job_id

    client.requestMatchesForSample = request_and_capture
    try:
        with _result_dialog_adapter(main_widget, "request"):
            main_widget.getMatchResultAction.trigger()
    finally:
        client.requestMatchesForSample = original_request
    _check(bool(job_ids and job_ids[-1]), "Create Matching Job returned a job id")

    result = client.awaitResult(job_ids[-1], sleep_time=1)
    _check(isinstance(result, dict), "matching job finished")
    matches = result.get("matches", {})
    _check(bool(matches.get("samples") or matches.get("functions")), "MCRIT returned matches")
    reference_sha256 = os.environ.get("MCRIT_IDA_INTEGRATION_REFERENCE_SHA256")
    if reference_sha256:
        reference_sample = client.getSampleBySha256(reference_sha256)
        _check(reference_sample is not None, "MCRIT reference sample could be retrieved")
        _check(
            _matches_sample(matches, reference_sample.sample_id),
            "IDA report matches the reference sample",
        )

    with _result_dialog_adapter(main_widget, "select", job_ids[-1]):
        main_widget.getMatchResultAction.trigger()
    _check(form.matching_report is not None, "result chooser loaded the MatchingResult")
    _check(
        main_widget.tabs.currentWidget() is form.function_widget,
        "Function Overview shown with results",
    )
    return job_ids[-1]


################################################################################
# Function Overview tab
################################################################################


def _exercise_overview_widget(form, qt_application):
    import ida_undo

    import mcrit_plugin.core.McritTableColumn as McritTableColumn

    widget = form.function_widget
    table = widget.table_local_functions
    label_column = McritTableColumn.columnTypeToIndex(
        McritTableColumn.SCORE_AND_LABEL, form.config.OVERVIEW_TABLE_COLUMNS
    )
    offset_column = McritTableColumn.columnTypeToIndex(
        McritTableColumn.OFFSET, form.config.OVERVIEW_TABLE_COLUMNS
    )
    _check(
        label_column is not None and offset_column is not None, "Function Overview columns exist"
    )

    widget.b_fetch_labels.click()
    _process_events(qt_application, rounds=2)
    _check(table.rowCount() > 0, "Fetch labels for matches populated the Function Overview")
    _check(
        any(entry.function_labels for entry in (form.matched_function_entries or {}).values()),
        "Fetch labels for matches returned labels from the server",
    )

    baseline = table.rowCount()
    widget.rb_filter_labels.setChecked(True)
    _check(table.rowCount() <= baseline, "filter 'labels' does not widen the Function Overview")
    widget.rb_filter_applicable.setChecked(True)
    applicable = table.rowCount()
    widget.rb_filter_conflicted.setChecked(True)
    _check(table.rowCount() <= applicable, "filter 'conflicted' is a subset of filter 'applicable'")
    widget.rb_filter_none.setChecked(True)
    _check(table.rowCount() == baseline, "filter 'none' restores the full Function Overview")

    spinbox = widget.sb_minhash_threshold
    spinbox.setValue(spinbox.maximum())
    _check(table.rowCount() <= baseline, "Function Overview min-score spinbox narrows the table")
    spinbox.setValue(spinbox.minimum())
    _check(table.rowCount() == baseline, "Function Overview min-score spinbox restores the table")

    rows = table.rowCount()
    for column in range(table.columnCount()):
        table.sortByColumn(column, _qt_order(form))
        _check(
            table.rowCount() == rows,
            f"Function Overview keeps all rows sorting column {column} ascending",
        )
        table.sortByColumn(column, _qt_order(form, descending=True))
        _check(
            table.rowCount() == rows,
            f"Function Overview keeps all rows sorting column {column} descending",
        )
    table.sortByColumn(offset_column, _qt_order(form))
    offsets = [int(table.item(row, offset_column).text(), 16) for row in range(rows)]
    _check(offsets == sorted(offsets), "Function Overview sorts offsets ascending")

    delegate = table.itemDelegateForColumn(label_column)
    _check(hasattr(delegate, "getEditorForRow"), "Function Overview installed label dropdowns")
    editor = delegate.getEditorForRow(0)
    _check(editor is not None, "label dropdown editor exists for the first row")
    _check(editor.count() > 1, "label dropdown offers a label and the '-|-' opt-out")
    editor.setCurrentIndex(0)
    editor.activated.emit(0)
    _check(editor.hasUserMadeSelection(), "label dropdown records an explicit user selection")

    offset = int(table.item(0, offset_column).text(), 16)
    widget._handleRightClickOnRow(0, label_column)
    _check(
        offset in widget.resolved_function_labels,
        "right click on a label dropdown marks the function resolved",
    )
    widget._handleRightClickOnRow(0, label_column)
    _check(
        offset not in widget.resolved_function_labels,
        "right click again clears the resolved marker",
    )

    widget.b_select_deselect_all.click()
    _check(
        all(widget.getSelectedLabel(row, label_column) == "-|-" for row in range(table.rowCount())),
        "(de)select all sets every label dropdown to the opt-out entry",
    )
    widget.b_select_deselect_all.click()
    # a row whose matches carry no label has nothing but the opt-out entry to offer
    labelled_rows = [
        row for row in range(table.rowCount()) if delegate.getEditorForRow(row).count() > 1
    ]
    _check(
        bool(labelled_rows)
        and all(widget.getSelectedLabel(row, label_column) != "-|-" for row in labelled_rows),
        "(de)select all restores a real label in every dropdown",
    )

    backend = form.cc.backend
    offsets = [int(table.item(row, offset_column).text(), 16) for row in range(table.rowCount())]
    importable = [offset for offset in offsets if backend.has_default_function_name(offset)]
    _check(bool(importable), "Function Overview lists functions without a custom name")
    before = {offset: backend.get_function_name(offset) for offset in importable}
    widget.b_import_labels.click()
    _process_events(qt_application)
    renamed = [
        offset for offset in importable if backend.get_function_name(offset) != before[offset]
    ]
    _check(bool(renamed), "Import labels renamed at least one function")
    _check(
        "Imported" in form.local_widget.label_mcrit_activity_info.text(),
        "Import labels reports the import in the activity info",
    )
    ida_undo.perform_undo()
    _check(
        all(backend.get_function_name(offset) == before[offset] for offset in renamed),
        "Import labels is undoable in one step",
    )

    offset = int(table.item(0, offset_column).text(), 16)
    _expect_jump(
        form,
        lambda: _double_click(table, 0, offset_column),
        offset,
        "double clicking the offset column jumps the cursor",
    )
    _double_click(table, 0, 1)
    _check(
        form.main_widget.tabs.currentWidget() is form.function_match_widget,
        "double clicking a match column switches to Function Scope",
    )


################################################################################
# Sample Match Summary tab
################################################################################


def _exercise_sample_widget(form, qt_application):
    widget = form.sample_widget
    families = widget.table_best_family_matches
    samples = widget.table_family_sample_matches

    form.main_widget.setTabFocus(widget.name)
    _process_events(qt_application, rounds=2)
    _check(
        form.main_widget.tabs.currentWidget() is widget,
        "setTabFocus reaches the Sample Match Summary tab",
    )
    _check(
        families.rowCount() > 0,
        "Sample Match Summary lists best matches once a result is loaded",
    )

    baseline = families.rowCount()
    widget.cb_filter_library.setChecked(True)
    _check(
        families.rowCount() <= baseline,
        "Sample Match Summary library filter does not widen the table",
    )
    widget.cb_filter_library.setChecked(False)
    _check(
        families.rowCount() == baseline, "Sample Match Summary library filter restores the table"
    )

    family = families.item(0, 2).text()
    _single_click(families, 0, 2)
    _check(widget.last_family_selected == family, "clicking a family row selects that family")
    _check(
        f'"{family}"' in widget.label_sample_matches_family.text(),
        "the sample table header names the selected family",
    )
    _check(samples.rowCount() > 0, "the selected family lists its sample matches")

    rows = families.rowCount()
    for column in range(families.columnCount()):
        families.sortByColumn(column, _qt_order(form, descending=True))
        _check(
            families.rowCount() == rows,
            f"Sample Match Summary keeps all rows sorting column {column}",
        )

    before = families.rowCount()
    _double_click(families, 0, 2)
    _check(families.rowCount() == before, "double clicking a family row leaves the table untouched")


################################################################################
# cursor navigation reaching both cursor-following tabs
################################################################################


def _navigate_to(form, offset, qt_application):
    import ida_kernwin

    if _has_disassembly_view():
        _check(ida_kernwin.jumpto(offset), "jumpto moved the IDA cursor to 0x%x" % offset)
        _process_events(qt_application, rounds=4)
        form.view_hook.refresh_widget(ida_kernwin.get_current_widget())
    else:
        # batch mode has no view to follow; drive the same refresh the view hook would
        form.current_function = offset
        form.function_match_widget.hook_refresh(None, use_current_function=True)
        form.block_match_widget.hook_refresh(None, use_current_block=True)
    _process_events(qt_application, rounds=2)
    expected = "0x%x" % offset
    block_label = form.block_match_widget.label_current_function_matches.text()
    function_label = form.function_match_widget.label_current_function_matches.text()
    _check(
        expected in block_label,
        f"Block Scope header follows the cursor to {expected} ({block_label!r})",
    )
    _check(
        expected in function_label,
        f"Function Scope header follows the cursor to {expected} ({function_label!r})",
    )


def _exercise_navigation(form, report, qt_application):
    candidates = sorted(
        (
            function
            for function in report.getFunctions()
            if function.num_instructions >= 10
            and any(sum(1 for _ in block.getInstructions()) >= 4 for block in function.getBlocks())
        ),
        key=lambda function: len(list(function.getBlocks())),
        reverse=True,
    )
    _check(len(candidates) >= 2, "the query sample has two functions large enough to match")
    target, second_target = candidates[0], candidates[1]

    for widget, name in (
        (form.block_match_widget, "Block Scope"),
        (form.function_match_widget, "Function Scope"),
    ):
        widget.cb_activate_live_tracking.setChecked(False)
        widget.cb_activate_live_tracking.click()
        _check(
            widget.cb_activate_live_tracking.isChecked(),
            f"{name} live query checkbox turns live tracking on",
        )

    _navigate_to(form, target.offset, qt_application)
    _navigate_to(form, second_target.offset, qt_application)
    _check(
        form.function_match_widget.table_function_matches.rowCount() > 0,
        "the second function queried successfully and lists matches",
    )
    return target, second_target


################################################################################
# Function Scope tab
################################################################################


def _exercise_function_widget(form, second_target, qt_application):
    import mcrit_plugin.core.McritTableColumn as McritTableColumn

    widget = form.function_match_widget
    matches = widget.table_function_matches
    names = widget.table_function_names
    form.main_widget.setTabFocus(widget.name)

    widget.b_query_single.click()
    _process_events(qt_application, rounds=2)
    _check(matches.rowCount() > 0, "Query current function lists matches for the cursor")
    _check(
        "0x%x" % second_target.offset in widget.label_current_function_matches.text(),
        "Function Scope header names the queried function",
    )

    baseline = matches.rowCount()
    widget.sb_score_threshold.setValue(100)
    _check(matches.rowCount() <= baseline, "Function Scope min-score spinbox narrows matches")
    widget.sb_score_threshold.setValue(widget.sb_score_threshold.minimum())
    _check(matches.rowCount() == baseline, "Function Scope min-score spinbox restores matches")

    baseline = matches.rowCount()
    widget.cb_filter_library.setChecked(False)
    widget.cb_filter_library.click()
    _check(
        widget.cb_filter_library.isChecked(), "Function Scope library filter checkbox toggles on"
    )
    _check(
        matches.rowCount() <= baseline, "Function Scope library filter does not widen the matches"
    )
    widget.cb_filter_library.click()
    _check(matches.rowCount() == baseline, "Function Scope library filter restores the matches")

    with _capture_graph_show() as graphs:
        _double_click(matches, 0, 0)
    _check(len(graphs) == 1, "double clicking a function match opens the CFG graph")
    _check(bool(graphs[0][1] and graphs[0][2]), "the function graph renders text and hints")

    columns = form.config.FUNCTION_MATCHES_TABLE_COLUMNS
    sha256_column = McritTableColumn.columnTypeToIndex(McritTableColumn.SHA256, columns)
    sample_column = McritTableColumn.columnTypeToIndex(McritTableColumn.SAMPLE_ID, columns)
    _check(sha256_column is not None, "Function Scope has a SHA256 column")
    matches.setCurrentCell(0, sha256_column)
    sample_id = int(matches.item(0, sample_column).text())
    matches.customContextMenuRequested.emit(form.cc.QtCore.QPoint(0, 0))
    _check(
        form.cc.QApplication.clipboard().text() == form.sample_infos[sample_id].sha256,
        "right clicking the SHA256 column copies the full hash to the clipboard",
    )

    _check(names.rowCount() > 0, "Names from Matched Functions lists labels for the matches")
    name_columns = form.config.FUNCTION_NAMES_TABLE_COLUMNS
    id_column = McritTableColumn.columnTypeToIndex(McritTableColumn.FUNCTION_ID, name_columns)
    label_column = McritTableColumn.columnTypeToIndex(McritTableColumn.FUNCTION_LABEL, name_columns)
    with _capture_graph_show() as graphs:
        _double_click(names, 0, id_column)
    _check(len(graphs) == 1, "double clicking a name's function id opens the CFG graph")

    import ida_undo

    backend = form.cc.backend
    original_name = backend.get_function_name(second_target.offset)
    label = names.item(0, label_column).text()
    _double_click(names, 0, label_column)
    _check(
        backend.get_function_name(second_target.offset) == label,
        "double clicking a label renames the current function",
    )
    ida_undo.perform_undo()
    _check(
        backend.get_function_name(second_target.offset) == original_name,
        "the label rename is undoable",
    )


################################################################################
# Block Scope tab
################################################################################


def _exercise_block_widget(form, second_target, qt_application):
    import mcrit_plugin.core.McritTableColumn as McritTableColumn

    widget = form.block_match_widget
    summary = widget.table_block_summary
    matches = widget.table_block_matches
    form.main_widget.setTabFocus(widget.name)

    widget.b_query_single.click()
    _process_events(qt_application, rounds=2)
    _check(summary.rowCount() > 0, "Query current basic block lists the blocks")
    _check(
        "0x%x" % second_target.offset in widget.label_current_function_matches.text(),
        "Block Scope header names the queried function",
    )

    baseline = summary.rowCount()
    widget.sb_blocksize_threshold.setValue(widget.sb_blocksize_threshold.maximum())
    _check(summary.rowCount() <= baseline, "Block Scope min-size spinbox narrows the block summary")
    widget.sb_blocksize_threshold.setValue(4)
    _check(
        summary.rowCount() == baseline, "Block Scope min-size spinbox restores the block summary"
    )

    baseline = summary.rowCount()
    widget.cb_filter_library.setChecked(False)
    widget.cb_filter_library.click()
    _check(widget.cb_filter_library.isChecked(), "Block Scope library filter checkbox toggles on")
    _check(
        summary.rowCount() <= baseline,
        "Block Scope library filter does not widen the block summary",
    )
    widget.cb_filter_library.click()
    _check(summary.rowCount() == baseline, "Block Scope library filter restores the blocks")

    offset_column = McritTableColumn.columnTypeToIndex(
        McritTableColumn.OFFSET, form.config.BLOCK_SUMMARY_TABLE_COLUMNS
    )
    functions_column = McritTableColumn.columnTypeToIndex(
        McritTableColumn.FUNCTIONS, form.config.BLOCK_SUMMARY_TABLE_COLUMNS
    )
    matched_row = next(
        (
            row
            for row in range(summary.rowCount())
            if int(summary.item(row, functions_column).text()) > 0
        ),
        None,
    )
    _check(matched_row is not None, "at least one block of the function has matches")
    offset = int(summary.item(matched_row, offset_column).text(), 16)
    _single_click(summary, matched_row, offset_column)
    _check(form.current_block == offset, "clicking a block summary row selects that block")
    _check(
        "0x%x" % offset in widget.label_block_matches.text(),
        "the block matches header names the selected block",
    )
    _check(matches.rowCount() > 0, "the selected block lists its matches")

    _expect_jump(
        form,
        lambda: _double_click(summary, matched_row, offset_column),
        offset,
        "double clicking a block summary row jumps the cursor to the block",
    )

    with _capture_graph_show() as graphs:
        _double_click(matches, 0, 0)
    _check(len(graphs) == 1, "double clicking a block match opens the CFG graph")
    _check(bool(graphs[0][1] and graphs[0][2]), "the block graph renders text and hints")

    sha256_column = McritTableColumn.columnTypeToIndex(
        McritTableColumn.SHA256, form.config.BLOCK_MATCHES_TABLE_COLUMNS
    )
    clipboard = form.cc.QApplication.clipboard()
    before = clipboard.text()
    matches.setCurrentCell(0, 0)
    matches.customContextMenuRequested.emit(form.cc.QtCore.QPoint(0, 0))
    _check(
        sha256_column is None and clipboard.text() == before,
        "the block match context menu stays inert without a SHA256 column",
    )


################################################################################
# Export and YARA toolbar actions
################################################################################


def _exercise_export(form, qt_application):
    artifact_dir = _artifact_dir()
    export_path = (
        artifact_dir / "exported-smda.json"
        if artifact_dir is not None
        else Path(tempfile.gettempdir()) / "mcrit-ida-integration.smda"
    )
    form.cc.backend.ask_save_file = lambda default_name, prompt: str(export_path)
    try:
        form.main_widget.exportSmdaAction.trigger()
    finally:
        del form.cc.backend.ask_save_file
    _process_events(qt_application, rounds=2)
    _check(
        export_path.is_file() and export_path.stat().st_size > 0,
        "Export SMDA report wrote the report to the chosen path",
    )
    json.loads(export_path.read_text(encoding="utf-8"))
    _check(
        "exported to" in form.local_widget.label_mcrit_activity_info.text(),
        "Export SMDA report reports the path in the activity info",
    )
    if artifact_dir is None:
        export_path.unlink(missing_ok=True)


@contextmanager
def _ida_cursor(form, offset, size=1):
    import ida_kernwin

    original_screen_ea = ida_kernwin.get_screen_ea
    ida_kernwin.get_screen_ea = lambda: offset
    backend = form.cc.backend
    backend.get_selection = lambda: (offset, offset + size)
    try:
        yield
    finally:
        ida_kernwin.get_screen_ea = original_screen_ea
        del backend.get_selection


def _exercise_yara_action(form, report, second_target, qt_application):
    main_widget = form.main_widget
    clipboard = form.cc.QApplication.clipboard()
    instructions = list(second_target.getInstructions())
    _check(bool(instructions), "the queried function has instructions for the YARA builder")
    instruction = instructions[0]
    original_dialog = main_widget.YaraStringBuilderDialog
    created_dialogs = []

    class AutoAcceptYaraDialog(original_dialog):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created_dialogs.append(self)

        def exec_(self):
            _check(
                self.radio_function.isEnabled(),
                "YARA builder offers the current function as scope",
            )
            self.radio_selection.click()
            self.radio_block.click()
            self.radio_function.click()
            self.cb_wildcards.setChecked(False)
            self.copy_escaped_button.click()
            _check(
                bool(clipboard.text()) and " " in clipboard.text(),
                "Copy Escaped Bytes puts the instruction bytes on the clipboard",
            )
            self.cb_wildcards.setChecked(True)
            self.copy_yara_button.click()
            _check(
                clipboard.text().startswith("rule ") and "condition:" in clipboard.text(),
                "Copy YARA Rule puts a complete rule on the clipboard",
            )
            self.ok_button.click()
            return 1

    main_widget.YaraStringBuilderDialog = AutoAcceptYaraDialog
    try:
        with _ida_cursor(form, instruction.offset, size=len(instruction.bytes) // 2 or 1):
            main_widget.buildYaraStringAction.trigger()
    finally:
        main_widget.YaraStringBuilderDialog = original_dialog
    _process_events(qt_application)
    _check(bool(created_dialogs), "the YARA toolbar action created its dialog")
    _check(
        "rule " in created_dialogs[0].text_yara.toPlainText(),
        "the YARA dialog shows the generated rule",
    )
    _check(
        "YARA rule copied to clipboard" in form.local_widget.label_mcrit_activity_info.text(),
        "the YARA builder reports the copy in the activity info",
    )

    data_dialog = original_dialog(
        main_widget,
        data=b"\x90\x90",
        sha256=report.sha256,
        offset=instruction.offset,
        selection_start=instruction.offset,
        selection_end=instruction.offset + 2,
    )
    data_dialog.copy_escaped_button.click()
    data_dialog.copy_yara_button.click()
    _check(
        "rule " in data_dialog.text_yara.toPlainText(),
        "the YARA builder also works on a raw byte selection",
    )
    data_dialog.ok_button.click()
    _process_events(qt_application)


################################################################################
# plugin menu / hotkey action
################################################################################


def _exercise_plugin_action(form, module, plugmod):
    """IDA runs the plugin's Ctrl-F4 entry through the plugmod, not through a registered action."""
    requested = []
    original_show = module.show_mcrit_form
    module.show_mcrit_form = lambda: requested.append(True) or form
    try:
        _check(plugmod.run(0) is True, "the Ctrl-F4 plugin entry runs MCRIT4IDA")
    finally:
        module.show_mcrit_form = original_show
    _check(requested == [True], "the plugin entry opens the MCRIT4IDA form")
    _check(plugmod.form is form, "the plugin entry keeps the form it opened")
    plugmod.form = None


################################################################################
# close-time upload prompt
################################################################################


def _exercise_close_prompt(form, target):
    import ida_settings
    import ida_undo

    backend = form.cc.backend
    ida_settings.set_plugin_setting("mcrit-ida", "submit_function_names_on_close", True)
    _check(
        form.config.SUBMIT_FUNCTION_NAMES_ON_CLOSE,
        "submit_function_names_on_close is enabled for the close prompt",
    )
    backend.set_function_name(target.offset, "mcrit_integration_renamed")
    _check(
        bool(form.findUnsyncedFunctionNames()),
        "renaming a function makes the report look out of sync",
    )
    prompts = []
    uploads = []
    backend.ask_yes_no = lambda prompt: prompts.append(prompt) or True
    original_upload = form.mcrit_interface.uploadReport

    def capture_upload(report):
        uploads.append(report)
        return original_upload(report)

    form.mcrit_interface.uploadReport = capture_upload
    try:
        form.OnClose(None)
    finally:
        form.mcrit_interface.uploadReport = original_upload
        del backend.ask_yes_no
    _check(len(prompts) == 1, "closing the file asks once about the renamed functions")
    _check(
        "upload an updated report" in prompts[0].lower(),
        "the close prompt explains that the report is uploaded",
    )
    _check(len(uploads) == 1, "answering yes uploads the updated report")
    _check(
        any(
            function.function_name == "mcrit_integration_renamed"
            for function in uploads[0].getFunctions()
        ),
        "the uploaded report carries the new function name",
    )
    ida_undo.perform_undo()


def _exercise_live_mcrit(form, module, plugmod, qt_application):
    interface = form.mcrit_interface
    interface.checkConnection(async_=False)

    _check_input_sha256(form)
    _check_disabled_before_conversion(form)
    report = _convert(form, qt_application)
    _upload_and_match(form, report, qt_application)

    _exercise_overview_widget(form, qt_application)
    _exercise_sample_widget(form, qt_application)
    target, second_target = _exercise_navigation(form, report, qt_application)
    _exercise_function_widget(form, second_target, qt_application)
    _exercise_block_widget(form, second_target, qt_application)
    _exercise_export(form, qt_application)
    _exercise_yara_action(form, report, second_target, qt_application)
    _exercise_plugin_action(form, module, plugmod)
    _exercise_close_prompt(form, target)


def _exercise_offline_plugin(form, qt_application):
    main_widget = form.main_widget
    _check_disabled_before_conversion(form)
    with _smda_info_adapter(main_widget, family="offline-ci", version="no-server"):
        main_widget.parseSmdaAction.trigger()
    _process_events(qt_application, rounds=2)
    _check(form.local_smda_report is not None, "offline Convert action produced a report")
    _check(main_widget.exportSmdaAction.isEnabled(), "offline conversion enabled export")
    _exercise_export(form, qt_application)
    function = max(form.local_smda_report.getFunctions(), key=lambda item: item.num_instructions)
    _exercise_yara_action(form, form.local_smda_report, function, qt_application)


def main() -> int:
    form = None
    qt_application = None
    try:
        import ida_auto

        ida_auto.auto_wait()
        import ida_mcrit

        _plugin, plugmod = _run_plugin_lifecycle(ida_mcrit)
        form, qt_application = _create_form(ida_mcrit)
        _exercise_cursor_tracking(form, qt_application)
        ida_mcrit.MCRIT4IDA = form

        if _is_live():
            _exercise_live_mcrit(form, ida_mcrit, plugmod, qt_application)
        else:
            _exercise_offline_plugin(form, qt_application)
            form.OnClose(None)

        _release_qt_objects(form, qt_application)
        print("MCRIT_IDA_INTEGRATION_OK")
        _qexit(0)
        return 0
    except Exception as exc:
        print(f"MCRIT_IDA_INTEGRATION_FAILURE: {exc}")
        import traceback

        traceback.print_exc()
        try:
            if qt_application is not None:
                _release_qt_objects(form, qt_application)
            _qexit(1)
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
