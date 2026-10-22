"""Toolbar, status area and tabs of the Ghidra frontend, the counterpart of the Qt MainWidget.

The flows (convert, upload, fetch a matching result, export, YARA) follow MainWidget step by step;
the dialogs they open are in dialogs.py.
"""

import json

from mcrit_plugin.ghidra.ui.components import button, load_icon, scrolling_tabs
from mcrit_plugin.ghidra.ui.dialogs import (
    ResultChooserDialog,
    SmdaInfoDialog,
    YaraStringBuilderDialog,
)


class MainPanel:
    def __init__(self, parent):
        from java.awt import BorderLayout
        from javax.swing import JPanel, JSplitPane, JToolBar

        self.parent = parent
        self.cc = parent.cc
        self.name = "Main"
        self._building = False
        self.tabbed_widgets = [
            parent.block_match_widget,
            parent.function_match_widget,
            parent.function_widget,
            parent.sample_widget,
        ]
        icons = parent.config.ICON_FILE_PATH
        self.toolbar = JToolBar()
        self.toolbar.setFloatable(False)

        def tool(icon, tooltip, handler, enabled):
            widget = button(
                "",
                handler,
                enabled=enabled,
                icon=load_icon(icons + icon, 24),
                tooltip=tooltip,
            )
            self.toolbar.add(widget)
            return widget

        self.parseSmdaAction = tool(
            "fingerprint_scan.png",
            "Convert this program to a SMDA report which can then be used to query MCRIT.",
            self._onConvertSmdaButtonClicked,
            True,
        )
        self.uploadSmdaAction = tool(
            "cloud-upload.png",
            "Reparse and upload the SMDA report to the MCRIT server.",
            self._onUploadSmdaButtonClicked,
            False,
        )
        self.getMatchResultAction = tool(
            "satellite_dish.png",
            "Request the MatchResult for the uploaded sample.",
            self._onGetMatchResultButtonClicked,
            False,
        )
        self.exportSmdaAction = tool(
            "export.png",
            "Export the SMDA report to local disk.",
            self._onExportSmdaButtonClicked,
            False,
        )
        self.buildYaraStringAction = tool(
            "yara.png",
            "Build a YARA string from the current selection.",
            self._onBuildYaraStringButtonClicked,
            False,
        )
        self.tabs = scrolling_tabs()
        for widget in self.tabbed_widgets:
            self.tabs.addTab(widget.name, load_icon(icons + widget.icon_file, 16), widget.component)
        self.splitter = JSplitPane(
            JSplitPane.VERTICAL_SPLIT, parent.local_widget.component, self.tabs
        )
        self.splitter.setResizeWeight(0.1)
        self.splitter.setOneTouchExpandable(True)
        self.component = JPanel(BorderLayout())
        self.component.add(self.toolbar, BorderLayout.NORTH)
        self.component.add(self.splitter, BorderLayout.CENTER)
        self.setTabFocus(parent.sample_widget.name)
        parent.mcrit_interface.checkConnection(async_=True)

    # report building

    def getLocalSmdaReport(self):
        backend = self.cc.backend
        local_report = None
        if self.parent.config.USE_SMDA_FOR_ANALYSIS:
            local_report = self.parent.mcrit_interface.convertToSmdaUsingSmda()
            if local_report is not None:
                self._printFunctionSetDifference(local_report)
        if local_report is None:
            local_report = self.parent.mcrit_interface.convertToSmda()
        if local_report is not None:
            local_report.sha256 = backend.get_input_sha256()
            local_report.filename = backend.get_input_filename()
            local_report.buffer_size = backend.get_input_size()
            local_report.smda_version = "%s v%s via SMDA %s" % (
                backend.plugin_name,
                self.parent.config.VERSION,
                local_report.smda_version,
            )
            remote = self.parent.remote_sample_entry
            if remote is not None:
                local_report.family = remote.family
                local_report.version = remote.version
                local_report.is_library = remote.is_library
        return local_report

    def _printFunctionSetDifference(self, smda_report):
        backend_name = self.cc.backend.name
        backend_offsets = set(self.cc.backend.get_function_offsets())
        smda_offsets = {function.offset for function in smda_report.getFunctions()}
        if backend_offsets == smda_offsets:
            print(f"[MCRIT] SMDA report function set matches the {backend_name} function set.")
            return
        print(
            f"[MCRIT] SMDA report function set ({len(smda_offsets)}) differs from the "
            f"{backend_name} function set ({len(backend_offsets)}); using the SMDA report."
        )
        for label, missing in (
            (f"in {backend_name} but not in SMDA report", backend_offsets - smda_offsets),
            (f"in SMDA but not in {backend_name} report", smda_offsets - backend_offsets),
        ):
            if missing:
                offsets = ", ".join(f"0x{offset:x}" for offset in sorted(missing))
                print(f"    Functions {label} ({len(missing)}): {offsets}")

    def _buildLocalSmdaReport(self, on_ready):
        if self._building:
            self.parent.local_widget.updateActivityInfo(
                "An SMDA report is still being built; try again when it is done."
            )
            return
        self._building = True

        def build():
            try:
                return self.getLocalSmdaReport()
            except Exception:
                self._building = False
                raise

        def done(report):
            self._building = False
            on_ready(report)

        self.cc.backend.run_background("MCRIT: exporting SMDA report", build, done)

    # convert

    def _onConvertSmdaButtonClicked(self):
        self._buildLocalSmdaReport(self._lookUpConvertedSample)

    def _lookUpConvertedSample(self, local_smda_report):
        if local_smda_report is None:
            self._applyConvertedReport(None)
            return
        self._building = True

        def done(_result):
            self._building = False
            self._applyConvertedReport(local_smda_report)

        self.cc.backend.run_request(
            "MCRIT: looking up the converted sample",
            lambda: self.parent.mcrit_interface.querySampleSha256(local_smda_report.sha256),
            done,
        )

    def _applyConvertedReport(self, local_smda_report):
        first_conversion = self.parent.local_smda_report is None
        if first_conversion:
            self.parent.local_smda_report = local_smda_report
        if first_conversion and (
            self.parent.local_smda_report is None or self.parent.remote_sample_entry is not None
        ):
            self.cc.backend.run_request(
                "MCRIT: downloading family and sample lists",
                self.parent.getRemoteSampleInformation,
                lambda _result: self.parent.local_widget.updateActivityInfo(
                    "Downloaded all family/sample information from MCRIT"
                ),
            )
        report = self.parent.local_smda_report
        if report is not None:
            self.exportSmdaAction.setEnabled(True)
            self.uploadSmdaAction.setEnabled(True)
            self.buildYaraStringAction.setEnabled(True)
            remote = self.parent.remote_sample_entry
            if remote is not None:
                self.getMatchResultAction.setEnabled(True)
                report.family = remote.family
                report.version = remote.version
                report.is_library = remote.is_library
            else:
                self._building = True
                self.cc.backend.run_request(
                    "MCRIT: downloading family and sample lists",
                    self._downloadListsForChooser,
                    lambda _result: self._askSmdaInfo(),
                )
                return
            self._enableMatchWidgets()
        self.parent.local_widget.update()

    def _downloadListsForChooser(self):
        try:
            return self.parent.getRemoteSampleInformation()
        except Exception:
            self._building = False
            raise

    def _askSmdaInfo(self):
        dialog = SmdaInfoDialog(self)
        dialog.exec_()
        self._building = False
        smda_info = dialog.getSmdaInfo()
        report = self.parent.local_smda_report
        report.family = smda_info["family"]
        report.version = smda_info["version"]
        report.is_library = smda_info["is_library"]
        self._enableMatchWidgets()
        self.parent.local_widget.update()

    def _enableMatchWidgets(self):
        self.parent.block_match_widget.enable()
        self.parent.function_match_widget.enable()

    # export and upload

    def _keepMetadata(self, updated_report):
        """Swap in a re-exported report, keeping the family, version and library flag."""
        current = self.parent.local_smda_report
        family = current.family if current else ""
        version = current.version if current else ""
        is_library = current.is_library if current else False
        self.parent.local_smda_report = updated_report
        if updated_report is not None:
            updated_report.family = family
            updated_report.version = version
            updated_report.is_library = is_library
        return updated_report

    def _onExportSmdaButtonClicked(self):
        self._buildLocalSmdaReport(self._exportReport)

    def _exportReport(self, updated_report):
        report = self._keepMetadata(updated_report)
        if not report:
            self.parent.local_widget.updateActivityInfo(
                "Program is not converted to SMDA report yet, can't export."
            )
            return
        filepath = self.cc.backend.ask_save_file(report.filename + ".smda", "Export SMDA report")
        if filepath:
            with open(filepath, "w") as fout:
                json.dump(report.toDict(), fout, indent=1, sort_keys=True)
            self.parent.local_widget.updateActivityInfo('SMDA report exported to: "%s".' % filepath)
        else:
            self.parent.local_widget.updateActivityInfo("Export aborted.")

    def _onUploadSmdaButtonClicked(self):
        self._buildLocalSmdaReport(self._uploadReport)

    def _uploadReport(self, updated_report):
        report = self._keepMetadata(updated_report)
        if not report:
            self.parent.local_widget.updateActivityInfo(
                "Program is not converted to SMDA report yet, can't upload."
            )
            return
        self.uploadSmdaAction.setEnabled(False)
        self.cc.backend.run_request(
            "MCRIT: uploading the SMDA report",
            lambda: self.parent.mcrit_interface.uploadReport(report),
            self._afterUpload,
        )

    def _afterUpload(self, _result):
        self.uploadSmdaAction.setEnabled(True)
        if self.parent.remote_sample_id is not None:
            self.getMatchResultAction.setEnabled(True)
        self.parent.local_widget.update()

    # matching results

    def _onGetMatchResultButtonClicked(self):
        sample_id = self.parent.remote_sample_id
        if sample_id is None:
            self.parent.local_widget.updateActivityInfo(
                "No remote Sample present yet, can't request a matching or query results."
            )
            return
        self.getMatchResultAction.setEnabled(False)
        self.cc.backend.run_request(
            "MCRIT: fetching matching jobs",
            lambda: self.parent.mcrit_interface.queryJobs(sample_id=sample_id),
            lambda jobs: self._chooseMatchingJob(sample_id, jobs),
        )

    def _chooseMatchingJob(self, sample_id, jobs):
        if jobs is None:
            self.getMatchResultAction.setEnabled(True)
            return
        dialog = ResultChooserDialog(self, job_infos=jobs)
        dialog.exec_()
        result = dialog.getResultChosen()
        selected_job_id = result["selected_job_id"]
        if result["is_requesting_matching_job"]:
            self.cc.backend.run_request(
                "MCRIT: requesting a matching job",
                lambda: self.parent.mcrit_interface.requestMatchingJob(
                    sample_id, force_update=True
                ),
                lambda _job_id: self._showMatchingResult(False),
            )
        elif selected_job_id:
            if self.parent.matching_job_id is not None and (
                self.parent.matching_job_id == selected_job_id
            ):
                self._showMatchingResult(True)
            else:
                self.cc.backend.run_request(
                    "MCRIT: downloading the matching result",
                    lambda: self.parent.mcrit_interface.getMatchingJobById(selected_job_id),
                    lambda _result: self._showMatchingResult(True),
                )
        else:
            self._showMatchingResult(False)

    def _showMatchingResult(self, focus_overview):
        self.getMatchResultAction.setEnabled(True)
        if focus_overview:
            self.setTabFocus(self.parent.function_widget.name)
            self.hideLocalWidget()
        self.parent.function_widget.update()
        self.parent.sample_widget.update()
        if self.parent.config.OVERVIEW_FETCH_LABELS_AUTOMATICALLY:
            self.parent.function_widget.fetchLabels()

    # YARA

    def _onBuildYaraStringButtonClicked(self):
        report = self.parent.local_smda_report
        if report is None:
            return
        selection_start, selection_end = self.cc.backend.get_selection()
        has_selection = (
            selection_start is not None
            and selection_end is not None
            and selection_start != selection_end
        )
        current_ea = self.cc.backend.get_cursor_address()
        if current_ea is None:
            self.parent.local_widget.updateActivityInfo("Place the cursor in the listing first.")
            return
        current_function = report.findFunctionByContainedAddress(current_ea)
        current_block = report.findBlockByContainedAddress(current_ea)
        selected = []
        if has_selection:
            for smda_function in report.getFunctions():
                for instruction in smda_function.getInstructions():
                    if selection_start <= instruction.offset < selection_end:
                        selected.append(instruction)
            selected.sort(key=lambda instruction: instruction.offset)
        elif current_function is not None:
            selected = [
                instruction
                for instruction in current_function.getInstructions()
                if instruction.offset == current_ea
            ][:1]
        data_bytes = b""
        if not selected and has_selection:
            data_bytes = self.cc.backend.read_bytes(
                selection_start, selection_end - selection_start
            )
        dialog = YaraStringBuilderDialog(
            self,
            data=data_bytes,
            selection_sequence=selected or None,
            block_sequence=list(current_block.getInstructions()) if current_block else None,
            function_sequence=(
                list(current_function.getInstructions()) if current_function else None
            ),
            sha256=report.sha256 or "",
            offset=current_ea,
            selection_start=selection_start or current_ea,
            selection_end=selection_end or current_ea,
        )
        dialog.exec_()

    # layout

    def hideLocalWidget(self):
        self.splitter.setDividerLocation(0)

    def setTabFocus(self, widget_name):
        for index, widget in enumerate(self.tabbed_widgets):
            if widget.name == widget_name:
                self.tabs.setSelectedIndex(index)
