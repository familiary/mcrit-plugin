import json
import os

import mcrit_plugin.ui_qt.QtShim as QtShim
from mcrit_plugin.ui_qt.widgets.ResultChooserDialog import ResultChooserDialog
from mcrit_plugin.ui_qt.widgets.SmdaInfoDialog import SmdaInfoDialog
from mcrit_plugin.ui_qt.widgets.YaraStringBuilderDialog import YaraStringBuilderDialog

QMainWindow = QtShim.get_QMainWindow()


class MainWidget(QMainWindow):
    def __init__(self, parent):
        self.cc = parent.cc
        self.cc.QMainWindow.__init__(self)
        print("[|] loading MainWidget")
        # enable access to shared MCRIT4IDA modules
        self.parent = parent
        self.name = "Main"
        self.icon = self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "mcrit.png")
        self.tabs = None
        self._building = False
        self.tabbed_widgets = [
            self.parent.block_match_widget,
            self.parent.function_match_widget,
            self.parent.function_widget,
            self.parent.sample_widget,
        ]
        self.central_widget = self.cc.QWidget()
        self.setCentralWidget(self.central_widget)
        self.SmdaInfoDialog = SmdaInfoDialog
        self.ResultChooserDialog = ResultChooserDialog
        self.YaraStringBuilderDialog = YaraStringBuilderDialog
        self._createGui()
        self.parent.mcrit_interface.checkConnection(async_=True)
        # IDA 6.x Windows workaronud to avoid lost imports
        self.os = os
        self.os_path = os.path

    def _createGui(self):
        """
        Setup function for the full GUI of this widget.
        """
        # create the main toolbar
        self._createToolbar()
        # layout and fill the widget
        self.tabs = self.cc.QTabWidget()
        self.tabs.setTabsClosable(False)
        for widget in self.tabbed_widgets:
            self.tabs.addTab(widget, widget.icon, widget.name)
        layout = self.cc.QVBoxLayout()
        self.splitter = self.cc.QSplitter(self.cc.QtCore.Qt.Vertical)
        q_clean_style = self.cc.QStyleFactory.create("Plastique")
        self.splitter.setStyle(q_clean_style)
        self.splitter.addWidget(self.parent.local_widget)
        self.splitter.addWidget(self.tabs)
        self.splitter.setStretchFactor(1, 10)
        layout.addWidget(self.splitter)
        self.central_widget.setLayout(layout)
        self.setTabFocus(self.parent.sample_widget.name)

    def _createToolbar(self):
        """
        Creates the toolbar, containing buttons to control the widget.
        """
        # TODO for MCRIT 1.0.0 release, we hide the other buttons until they are properly developed
        self.toolbar = self.addToolBar(self.cc.backend.plugin_name + " Toolbar")
        self._createParseSmdaAction()
        self.toolbar.addAction(self.parseSmdaAction)
        self._createUploadSmdaAction()
        self.toolbar.addAction(self.uploadSmdaAction)
        self._createGetMatchResultAction()
        self.toolbar.addAction(self.getMatchResultAction)
        self._createExportSmdaAction()
        self.toolbar.addAction(self.exportSmdaAction)
        self._createBuildYaraStringAction()
        self.toolbar.addAction(self.buildYaraStringAction)

    def _createParseSmdaAction(self):
        """
        Create an action for parsing the IDB into a SMDA report.
        """
        self.parseSmdaAction = self.cc.QAction(
            self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "fingerprint_scan.png"),
            "Convert this database to a SMDA report which can then be used to query MCRIT.",
            self,
        )
        self.parseSmdaAction.triggered.connect(self._onConvertSmdaButtonClicked)

    def _createUploadSmdaAction(self):
        """
        Create an action for uploading the parsed SMDA report to the server.
        TODO: will require addition of some more meta data.
        """
        self.uploadSmdaAction = self.cc.QAction(
            self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "cloud-upload.png"),
            "Reparse and upload the SMDA report to the MCRIT server.",
            self,
        )
        self.uploadSmdaAction.setEnabled(False)
        self.uploadSmdaAction.triggered.connect(self._onUploadSmdaButtonClicked)

    def _createGetMatchResultAction(self):
        """
        Create an action for requesting a MatchReport for the given remote sample
        """
        self.getMatchResultAction = self.cc.QAction(
            self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "satellite_dish.png"),
            "Request the MatchResult for the uploaded sample.",
            self,
        )
        self.getMatchResultAction.setEnabled(False)
        self.getMatchResultAction.triggered.connect(self._onGetMatchResultButtonClicked)

    def _createExportSmdaAction(self):
        """
        Create an action for exporting the parsed SMDA report into json/smda format.
        """
        self.exportSmdaAction = self.cc.QAction(
            self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "export.png"),
            "Export the SMDA report to local disk.",
            self,
        )
        self.exportSmdaAction.setEnabled(False)
        self.exportSmdaAction.triggered.connect(self._onExportSmdaButtonClicked)

    def _createBuildYaraStringAction(self):
        """
        Create an action for building a YARA string from the current selection.
        """
        self.buildYaraStringAction = self.cc.QAction(
            self.cc.QIcon(self.parent.config.ICON_FILE_PATH + "yara.png"),
            "Build a YARA string from the current selection.",
            self,
        )
        self.buildYaraStringAction.setEnabled(False)
        self.buildYaraStringAction.triggered.connect(self._onBuildYaraStringButtonClicked)

    def getLocalSmdaReport(self):
        backend_converted_report = self.parent.mcrit_interface.convertToSmda()
        local_report = backend_converted_report
        # check of we alternatively want to use SMDA for analysis
        smda_converted_report = None
        if self.parent.config.USE_SMDA_FOR_ANALYSIS:
            smda_converted_report = self.parent.mcrit_interface.convertToSmdaUsingSmda()
        if smda_converted_report is not None:
            backend_report_offsets = [
                func.offset for func in backend_converted_report.getFunctions()
            ]
            smda_report_offsets = [func.offset for func in smda_converted_report.getFunctions()]
            # output diagnostic information if function sets differ
            if set(backend_report_offsets) != set(smda_report_offsets):
                print(
                    f"[!] SMDA disassembly report function set ({len(smda_report_offsets)}) differs from {self.cc.backend.name} converted report function set ({len(backend_report_offsets)})!"
                )
                missing_in_smda = set(backend_report_offsets) - set(smda_report_offsets)
                missing_in_backend = set(smda_report_offsets) - set(backend_report_offsets)
                if missing_in_smda:
                    print(
                        "    Functions in %s but not in SMDA report (%d): %s"
                        % (
                            self.cc.backend.name,
                            len(missing_in_smda),
                            ", ".join([f"0x{off:x}" for off in missing_in_smda]),
                        )
                    )
                if missing_in_backend:
                    print(
                        "    Functions in SMDA but not in %s report (%d): %s"
                        % (
                            self.cc.backend.name,
                            len(missing_in_backend),
                            ", ".join([f"0x{off:x}" for off in missing_in_backend]),
                        )
                    )
                print("    Using SMDA converted report.")
            else:
                print(
                    f"[|] SMDA converted report function set matches {self.cc.backend.name} converted report function set."
                )
            local_report = smda_converted_report
        if local_report is not None:
            local_report.sha256 = self.cc.backend.get_input_sha256()
            local_report.filename = self.cc.backend.get_input_filename()
            local_report.buffer_size = self.cc.backend.get_input_size()
            local_report.smda_version = "%s v%s via SMDA %s" % (
                self.cc.backend.plugin_name,
                self.parent.config.VERSION,
                local_report.smda_version,
            )
            # if yes, use information from it
            if self.parent.remote_sample_entry is not None:
                local_report.family = self.parent.remote_sample_entry.family
                local_report.version = self.parent.remote_sample_entry.version
                local_report.is_library = self.parent.remote_sample_entry.is_library
        return local_report

    def _onBuildYaraStringButtonClicked(self):
        selection_start, selection_end = self.cc.backend.get_selection()
        has_selection = (
            selection_start is not None
            and selection_end is not None
            and selection_start != selection_end
        )

        # fetch instruction, block, and function information based on current cursor position
        current_ea = self.cc.backend.get_cursor_address()
        current_function = self.parent.local_smda_report.findFunctionByContainedAddress(current_ea)
        current_block = self.parent.local_smda_report.findBlockByContainedAddress(current_ea)

        # for sequences of instructions, we need to emulate the procedure from SmdaFunction
        # this will allow us to correlate the individual escaped instructions with their disassembly representation
        selected_ins_sequence = []
        if has_selection:
            for smda_function in self.parent.local_smda_report.getFunctions():
                for smda_instruction in smda_function.getInstructions():
                    if (
                        smda_instruction.offset >= selection_start
                        and smda_instruction.offset < selection_end
                    ):
                        selected_ins_sequence.append(smda_instruction)
            selected_ins_sequence.sort(key=lambda ins: ins.offset)
        else:
            # If no selection, use single instruction at cursor
            for smda_function in self.parent.local_smda_report.getFunctions():
                for smda_instruction in smda_function.getInstructions():
                    if smda_instruction.offset == current_ea:
                        selected_ins_sequence = [smda_instruction]
                        break
                if selected_ins_sequence:
                    break
        functions_ins_sequence = (
            list(current_function.getInstructions()) if current_function else None
        )
        blocks_ins_sequence = list(current_block.getInstructions()) if current_block else None

        data_bytes = b""
        if not selected_ins_sequence and has_selection:
            data_bytes = self.cc.backend.read_bytes(
                selection_start, selection_end - selection_start
            )
        # Create and show the dialog
        dialog = self.YaraStringBuilderDialog(
            self,
            data=data_bytes,
            selection_sequence=selected_ins_sequence if selected_ins_sequence else None,
            block_sequence=blocks_ins_sequence,
            function_sequence=functions_ins_sequence,
            sha256=self.parent.local_smda_report.sha256 if self.parent.local_smda_report else "",
            offset=current_ea,
            selection_start=selection_start or current_ea,
            selection_end=selection_end or current_ea,
        )
        dialog.exec_()

    def _buildLocalSmdaReport(self, on_ready, work=None):
        """Run work off the UI thread where supported, then call on_ready(report) on the UI thread."""
        if self._building:
            return
        self._building = True

        def build():
            try:
                return (work or self.getLocalSmdaReport)()
            except Exception:
                self._building = False
                raise

        def done(report):
            self._building = False
            on_ready(report)

        self.cc.backend.run_background("MCRIT: exporting SMDA report", build, done)

    def _onConvertSmdaButtonClicked(self):
        self._buildLocalSmdaReport(self._applyConvertedReport, self._convertAndFetchRemote)

    def _convertAndFetchRemote(self):
        local_smda_report = self.getLocalSmdaReport()
        if self.parent.local_smda_report is None:
            self.parent.getRemoteSampleInformation()
        return local_smda_report

    def _applyConvertedReport(self, local_smda_report):
        if self.parent.local_smda_report is None:
            self.parent.local_smda_report = local_smda_report
            self.parent.local_widget.updateActivityInfo(
                "Downloaded all family/sample information from MCRIT"
            )
        if self.parent.local_smda_report is not None:
            self.exportSmdaAction.setEnabled(True)
            self.uploadSmdaAction.setEnabled(True)
            self.buildYaraStringAction.setEnabled(True)
            # check if remote sample exists
            self.parent.mcrit_interface.querySampleSha256(self.parent.local_smda_report.sha256)
            # if yes, enable matching and use meta data
            if self.parent.remote_sample_entry is not None:
                self.getMatchResultAction.setEnabled(True)
                self.parent.local_smda_report.family = self.parent.remote_sample_entry.family
                self.parent.local_smda_report.version = self.parent.remote_sample_entry.version
                self.parent.local_smda_report.is_library = (
                    self.parent.remote_sample_entry.is_library
                )
            # else query for family, version, library instead
            else:
                dialog = self.SmdaInfoDialog(self)
                dialog.exec_()
                smda_info = dialog.getSmdaInfo()
                self.parent.local_smda_report.family = smda_info["family"]
                self.parent.local_smda_report.version = smda_info["version"]
                self.parent.local_smda_report.is_library = smda_info["is_library"]
            self.parent.block_match_widget.enable()
            self.parent.function_match_widget.enable()
        self.parent.local_widget.update()

    def _onExportSmdaButtonClicked(self):
        self._buildLocalSmdaReport(self._exportReport)

    def _exportReport(self, updated_report):
        # save metadata before upload to not overwrite it
        local_family = self.parent.local_smda_report.family if self.parent.local_smda_report else ""
        local_version = (
            self.parent.local_smda_report.version if self.parent.local_smda_report else ""
        )
        local_library = (
            self.parent.local_smda_report.is_library if self.parent.local_smda_report else False
        )
        self.parent.local_smda_report = updated_report
        self.parent.local_smda_report.family = local_family
        self.parent.local_smda_report.version = local_version
        self.parent.local_smda_report.is_library = local_library
        if self.parent.local_smda_report:
            filepath = self.cc.backend.ask_save_file(
                self.parent.local_smda_report.filename + ".smda", "Export SMDA report to file..."
            )
            if filepath:
                with open(filepath, "w") as fout:
                    json.dump(
                        self.parent.local_smda_report.toDict(), fout, indent=1, sort_keys=True
                    )
                self.parent.local_widget.updateActivityInfo(
                    'SMDA report exported to: "%s".' % filepath
                )
            else:
                self.parent.local_widget.updateActivityInfo("Export aborted.")
        else:
            self.parent.local_widget.updateActivityInfo(
                "Database is not converted to SMDA report yet, can't export."
            )

    def _onUploadSmdaButtonClicked(self):
        self._buildLocalSmdaReport(self._uploadReport)

    def _uploadReport(self, updated_report):
        # save metadata before upload to not overwrite it
        local_family = self.parent.local_smda_report.family if self.parent.local_smda_report else ""
        local_version = (
            self.parent.local_smda_report.version if self.parent.local_smda_report else ""
        )
        local_library = (
            self.parent.local_smda_report.is_library if self.parent.local_smda_report else False
        )
        self.parent.local_smda_report = updated_report
        self.parent.local_smda_report.family = local_family
        self.parent.local_smda_report.version = local_version
        self.parent.local_smda_report.is_library = local_library
        if self.parent.local_smda_report:
            self.parent.mcrit_interface.uploadReport(self.parent.local_smda_report)
            # check if remote sample exists
            if self.parent.remote_sample_id is not None:
                self.getMatchResultAction.setEnabled(True)
        else:
            self.parent.local_widget.updateActivityInfo(
                "Database is not converted to SMDA report yet, can't upload."
            )

    def _onGetMatchResultButtonClicked(self):
        if self.parent.remote_sample_id is not None:
            # fetch jobs
            jobs = self.parent.mcrit_interface.queryJobs(sample_id=self.parent.remote_sample_id)
            # check which job the user wants to use as reference
            dialog = self.ResultChooserDialog(self, job_infos=jobs)
            dialog.exec_()
            dialog_result = dialog.getResultChosen()
            # if user wants to request a new matching, schedule it via client
            if dialog_result["is_requesting_matching_job"]:
                self.parent.mcrit_interface.requestMatchingJob(
                    self.parent.remote_sample_id, force_update=True
                )
            # if otherwise a job was finished and a job_id selected, fetch the data
            elif dialog_result["selected_job_id"]:
                # we already have this matching data, so we can skip and save time
                if (
                    self.parent.matching_job_id is not None
                    and self.parent.matching_job_id == dialog_result["selected_job_id"]
                ):
                    pass
                else:
                    self.parent.mcrit_interface.getMatchingJobById(dialog_result["selected_job_id"])
                self.setTabFocus(self.parent.function_widget.name)
                self.hideLocalWidget()
            self.parent.function_widget.update()
            self.parent.sample_widget.update()
            if self.parent.config.OVERVIEW_FETCH_LABELS_AUTOMATICALLY:
                self.parent.function_widget.fetchLabels()
            return
        else:
            self.parent.local_widget.updateActivityInfo(
                "No remote Sample present yet, can't request a matching or query results."
            )

    def hideLocalWidget(self):
        self.splitter.setSizes([0, 1])

    def setTabFocus(self, widget_name):
        """
        Can be used by MCRIT4IDA widgets to set focus to a widget, identified by name.
        @param widget_name: A widget name
        @type widget_name: str
        """
        for widget in self.tabbed_widgets:
            if widget.name == widget_name:
                tab_index = self.tabs.indexOf(widget)
                self.tabs.setCurrentIndex(tab_index)
        return
