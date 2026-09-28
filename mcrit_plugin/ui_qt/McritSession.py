import time


class McritSession:
    """State shared by all MCRIT widgets for one analyzed binary, independent of the disassembler.

    Widgets receive the session as their ``parent`` and read/write the attributes below.
    Qt and the widget modules are imported lazily so headless loaders can import this module.
    """

    def __init__(self, backend, config):
        import mcrit_plugin.ui_qt.QtShim as QtShim
        from mcrit_plugin.core.McritInterface import McritInterface
        from mcrit_plugin.ui_qt.ClassCollection import ClassCollection

        self.cc = ClassCollection(QtShim, backend)
        self.config = config
        self.tabs = None
        self.parent = None
        #### local state used to populate and exchange information across widgets
        self.remote_sample_id = None
        self.remote_sample_entry = None
        self.local_smda_report = None
        # the smda_report without xcfg part, rebuilt whenever the report is replaced
        self.local_smda_report_outline = None
        self._outline_source = None
        # after selecting a finished remote job, this is the cached data
        self.matching_job_id = None
        self.matching_report = None
        self.matched_function_entries = None
        # cached function matches that result from Function Scope queries
        self.current_block = None
        self.current_function = None
        self.function_matches = {}
        # offset to PicBlockHash
        self.block_to_hash = {}
        # PicBlockHash to matches from remote server
        self.blockhash_matches = {}
        # unused
        self.remote_function_mapping = {}
        self.sample_infos = {}
        self.family_infos = None
        self.function_id_to_offset = {}
        self.pichash_matches = {}
        self.pichash_match_summaries = {}
        self.picblockhash_matches = {}
        self.icon = self.cc.QIcon(config.ICON_FILE_PATH + "relationship.png")
        self.mcrit_interface = McritInterface(self, backend)
        self.hook_subscribed_widgets = []

    def copyStringToClipboard(self, string_to_copy: str):
        if string_to_copy is not None:
            self.cc.QApplication.clipboard().setText(string_to_copy)
            print('Copied "%s" to clipboard.' % string_to_copy)

    def getMatchingReport(self):
        return self.matching_report

    def getSampleInfos(self):
        return self.sample_infos

    def getFunctionInfos(self):
        return self.remote_function_mapping

    def getLocalSmdaReport(self):
        return self.local_smda_report

    def getLocalSmdaReportOutline(self):
        """A fresh copy of the local report without functions; SmdaReport caches getFunctions(), so one
        outline must not be reused with a different xcfg."""
        from smda.common.SmdaReport import SmdaReport

        if self.local_smda_report is None:
            return None
        if self._outline_source is not self.local_smda_report:
            self._outline_source = self.local_smda_report
            self.local_smda_report_outline = self.local_smda_report.toDict()
            self.local_smda_report_outline["xcfg"] = {}
        return SmdaReport.fromDict(dict(self.local_smda_report_outline))

    def getRemoteSampleInformation(self):
        """Download family/sample meta data; callable off the UI thread, so it touches no widget."""
        time_before = time.time()
        print("[/] starting download of meta data from MCRIT...")
        self.mcrit_interface.queryAllFamilyEntries()
        print("[|] downloaded FamilyEntries!")
        self.mcrit_interface.queryAllSampleEntries()
        print("[|] downloaded SampleEntries!")
        print("[\\] this took %3.2f seconds.\n" % (time.time() - time_before))

    def setupWidgets(self):
        """Create the widgets and lay them out inside ``self.parent``."""
        from mcrit_plugin.ui_qt.widgets.BlockMatchWidget import BlockMatchWidget
        from mcrit_plugin.ui_qt.widgets.FunctionMatchWidget import FunctionMatchWidget
        from mcrit_plugin.ui_qt.widgets.FunctionOverviewWidget import FunctionOverviewWidget
        from mcrit_plugin.ui_qt.widgets.LocalInfoWidget import LocalInfoWidget
        from mcrit_plugin.ui_qt.widgets.MainWidget import MainWidget
        from mcrit_plugin.ui_qt.widgets.SampleInfoWidget import SampleInfoWidget

        time_before = time.time()
        print("[/] setting up widgets...")
        self.local_widget = LocalInfoWidget(self)
        self.block_match_widget = BlockMatchWidget(self)
        self.function_match_widget = FunctionMatchWidget(self)
        self.sample_widget = SampleInfoWidget(self)
        self.function_widget = FunctionOverviewWidget(self)
        self.main_widget = MainWidget(self)
        self.hook_subscribed_widgets.append(self.function_match_widget)
        self.hook_subscribed_widgets.append(self.block_match_widget)
        layout = self.cc.QVBoxLayout()
        layout.addWidget(self.main_widget)
        self.parent.setLayout(layout)
        print("[\\] this took %3.2f seconds.\n" % (time.time() - time_before))

    def refreshCursorWidgets(self, view=None):
        for widget in self.hook_subscribed_widgets:
            widget.hook_refresh(view)

    def findUnsyncedFunctionNames(self):
        """(offset, name in local SMDA report, current name) for functions renamed since conversion."""
        if self.local_smda_report is None:
            return []
        current_names = self.cc.backend.get_function_symbols()
        report_names = {
            func.offset: func.function_name
            for func in self.local_smda_report.getFunctions()
            if func.function_name
        }
        unsynced = []
        for offset, current_name in current_names.items():
            report_name = report_names.get(offset, None)
            if report_name is not None and report_name != current_name:
                unsynced.append((offset, report_name, current_name))
            if offset not in report_names:
                unsynced.append((offset, None, current_name))
        return unsynced

    def uploadUpdatedReport(self):
        """Patch the current function names into the local report and upload it, without re-exporting."""
        functions = {func.offset: func for func in self.local_smda_report.getFunctions()}
        for offset, _report_name, current_name in self.findUnsyncedFunctionNames():
            if offset in functions:
                functions[offset].function_name = current_name
        self.mcrit_interface.uploadReport(self.local_smda_report)
