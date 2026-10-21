"""Activity, server and local report information, the counterpart of the Qt LocalInfoWidget.

updateActivityInfo and updateServerInfo are called from worker threads by McritInterface; the
labels hand their updates to the event dispatch thread.
"""

import datetime

from mcrit_plugin.core.revision import core_revision
from mcrit_plugin.ghidra.ui.components import Label, grid, separator, stack


class LocalInfoPanel:
    def __init__(self, parent):
        self.parent = parent
        self.name = "LocalInfo"
        self.label_activity = Label("Activity Info: <PLACEHOLDER>")
        self.label_server = Label("MCRIT Remote server: <not_active>")
        self.label_remote_sample = Label("Remote sample: <unknown>")
        self.values = {}
        fields = [
            ("sha256", "SHA256: "),
            ("architecture", "Architecture: "),
            ("bitness", "Bitness: "),
            ("image_base", "ImageBase: "),
            ("functions", "Functions: "),
            ("instructions", "Instructions: "),
            ("size", "Code Size: "),
            ("family", "Family: "),
            ("version", "Version: "),
            ("library", "Library: "),
        ]
        pairs = []
        for key, title in fields:
            value = Label("no data", wrap=False)
            self.values[key] = value
            pairs.append((Label(title, wrap=False).component, value.component))
        self.component = stack(
            self.label_activity.component,
            self.label_server.component,
            self.label_remote_sample.component,
            separator(),
            grid(pairs),
        )
        self.updateActivityInfo(
            f"{parent.cc.backend.plugin_name} v{parent.config.VERSION} started "
            f"(core {core_revision()})."
        )

    @staticmethod
    def _instructionBytes(report):
        return sum(
            len(instruction.bytes) // 2
            for function in report.getFunctions()
            for instruction in function.getInstructions()
        )

    def update(self):
        report = self.parent.getLocalSmdaReport()
        if not report:
            return
        self.values["sha256"].setText(report.sha256)
        self.values["architecture"].setText(report.architecture)
        self.values["bitness"].setText("%d bit" % report.bitness)
        self.values["image_base"].setText("0x%x" % report.base_addr)
        self.values["functions"].setText(
            "%d (leaf: %d, recursive: %d)"
            % (
                report.num_functions,
                report.statistics.num_leaf_functions,
                report.statistics.num_recursive_functions,
            )
        )
        self.values["instructions"].setText("%d" % report.statistics.num_instructions)
        self.values["size"].setText("%d bytes" % self._instructionBytes(report))
        self.values["family"].setText(report.family or "")
        self.values["version"].setText(report.version or "")
        self.values["library"].setText("YES" if report.is_library else "NO")
        remote = self.parent.remote_sample_entry
        if remote:
            self.label_remote_sample.setText(
                "Remote sample: %s (%s -- %s)" % (remote.sample_id, remote.family, remote.version)
            )

    def updateActivityInfo(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.label_activity.setText("Activity Info: %s - %s" % (timestamp, message))

    def updateServerInfo(self, mcrit_server, version=None, statistics=None):
        version_text = version if version is not None else "No connection"
        if statistics:
            status_text = "Content: %d families, %d samples, %d functions." % (
                statistics["num_families"],
                statistics["num_samples"],
                statistics["num_functions"],
            )
        else:
            status_text = "No statistics"
        self.label_server.setText(
            "Remote server: %s  -- %s -- %s." % (mcrit_server, version_text, status_text)
        )
