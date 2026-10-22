"""Modal dialogs of the Ghidra frontend, counterparts of SmdaInfoDialog, ResultChooserDialog and
YaraStringBuilderDialog. Each has exec_() like its Qt counterpart; it blocks while the dialog is
open, with Swing still processing events."""

from mcrit_plugin.core.presentation import (
    build_yara_rule,
    escaped_hex_string,
    format_data_bytes,
    format_hex_lines,
)
from mcrit_plugin.core.ScoreColorProvider import ScoreColorProvider, ThemeRole
from mcrit_plugin.ghidra import swing
from mcrit_plugin.ghidra.ui.components import (
    Label,
    button,
    checkbox,
    copy_to_clipboard,
    grid,
    row,
    stack,
)
from mcrit_plugin.ghidra.ui.table import MatchRow, MatchTableView

MAX_FAMILY_SUGGESTIONS = 15


def _window(panel):
    from javax.swing import SwingUtilities

    return SwingUtilities.getWindowAncestor(panel.component)


class _Dialog:
    def __init__(self, main_panel, title, width=None, height=None):
        from java.awt import BorderLayout
        from javax.swing import JDialog

        self.main_panel = main_panel
        self.dialog = JDialog(_window(main_panel), title)
        self.dialog.setModal(True)
        self.dialog.getContentPane().setLayout(BorderLayout())
        self._size = (width, height)

    def _layout(self, body, buttons):
        from java.awt import BorderLayout
        from javax.swing import BorderFactory

        body.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8))
        self.dialog.getContentPane().add(body, BorderLayout.CENTER)
        footer = row(*buttons, glue=False)
        footer.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8))
        self.dialog.getContentPane().add(footer, BorderLayout.SOUTH)
        self.dialog.pack()
        width, height = self._size
        if width and height:
            self.dialog.setSize(width, height)
        self.dialog.setLocationRelativeTo(self.dialog.getOwner())

    def close(self):
        self.dialog.setVisible(False)
        self.dialog.dispose()

    def exec_(self):
        self.dialog.setVisible(True)


class SmdaInfoDialog(_Dialog):
    """Family, version and library flag for a sample the server does not know yet."""

    def __init__(self, main_panel):
        super().__init__(main_panel, "Provide additional information about the sample")
        from javax.swing import JTextField

        session = main_panel.parent
        report = session.local_smda_report
        self._info = {
            "family": report.family if report is not None else "",
            "version": report.version if report is not None else "",
            "is_library": bool(report.is_library) if report is not None else False,
        }
        self._families = sorted(
            {
                entry.family_name
                for entry in (session.family_infos or {}).values()
                if entry.family_name
            },
            key=str.lower,
        )
        self.edit_family = JTextField(self._info["family"] or "", 30)
        self.edit_version = JTextField(self._info["version"] or "", 30)
        self.cb_is_library = checkbox("Sample is a library?", self._info["is_library"])
        self._createSuggestions()
        body = stack(
            grid(
                [
                    (Label("Family:", wrap=False).component, self.edit_family),
                    (Label("Version:", wrap=False).component, self.edit_version),
                ]
            ),
            self.cb_is_library,
        )
        ok = button("OK", self.accept)
        self.dialog.getRootPane().setDefaultButton(ok)
        self._layout(body, [ok, button("Cancel", self.close)])

    def _createSuggestions(self):
        """Family names containing the typed text, offered in a popup below the field."""
        from javax.swing import JMenuItem, JPopupMenu

        self.popup = JPopupMenu()
        self.popup.setFocusable(False)

        def choose(name):
            self.edit_family.setText(name)
            self.popup.setVisible(False)

        def changed(_event):
            def refresh():
                text = str(self.edit_family.getText()).lower()
                self.popup.setVisible(False)
                self.popup.removeAll()
                if not text or not self.edit_family.hasFocus():
                    return
                matches = [name for name in self._families if text in name.lower()]
                if len(matches) == 1 and matches[0].lower() == text:
                    return
                for name in matches[:MAX_FAMILY_SUGGESTIONS]:
                    item = JMenuItem(name)
                    item.addActionListener(swing.ActionListener(lambda _e, n=name: choose(n)))
                    self.popup.add(item)
                if matches:
                    self.popup.show(self.edit_family, 0, self.edit_family.getHeight())

            # the document is locked while listeners run; the field cannot change from here
            swing.invoke_later(refresh)

        self._document_listener = swing.DocumentListener(changed)
        self.edit_family.getDocument().addDocumentListener(self._document_listener)

    def accept(self):
        self._info = {
            "family": str(self.edit_family.getText()),
            "version": str(self.edit_version.getText()),
            "is_library": bool(self.cb_is_library.isSelected()),
        }
        self.close()

    def getSmdaInfo(self):
        return dict(self._info)


class ResultChooserDialog(_Dialog):
    """Pick a finished matching job of the sample, or ask for a new one."""

    STATUS_COLORS = {
        "queued": (ThemeRole.RED, (200, 50, 50)),
        "running": (ThemeRole.YELLOW, (200, 200, 50)),
        "finished": (ThemeRole.GREEN, (50, 200, 50)),
    }

    def __init__(self, main_panel, job_infos):
        super().__init__(main_panel, "Remote Match Results", 640, 360)
        self.job_infos = job_infos or []
        self._selected_job_id = None
        self._is_requesting_matching_job = False
        buttons = []
        if self.job_infos:
            self.table = MatchTableView()
            self._populate(main_panel.cc.backend)
            self.table.on_click(self._onClick)
            body = stack(self.table.component, fill=(self.table.component,))
            buttons.append(button("Select Result", self.accept_select))
        else:
            body = stack(Label("No Matching Results available yet.").component)
        buttons.append(button("Create New Matching Job", self.accept_create))
        buttons.append(button("Cancel", self.close))
        self._layout(body, buttons)

    @staticmethod
    def _status(job_info):
        if job_info.started_at is None:
            return "queued"
        if job_info.finished_at is not None:
            return "finished"
        return "running"

    def _populate(self, backend):
        scp = ScoreColorProvider(backend)
        rows = []
        preselected = None
        for index, job_info in enumerate(self.job_infos):
            status = self._status(job_info)
            if status == "queued":
                date = "Not started yet."
            elif status == "finished":
                date = job_info.finished_at[:19]
            else:
                date = job_info.started_at[:19]
            progress = 100 * job_info.progress if job_info.started_at is not None else 0
            if progress == 100 and preselected is None:
                preselected = index
            role, default = self.STATUS_COLORS[status]
            rows.append(
                MatchRow(
                    index,
                    job_info,
                    ["%d" % job_info.number, job_info.parameters, date, "%5.2f" % progress],
                    [job_info.number, job_info.parameters, date, progress],
                    scp.roleColor(role, default),
                )
            )
        text_color = scp.textOnTintColor()
        self.table.reset(["ID", "Type", "Date", "Progress"], rows, text_color)
        self.table.fit_columns()
        if preselected is not None:
            self.table.selectEntireRow(preselected)

    @staticmethod
    def _isFinished(job_info):
        return job_info.finished_at is not None and job_info.progress == 1

    def _onClick(self, view_row, _column, click_count):
        if click_count == 2:
            job_info = self.table.entryAt(view_row)
            if job_info is not None and self._isFinished(job_info):
                self._selected_job_id = job_info.job_id
                self.close()

    def accept_select(self):
        job_info = self.table.selectedEntry()
        if job_info is not None and self._isFinished(job_info):
            self._selected_job_id = job_info.job_id
            self.close()

    def accept_create(self):
        self._is_requesting_matching_job = True
        self.close()

    def getResultChosen(self):
        return {
            "selected_job_id": self._selected_job_id,
            "is_requesting_matching_job": self._is_requesting_matching_job,
        }


class YaraStringBuilderDialog(_Dialog):
    def __init__(
        self,
        main_panel,
        data=None,
        selection_sequence=None,
        block_sequence=None,
        function_sequence=None,
        sha256="",
        offset=0,
        selection_start=0,
        selection_end=0,
    ):
        super().__init__(main_panel, "YARA String Builder", 820, 600)
        from java.awt import Font
        from javax.swing import ButtonGroup, JRadioButton, JScrollPane, JTextArea

        self.session = main_panel.parent
        self.data = data or b""
        self.selection_sequence = selection_sequence or []
        self.block_sequence = block_sequence or []
        self.function_sequence = function_sequence or []
        self.sha256 = sha256
        self.offset = offset
        self.selection_start = selection_start
        self.selection_end = selection_end
        # as in the Qt dialog: raw bytes only when the cursor is in no function at all
        self.is_data_mode = (
            data is not None and block_sequence is None and function_sequence is None
        )
        self.current_scope = "selection"
        self.radio_selection = JRadioButton("Selection")
        self.radio_block = JRadioButton("Current Block")
        self.radio_function = JRadioButton("Current Function")
        group = ButtonGroup()
        for radio in (self.radio_selection, self.radio_block, self.radio_function):
            group.add(radio)
            radio.addActionListener(swing.ActionListener(lambda _e: self._onScopeChanged()))
        self.radio_selection.setSelected(True)
        self.radio_block.setEnabled(not self.is_data_mode and bool(self.block_sequence))
        self.radio_function.setEnabled(not self.is_data_mode and bool(self.function_sequence))
        if not self.selection_sequence and not self.is_data_mode:
            self.radio_selection.setEnabled(False)
            if self.block_sequence:
                self.radio_block.setSelected(True)
                self.current_scope = "block"
            elif self.function_sequence:
                self.radio_function.setSelected(True)
                self.current_scope = "function"
        self.cb_wildcards = checkbox(
            "Use wildcards (show escaped version)",
            True,
            enabled=not self.is_data_mode,
            on_click=self._updateYaraRule,
        )
        self.text_yara = JTextArea()
        self.text_yara.setEditable(False)
        self.text_yara.setFont(Font(Font.MONOSPACED, Font.PLAIN, 12))
        scroll = JScrollPane(self.text_yara)
        body = stack(
            row(
                Label("Scope:", wrap=False).component,
                self.radio_selection,
                self.radio_block,
                self.radio_function,
            ),
            self.cb_wildcards,
            Label("Generated YARA Rule:", wrap=False).component,
            scroll,
            fill=(scroll,),
        )
        self._layout(
            body,
            [
                button("Copy Escaped Bytes", self._onCopyEscapedClicked),
                button("Copy YARA Rule", self._onCopyYaraClicked),
                button("OK", self.close),
            ],
        )
        self._updateYaraRule()

    def _onScopeChanged(self):
        if self.radio_selection.isSelected():
            self.current_scope = "selection"
        elif self.radio_block.isSelected():
            self.current_scope = "block"
        else:
            self.current_scope = "function"
        self._updateYaraRule()

    def _instructions(self):
        return {
            "selection": self.selection_sequence,
            "block": self.block_sequence,
            "function": self.function_sequence,
        }.get(self.current_scope, [])

    def _useWildcards(self):
        return bool(self.cb_wildcards.isSelected())

    def ruleText(self):
        instructions = self._instructions()
        if not instructions and not self.is_data_mode:
            return "No data available for selected scope."
        scope_offset = self.offset
        if self.current_scope == "selection" and self.selection_start != self.selection_end:
            scope_offset = self.selection_start
        elif instructions:
            scope_offset = instructions[0].offset
        if self.is_data_mode:
            hex_content = format_data_bytes(self.data)
        else:
            hex_content = format_hex_lines(
                instructions, self.session.local_smda_report, self._useWildcards()
            )
        return build_yara_rule(self.sha256, self.current_scope, scope_offset, hex_content)

    def _updateYaraRule(self):
        self.text_yara.setText(self.ruleText())
        self.text_yara.setCaretPosition(0)

    def _onCopyEscapedClicked(self):
        if self.is_data_mode:
            hex_string = self.data.hex()
        else:
            hex_string = escaped_hex_string(
                self._instructions(), self.session.local_smda_report, self._useWildcards()
            )
        copy_to_clipboard(hex_string)
        self.session.local_widget.updateActivityInfo(
            f"Copied escaped bytes to clipboard: {len(hex_string)} bytes"
        )

    def _onCopyYaraClicked(self):
        copy_to_clipboard(str(self.text_yara.getText()))
        self.session.local_widget.updateActivityInfo("YARA rule copied to clipboard")
