import hashlib
import os
import re
import traceback
from contextlib import contextmanager

import binaryninja
from binaryninja import Logger, interaction
from binaryninja.enums import (
    BranchType,
    InstructionTextTokenType,
    MessageBoxButtonResult,
    MessageBoxButtonSet,
    MessageBoxIcon,
    ThemeColor,
)

from mcrit_plugin.binja.BinjaSmdaInterface import BinjaSmdaInterface
from mcrit_plugin.core.Backend import Backend
from mcrit_plugin.core.ScoreColorProvider import ThemeRole

TITLE = "MCRIT"
logger = Logger(0, TITLE)

THEME_HIGHLIGHT_ROLES = {
    ThemeRole.BLUE: ThemeColor.BlueStandardHighlightColor,
    ThemeRole.CYAN: ThemeColor.CyanStandardHighlightColor,
    ThemeRole.GREEN: ThemeColor.GreenStandardHighlightColor,
    ThemeRole.YELLOW: ThemeColor.YellowStandardHighlightColor,
    ThemeRole.ORANGE: ThemeColor.OrangeStandardHighlightColor,
    ThemeRole.RED: ThemeColor.RedStandardHighlightColor,
    ThemeRole.MAGENTA: ThemeColor.MagentaStandardHighlightColor,
}
# the standard highlight colors are meant as tints; at full strength they overpower any theme
TINT_STRENGTH = 0.4
# Binary Ninja composites node highlights over the graph background, like its own highlighting
GRAPH_HIGHLIGHT_ALPHA = 128


class BinjaBackend(Backend):
    name = "Binary Ninja"
    plugin_name = "MCRIT4BinaryNinja"

    def __init__(self, bv):
        self.bv = bv
        self.view_frame = None
        self.cursor_offset = None
        self._input_hashes = None
        self.closed = False
        self._mutation_depth = 0

    def _smda_interface(self):
        return BinjaSmdaInterface(self.bv)

    def _input_bytes(self):
        raw = self.bv.file.raw
        return raw.read(raw.start, raw.length) if raw is not None else b""

    def _hashes(self):
        if self._input_hashes is None:
            data = self._input_bytes()
            self._input_hashes = (
                hashlib.md5(data).hexdigest(),
                hashlib.sha256(data).hexdigest(),
                len(data),
            )
        return self._input_hashes

    def get_input_md5(self):
        return self._hashes()[0]

    def get_input_sha256(self):
        return self._hashes()[1]

    def get_input_filename(self):
        return os.path.basename(self.bv.file.original_filename or self.bv.file.filename)

    def get_input_size(self):
        return self._hashes()[2]

    def export_smda_report(self):
        from smda.Disassembler import Disassembler
        from smda.ida.IdaExporter import IdaExporter

        interface = self._smda_interface()
        disassembler = Disassembler()
        # same path as Disassembler(backend="IDA"): an explicitly pinned exporter backend
        disassembler.disassembler = IdaExporter(disassembler.config, ida_interface=interface)
        disassembler._explicit_backend = True
        return disassembler.disassembleBuffer(interface.getBinary(), 0)

    def get_binary_info(self):
        from smda.common.BinaryInfo import BinaryInfo

        interface = self._smda_interface()
        binary_info = BinaryInfo(interface.getBinary())
        binary_info.architecture = interface.getArchitecture()
        binary_info.base_addr = interface.getBaseAddr()
        binary_info.bitness = interface.getBitness()
        return binary_info

    def get_function_symbols(self):
        return self._smda_interface().getFunctionSymbols()

    def get_cursor_address(self):
        if self.view_frame is not None:
            return self.view_frame.getCurrentOffset()
        return self.cursor_offset

    def get_selection(self):
        if self.view_frame is None:
            return None, None
        view = self.view_frame.getCurrentViewInterface()
        if view is None:
            return None, None
        start, end = view.getSelectionOffsets()
        if start == end:
            return None, None
        return start, end

    def get_current_function(self, view=None):
        """view is the offset reported by the sidebar; None means no location update."""
        if view is None:
            return None
        functions = self.bv.get_functions_containing(view)
        return functions[0].start if functions else None

    def read_bytes(self, address, size):
        return self.bv.read(address, size)

    def jump_to(self, address):
        if self.view_frame is not None:
            self.view_frame.navigate(self.bv, address)
        else:
            self.bv.navigate(self.bv.view, address)

    def get_function_name(self, address):
        function = self.bv.get_function_at(address)
        return function.name if function is not None else None

    @contextmanager
    def mutation(self, title):
        if self._mutation_depth:
            yield
            return
        self._mutation_depth += 1
        try:
            with self.bv.undoable_transaction():
                yield
        finally:
            self._mutation_depth -= 1

    def set_function_name(self, address, name):
        function = self.bv.get_function_at(address)
        if function is None:
            return False
        with self.mutation("Rename function"):
            function.name = name
        return True

    def has_default_function_name(self, address):
        function = self.bv.get_function_at(address)
        if function is None:
            return False
        return function.symbol.auto and re.match("sub_[0-9a-fA-F]+$", function.name) is not None

    def run_background(self, title, work, on_done):
        backend = self

        class Task(binaryninja.BackgroundTaskThread):
            def run(task):
                try:
                    task.progress = f"{title} (waiting for analysis)"
                    # reports must reflect finished analysis; not allowed on UI or worker threads
                    backend.bv.update_analysis_and_wait()
                    task.progress = title
                    result = work()
                except Exception:
                    logger.log_error(f"{title} failed:\n{traceback.format_exc()}")
                    backend._on_main_thread(
                        lambda: backend.show_warning(f"{title} failed, see the log for details.")
                    )
                    return
                backend._on_main_thread(lambda: on_done(result))

        Task(title, False).start()

    def _on_main_thread(self, func):
        binaryninja.execute_on_main_thread(lambda: None if self.closed else func())

    def run_on_ui_thread(self, func):
        outcome = []

        def call():
            if self.closed:
                return
            try:
                outcome.append((func(), None))
            except Exception as exc:
                # execute_on_main_thread_and_wait swallows exceptions raised here
                outcome.append((None, exc))

        binaryninja.execute_on_main_thread_and_wait(call)
        if not outcome:
            return None
        result, error = outcome[0]
        if error is not None:
            raise error
        return result

    def ask_save_file(self, default_name, prompt):
        return interaction.get_save_filename_input(prompt, "smda", default_name) or None

    def ask_yes_no(self, prompt):
        answer = interaction.show_message_box(
            TITLE, prompt, MessageBoxButtonSet.YesNoButtonSet, MessageBoxIcon.QuestionIcon
        )
        return answer == MessageBoxButtonResult.YesButton

    def show_warning(self, message):
        interaction.show_message_box(
            TITLE, message, MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon
        )

    def theme_color(self, role, default):
        try:
            from binaryninjaui import getThemeColor
        except ImportError:
            return default
        if role == ThemeRole.TEXT_ON_TINT:
            return None
        base = getThemeColor(ThemeColor.BackgroundHighlightDarkColor)
        if role == ThemeRole.NEUTRAL:
            return (base.red(), base.green(), base.blue())
        if role == ThemeRole.CURRENT:
            selection = getThemeColor(ThemeColor.SelectionColor)
            return (selection.red(), selection.green(), selection.blue())
        if role not in THEME_HIGHLIGHT_ROLES:
            return default
        tint = getThemeColor(THEME_HIGHLIGHT_ROLES[role])
        return tuple(
            int(b + TINT_STRENGTH * (t - b))
            for t, b in (
                (tint.red(), base.red()),
                (tint.green(), base.green()),
                (tint.blue(), base.blue()),
            )
        )

    @staticmethod
    def _edge_branch_types(block, targets):
        """Classify CFG edges so Binary Ninja colors them like its own graphs."""
        if len(targets) == 1:
            return {targets[0]: BranchType.UnconditionalBranch}
        if len(targets) != 2:
            return {target: BranchType.IndirectBranch for target in targets}
        last_instruction = list(block.getInstructions())[-1]
        fall_through = last_instruction.offset + len(last_instruction.bytes) // 2
        return {
            target: BranchType.FalseBranch if target == fall_through else BranchType.TrueBranch
            for target in targets
        }

    def show_function_graph(self, _parent, sample_entry, function_entry, smda_function, coloring):
        if smda_function is None:
            return
        graph = binaryninja.FlowGraph()
        nodes = {}
        for block in smda_function.getBlocks():
            node = binaryninja.FlowGraphNode(graph)
            lines = []
            for instruction in block.getInstructions():
                api = smda_function.apirefs.get(instruction.offset, "")
                operands = f"[{api}]" if api else instruction.operands
                lines.append(
                    binaryninja.DisassemblyTextLine(
                        [
                            binaryninja.InstructionTextToken(
                                InstructionTextTokenType.AddressDisplayToken,
                                f"{instruction.offset:x}  ",
                                instruction.offset,
                            ),
                            binaryninja.InstructionTextToken(
                                InstructionTextTokenType.InstructionToken,
                                f"{instruction.mnemonic:<8}",
                            ),
                            binaryninja.InstructionTextToken(
                                InstructionTextTokenType.TextToken, operands
                            ),
                        ],
                        instruction.offset,
                    )
                )
            node.lines = lines
            if block.offset in coloring:
                rgb = coloring[block.offset]
                node.highlight = binaryninja.HighlightColor(
                    red=(rgb >> 16) & 0xFF,
                    green=(rgb >> 8) & 0xFF,
                    blue=rgb & 0xFF,
                    alpha=GRAPH_HIGHLIGHT_ALPHA,
                )
            graph.append(node)
            nodes[block.offset] = node
        blocks = {block.offset: block for block in smda_function.getBlocks()}
        for source, targets in smda_function.blockrefs.items():
            if source not in nodes:
                continue
            branch_types = self._edge_branch_types(blocks[source], targets)
            for target in targets:
                if target in nodes:
                    nodes[source].add_outgoing_edge(branch_types[target], nodes[target])
        title = (
            f"MCRIT CFG: sample {sample_entry.sample_id} ({sample_entry.family}), "
            f"function {function_entry.function_id}@0x{smda_function.offset:x}"
        )
        self.bv.show_graph_report(title, graph)
