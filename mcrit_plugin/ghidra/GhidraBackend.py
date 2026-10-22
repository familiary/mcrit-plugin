"""Backend over a Ghidra Program, for the GUI (with a PluginTool) and for headless PyGhidra.

All Ghidra access goes through JPype. Swing is single threaded: widgets are touched on the event
dispatch thread only, requests to the MCRIT server run on Python threads, and the export runs as a
Ghidra background task so the status bar shows it.
"""

import hashlib
import os
import threading
import traceback
from contextlib import contextmanager

from mcrit_plugin.core.Backend import Backend
from mcrit_plugin.core.ScoreColorProvider import ThemeRole
from mcrit_plugin.ghidra import swing
from mcrit_plugin.ghidra.GhidraSmdaInterface import (
    GhidraSmdaInterface,
    function_display_name,
    is_default_function_name,
)

TITLE = "MCRIT"
# dark themes get the role colors as tints over the table background, as Binary Ninja does
TINT_STRENGTH = 0.4
# a remote CFG with more blocks than this is not worth laying out as a graph
MAX_GRAPH_BLOCKS = 2000
# below the selection (100) and search highlight (50) markers, so both stay visible over a tint
MARKER_PRIORITY = 40


class GhidraBackend(Backend):
    name = "Ghidra"
    plugin_name = "MCRIT4Ghidra"

    def __init__(self, program, tool=None):
        self.program = program
        self.tool = tool
        self.closed = False
        # set from ProgramLocationPluginEvents by the provider; the fallback without a tool
        self.cursor_offset = None
        self.parent_component = None
        self._space = program.getAddressFactory().getDefaultAddressSpace()
        self._input_info = None
        self._mutation_lock = threading.RLock()
        self._mutation_depth = 0
        self._transaction = None
        self._colored = None
        self._graph_displays = []

    # helpers

    def _address(self, offset):
        return self._space.getAddress(offset)

    def _service(self, name):
        if self.tool is None:
            return None
        from jpype import JClass

        return self.tool.getService(JClass(name))

    def _smda_interface(self):
        return GhidraSmdaInterface(self.program)

    def _function_at(self, address):
        return self.program.getFunctionManager().getFunctionAt(self._address(address))

    # input file

    def _file_bytes(self):
        """Original bytes of the imported file, which Ghidra keeps with the program."""
        all_file_bytes = self.program.getMemory().getAllFileBytes()
        if all_file_bytes.isEmpty():
            return None
        file_bytes = all_file_bytes.get(0)
        size = int(file_bytes.getSize())
        from jpype import JArray, JByte

        buffer = JArray(JByte)(size)
        read = file_bytes.getOriginalBytes(0, buffer)
        return bytes(buffer[:read])

    def _input(self):
        if self._input_info is None:
            data = self._file_bytes()
            if data is None:
                path = self.program.getExecutablePath()
                if path and os.path.isfile(path):
                    with open(path, "rb") as handle:
                        data = handle.read()
            if data is not None:
                self._input_info = (
                    hashlib.md5(data).hexdigest(),
                    hashlib.sha256(data).hexdigest(),
                    len(data),
                )
            else:
                # Ghidra records the hashes at import even when the bytes are not kept
                self._input_info = (
                    str(self.program.getExecutableMD5() or "") or None,
                    str(self.program.getExecutableSHA256() or ""),
                    0,
                )
        return self._input_info

    def get_input_md5(self):
        return self._input()[0]

    def get_input_sha256(self):
        return self._input()[1]

    def get_input_filename(self):
        path = str(self.program.getExecutablePath() or "")
        # Windows paths come back as /C:/..., which basename handles either way
        name = os.path.basename(path.replace("\\", "/"))
        return name or str(self.program.getName())

    def get_input_size(self):
        return self._input()[2]

    # analysis export

    def export_smda_report(self):
        from mcrit_plugin.ghidra.GhidraExporter import exportProgram

        return exportProgram(self.program)

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

    def get_function_offsets(self):
        interface = self._smda_interface()
        return {
            offset
            for offset in interface.getFunctions()
            if not interface.isExternalFunction(offset)
        }

    # cursor and navigation

    def _code_viewer(self):
        return self._service("ghidra.app.services.CodeViewerService")

    def get_cursor_address(self):
        viewer = self._code_viewer()
        if viewer is not None:
            location = viewer.getCurrentLocation()
            if location is not None and location.getProgram() == self.program:
                address = location.getAddress()
                if address is not None and address.getAddressSpace() == self._space:
                    return int(address.getOffset())
        return self.cursor_offset

    def get_selection(self):
        viewer = self._code_viewer()
        if viewer is None:
            return None, None
        selection = viewer.getCurrentSelection()
        if selection is None or selection.isEmpty():
            return None, None
        return (
            int(selection.getMinAddress().getOffset()),
            int(selection.getMaxAddress().getOffset()) + 1,
        )

    def get_current_function(self, view=None):
        """view is the address of the location event the provider forwards; None means the
        widgets asked without a cursor move."""
        if view is None:
            return None
        function = self.program.getFunctionManager().getFunctionContaining(self._address(view))
        return int(function.getEntryPoint().getOffset()) if function is not None else None

    def read_bytes(self, address, size):
        from jpype import JArray, JByte

        buffer = JArray(JByte)(size)
        read = self.program.getMemory().getBytes(self._address(address), buffer)
        return bytes(buffer[: max(read, 0)])

    def jump_to(self, address):
        self.cursor_offset = address
        go_to = self._service("ghidra.app.services.GoToService")
        if go_to is not None:
            go_to.goTo(self._address(address), self.program)

    # names

    def get_function_name(self, address):
        function = self._function_at(address)
        return function_display_name(function) if function is not None else None

    @contextmanager
    def mutation(self, title):
        with self._mutation_lock:
            if self._mutation_depth == 0:
                self._transaction = self.program.startTransaction(title)
            self._mutation_depth += 1
            committed = False
            try:
                yield
                committed = True
            finally:
                self._mutation_depth -= 1
                if self._mutation_depth == 0:
                    transaction, self._transaction = self._transaction, None
                    # an exception rolls the whole group back, like Binary Ninja's transaction
                    self.program.endTransaction(transaction, committed)

    def set_function_name(self, address, name):
        function = self._function_at(address)
        if function is None:
            return False
        from ghidra.program.model.symbol import SourceType

        with self.mutation("Rename function"):
            function.setName(name, SourceType.USER_DEFINED)
        return True

    def has_default_function_name(self, address):
        function = self._function_at(address)
        return function is not None and is_default_function_name(function)

    # threading

    def _report_failure(self, title):
        print(f"[MCRIT] {title} failed:\n{traceback.format_exc()}")
        self._on_ui_thread(
            lambda: self.show_warning(f"{title} failed, see the console for details.")
        )

    def _on_ui_thread(self, func):
        swing.invoke_later(lambda: None if self.closed else func())

    def run_background(self, title, work, on_done):
        if self.tool is None:
            on_done(work())
            return
        backend = self

        def run(monitor):
            monitor.setMessage(title)
            try:
                result = work()
            except Exception:
                backend._report_failure(title)
                return
            backend._on_ui_thread(lambda: on_done(result))

        swing.launch_background_task(title, run)

    def run_request(self, title, work, on_done):
        if self.tool is None:
            on_done(work())
            return
        backend = self

        def run():
            try:
                result = work()
            except Exception:
                backend._report_failure(title)
                return
            backend._on_ui_thread(lambda: on_done(result))

        threading.Thread(target=run, name=title, daemon=True).start()

    def run_on_ui_thread(self, func):
        if self.tool is None:
            return func()
        return swing.invoke_and_wait(lambda: None if self.closed else func())

    # dialogs

    def ask_save_file(self, default_name, prompt):
        if self.tool is None:
            return None
        from docking.widgets.filechooser import GhidraFileChooser
        from java.io import File

        chooser = GhidraFileChooser(self.parent_component)
        chooser.setTitle(prompt)
        chooser.setApproveButtonText("Save")
        chooser.setSelectedFile(File(default_name))
        selected = chooser.getSelectedFile()
        chooser.dispose()
        return str(selected.getAbsolutePath()) if selected is not None else None

    def ask_yes_no(self, prompt):
        if self.tool is None:
            return False
        from docking.widgets import OptionDialog

        answer = OptionDialog.showYesNoDialog(self.parent_component, TITLE, prompt)
        return answer == OptionDialog.YES_OPTION

    def show_warning(self, message):
        if self.tool is None:
            print(f"[MCRIT] {message}")
            return
        from ghidra.util import Msg

        Msg.showWarn(self.plugin_name, self.parent_component, TITLE, message)

    # colors

    def theme_color(self, role, default):
        dark = swing.is_dark_theme()
        if role == ThemeRole.TEXT_ON_TINT:
            # light themes draw black on the tints; dark themes keep their own text color
            return None if dark else default
        if not dark:
            return default
        background = swing.table_background()
        if role == ThemeRole.NEUTRAL:
            return background
        if role == ThemeRole.CURRENT:
            return swing.selection_background()
        return tuple(int(b + TINT_STRENGTH * (t - b)) for t, b in zip(default, background))

    def show_local_match_coloring(self, smda_function, coloring):
        markers = self._service("ghidra.app.services.MarkerService")
        if markers is None:
            return
        from java.awt import Color

        self.clear_local_match_coloring()
        # area markers tint the listing without touching the program: no undo entry, no save
        marker_sets = {}
        for block in smda_function.getBlocks():
            color = coloring.get(block.offset)
            if color is None:
                continue
            if color not in marker_sets:
                marker_sets[color] = markers.createAreaMarker(
                    f"MCRIT match 0x{color:06x}",
                    "MCRIT match",
                    self.program,
                    MARKER_PRIORITY,
                    True,
                    True,
                    True,
                    Color(color),
                )
            last = list(block.getInstructions())[-1]
            end = last.offset + len(last.bytes) // 2 - 1
            marker_sets[color].add(self._address(block.offset), self._address(end))
        self._colored = list(marker_sets.values())

    def clear_local_match_coloring(self):
        markers = self._service("ghidra.app.services.MarkerService")
        if markers is None or not self._colored:
            return
        for marker_set in self._colored:
            markers.removeMarker(marker_set, self.program)
        self._colored = None

    # remote CFG

    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        if smda_function is None:
            return
        title = (
            f"MCRIT CFG: sample {sample_entry.sample_id} ({sample_entry.family}), "
            f"function {function_entry.function_id}@0x{smda_function.offset:x}"
        )
        if smda_function.num_blocks > MAX_GRAPH_BLOCKS:
            self.show_warning(f"{title} has {smda_function.num_blocks} blocks, too many to draw.")
            return
        broker = self._service("ghidra.app.services.GraphDisplayBroker")
        if broker is None:
            print(f"[MCRIT] {title}: no graph service, {smda_function.num_blocks} blocks")
            return
        from mcrit_plugin.ghidra.RemoteCfgGraph import build_graph

        graph, options = build_graph(title, smda_function, coloring)

        def display(monitor):
            graph_display = broker.getDefaultGraphDisplay(False, monitor)
            graph_display.setGraph(graph, options, title, False, monitor)
            self._graph_displays.append(graph_display)

        swing.launch_background_task("MCRIT: drawing the remote CFG", display)

    def close(self):
        """Stop background work from reaching the UI and drop the tint left in the listing."""
        self.closed = True
        try:
            self.clear_local_match_coloring()
        except Exception:
            traceback.print_exc()
