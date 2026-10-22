import functools
import os
import queue
import re
import threading
import traceback
from contextlib import contextmanager

import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_undo
import idc

from mcrit_plugin.core.Backend import Backend
from mcrit_plugin.core.ScoreColorProvider import ThemeRole

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None


# bounds the threads fast cursor moves start; Block Scope parallelises its own lookups
REQUEST_WORKERS = 4


def _address_or_none(ea):
    if ea is None or ea == ida_idaapi.BADADDR:
        return None
    return ea


def _on_main_thread(method):
    """IDA's API is main-thread only: called on a worker, e.g. inside run_background's work, the
    method runs on the main thread while the worker waits."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if threading.current_thread() is threading.main_thread():
            return method(self, *args, **kwargs)
        outcome = []

        def call():
            try:
                # the form closed while this waited; the database may be gone with it
                if self.closed:
                    raise RuntimeError("the MCRIT form was closed")
                outcome.append((method(self, *args, **kwargs), None))
            except Exception as exc:
                outcome.append((None, exc))
            return 1  # execute_sync requires an int return value

        # MFF_READ: IDA runs it once the database is safe to read
        ida_kernwin.execute_sync(call, ida_kernwin.MFF_READ)
        if not outcome:
            raise RuntimeError("IDA did not run %s on its main thread" % method.__name__)
        result, error = outcome[0]
        if error is not None:
            raise error
        return result

    return wrapper


def _main_thread_waker(callback):
    """An object whose wake() any thread may call to have callback run on the main thread.

    It is a queued Qt signal rather than an IDA timer: IDA 9.4 never returns from register_timer
    called inside another timer's callback, and the cursor-settle timer starts live queries."""
    import mcrit_plugin.ui_qt.QtShim as QtShim

    QtCore = QtShim.get_QtCore()

    class _Waker(QtCore.QObject):
        woken = QtShim.get_Signal()()

        def wake(self):
            self.woken.emit()

    waker = _Waker()
    queued = (
        getattr(QtCore.Qt, "QueuedConnection", None) or QtCore.Qt.ConnectionType.QueuedConnection
    )
    waker.woken.connect(callback, queued)
    return waker


def _smda_ida_interface():
    """smda's IDA interface, set up on first use with the reads below.

    smda selects its ida_domain backend whenever that package is importable, and its per-call
    wrappers make the export about twice as slow inside IDA as smda's IDAPython backend.
    """
    from smda.ida.IdaInterface import IdaInterface

    if IdaInterface.instance is not None:
        return IdaInterface()

    import ida_xref
    from smda.ida.IdaIdapythonInterface import Ida85Interface

    class FastIdaInterface(Ida85Interface):
        # one item lookup and raw xref walks instead of a decode and an iterator per instruction;
        # the report is unchanged
        def getInstructionBytes(self, offset):
            return ida_bytes.get_bytes(offset, ida_bytes.get_item_size(offset))

        def getCodeInRefs(self, offset):
            refs = []
            ref = ida_xref.get_first_cref_to(offset)
            while ref != ida_idaapi.BADADDR:
                refs.append((ref, offset))
                ref = ida_xref.get_next_cref_to(offset, ref)
            return refs

        def getCodeOutRefs(self, offset):
            refs = []
            ref = ida_xref.get_first_cref_from(offset)
            while ref != ida_idaapi.BADADDR:
                refs.append((offset, ref))
                ref = ida_xref.get_next_cref_from(offset, ref)
            return refs

        def _cbEnumImports(self, addr, name, ordinal):
            # IDAPython passes no name for an import by ordinal IDA cannot name, and smda's own
            # callback then fails on module + "!" + None; its ida_domain backend writes "#<ordinal>"
            # (danielplohmann/smda#398)
            return super()._cbEnumImports(addr, name or f"#{ordinal}", ordinal)

    IdaInterface.instance = FastIdaInterface()
    return IdaInterface()


HCLI_PLUGIN_NAME = "mcrit-ida"
SETTINGS_EDITOR_IDC_FUNC = "ida_settings_show_plugin_settings"
SETTINGS_EDITOR_CAPTION = "Plugin Settings Manager"


# dark themes get the role colors as tints over the table background, as Ghidra and Binary Ninja do
TINT_STRENGTH = 0.4


def _direct_color(rgb):
    """A line-rendering bgcolor_t for 0xRRGGBB: IDA takes 0xFFBBGGRR as a color and anything
    without the 0xFF top byte as one of its theme's color keys (CK_*)."""
    return 0xFF000000 | ((rgb & 0xFF) << 16) | (rgb & 0xFF00) | (rgb >> 16)


class _MatchColoring(ida_kernwin.UI_Hooks):
    """Tints the lines of matched local blocks while IDA draws them, in the disassembly listing and
    graph; nothing is written to the database, so the tint goes with the session."""

    def __init__(self):
        super().__init__()
        self.ranges = []

    def get_lines_rendering_info(self, out, widget, info):
        if not self.ranges:
            return
        for section_lines in info.sections_lines:
            for line in section_lines:
                address = line.at.toea()
                for start, end, color in self.ranges:
                    if start <= address < end:
                        out.entries.push_back(
                            ida_kernwin.line_rendering_output_entry_t(
                                line, ida_kernwin.LROEF_FULL_LINE, color
                            )
                        )
                        break


class IdaBackend(Backend):
    name = "IDA"
    plugin_name = "MCRIT4IDA"
    reopen_hint = "close and reopen MCRIT"
    settings_hint = (
        "The other settings are in the Plugin Settings Manager, which comes with "
        "<code>hcli plugin install ida-settings-editor</code> (restart IDA afterwards), "
        "or in a terminal: <code>hcli plugin config mcrit-ida setup</code>."
    )

    def __init__(self):
        self._mutation_depth = 0
        self.closed = False
        self._requests = queue.SimpleQueue()
        self._workers = []
        self._deliveries = queue.SimpleQueue()
        self._pending = 0
        self._waker = None
        self._delivering = False
        self._coloring = None

    @_on_main_thread
    def get_input_md5(self):
        md5 = ida_nalt.retrieve_input_file_md5()
        return md5.hex() if md5 is not None else None

    @_on_main_thread
    def get_input_sha256(self):
        sha256 = ida_nalt.retrieve_input_file_sha256()
        return sha256.hex() if sha256 is not None else None

    @_on_main_thread
    def get_input_filename(self):
        return os.path.basename(ida_nalt.get_root_filename())

    @_on_main_thread
    def get_input_size(self):
        return ida_nalt.retrieve_input_file_size()

    def export_smda_report(self):
        # only reading the database needs IDA's main thread; disassembling and hashing, most of
        # the export, then run on the calling thread
        disassembler, snapshot = self._read_export_snapshot()
        return disassembler.disassembleBuffer(snapshot.getBinary(), 0)

    @_on_main_thread
    def _read_export_snapshot(self):
        from smda.Disassembler import Disassembler

        from mcrit_plugin.ida.SmdaInterfaceSnapshot import SmdaInterfaceSnapshot

        show_wait_box = ida_kernwin.is_idaq()
        if show_wait_box:
            ida_kernwin.show_wait_box("HIDECANCEL\nMCRIT: reading the database")
        try:
            # first, so smda's IDA facade holds this interface rather than its own choice
            interface = _smda_ida_interface()
            # IdaExporter reads the bitness and architecture from IDA when it is created
            disassembler = Disassembler(backend="IDA")
            snapshot = SmdaInterfaceSnapshot(interface)
        finally:
            if show_wait_box:
                ida_kernwin.hide_wait_box()
        disassembler.disassembler.ida_interface = snapshot
        return disassembler, snapshot

    @_on_main_thread
    def get_binary_info(self):
        from smda.common.BinaryInfo import BinaryInfo

        ida_interface = _smda_ida_interface()
        binary_info = BinaryInfo(ida_interface.getBinary())
        if not binary_info.architecture:
            binary_info.architecture = ida_interface.getArchitecture()
        if not binary_info.base_addr:
            binary_info.base_addr = ida_interface.getBaseAddr()
        if not binary_info.bitness:
            binary_info.bitness = ida_interface.getBitness()
        return binary_info

    @_on_main_thread
    def get_function_symbols(self):
        return _smda_ida_interface().getFunctionSymbols()

    @_on_main_thread
    def get_function_offsets(self):
        interface = _smda_ida_interface()
        # smda's exporter skips external functions
        return {
            offset
            for offset in interface.getFunctions()
            if not interface.isExternalFunction(offset)
        }

    def get_cursor_address(self):
        return _address_or_none(ida_kernwin.get_screen_ea())

    def get_selection(self):
        selected, start, end = ida_kernwin.read_range_selection(None)
        if not selected:
            return None, None
        return _address_or_none(start), _address_or_none(end)

    def get_current_function(self, view=None):
        """
        Courtesy of Alex Hanel's FunctionTrapperKeeper
        https://github.com/alexander-hanel/FunctionTrapperKeeper/blob/main/function_trapper_keeper.py
        """
        if view is None:
            return None
        widget_type = ida_kernwin.get_widget_type(view)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # the view already holds its decompiled function; no need to decompile per cursor event
            vdui = ida_hexrays.get_widget_vdui(view) if ida_hexrays is not None else None
            if vdui is None or vdui.cfunc is None:
                return None
            return _address_or_none(vdui.cfunc.entry_ea)
        if widget_type != ida_kernwin.BWN_DISASM:
            return None
        ea = self.get_cursor_address()
        if ea is None:
            return None
        if hasattr(ida_funcs, "get_func_start"):
            return _address_or_none(ida_funcs.get_func_start(ea))
        # get_func is deprecated from IDA 9.4, but get_func_start does not exist before it
        func = ida_funcs.get_func(ea)
        return _address_or_none(func.start_ea) if func else None

    def read_bytes(self, address, size):
        return ida_bytes.get_bytes(address, size)

    def jump_to(self, address):
        return ida_kernwin.jumpto(address)

    def get_function_name(self, address):
        return ida_funcs.get_func_name(address)

    def set_function_name(self, address, name):
        return idc.set_name(address, name, idc.SN_NOWARN)

    def has_default_function_name(self, address):
        name = self.get_function_name(address)
        return bool(name) and re.match("sub_[0-9A-Fa-f]+$", name) is not None

    @contextmanager
    def mutation(self, title):
        if self._mutation_depth:
            # an enclosing mutation already records these changes as one undo step
            yield
            return
        self._mutation_depth += 1
        try:
            ida_undo.create_undo_point(self.plugin_name, title)
            yield
        finally:
            self._mutation_depth -= 1

    def run_background(self, title, work, on_done):
        """work runs on a worker thread like a request; the methods it calls that read the
        database run on the main thread."""
        self.run_request(title, work, on_done)

    def run_request(self, title, work, on_done):
        """IDA's API is main-thread only: work, the requests, runs on a worker thread and must not
        call it; a queued Qt signal hands each result to on_done on the main thread. Called on the
        main thread, also from inside an IDA timer callback."""
        if self.closed:
            return
        if self._waker is None:
            # created on the main thread, so its queued signal is delivered there
            self._waker = _main_thread_waker(self._deliver)
        if not self._workers:
            # daemon threads: the interpreter joins a ThreadPoolExecutor's threads at exit, so
            # quitting IDA during a slow request would wait for it
            for number in range(REQUEST_WORKERS):
                worker = threading.Thread(
                    target=self._work, name="mcrit-request-%d" % number, daemon=True
                )
                worker.start()
                self._workers.append(worker)
        self._pending += 1
        self._requests.put((title, work, on_done))

    def _work(self):
        while True:
            request = self._requests.get()
            if request is None:
                return
            if self.closed:
                continue
            title, work, on_done = request
            try:
                self._deliveries.put((on_done, work()))
            except Exception:
                traceback.print_exc()
                self._deliveries.put((None, title))
            self._waker.wake()

    def _deliver(self):
        # a dialog opened by on_done runs a nested event loop in which further wakes arrive; their
        # results wait until it closes and this loop picks them up
        if self._delivering:
            return
        self._delivering = True
        try:
            while not self.closed:
                try:
                    on_done, result = self._deliveries.get_nowait()
                except queue.Empty:
                    break
                self._pending -= 1
                try:
                    if on_done is None:
                        self.show_warning("%s failed, see the Output window for details." % result)
                    else:
                        on_done(result)
                except Exception:
                    traceback.print_exc()
        finally:
            self._delivering = False

    def close(self):
        """Drop the results still to come; called when the MCRIT form closes."""
        self.closed = True
        for _worker in self._workers:
            self._requests.put(None)
        self._workers = []
        if self._coloring is not None:
            self._coloring.unhook()
            self._coloring = None
            ida_kernwin.refresh_idaview_anyway()

    def run_on_ui_thread(self, func):
        result = []

        def wrapper():
            # execute_sync requires an int return value
            result.append(func())
            return 1

        ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_FAST)
        return result[0] if result else None

    # IDAPython fixes the printf format of ask_file and ask_yn to "%s", so the prompt shows verbatim
    def ask_save_file(self, default_name, prompt):
        return ida_kernwin.ask_file(1, default_name, prompt) or None

    def ask_yes_no(self, prompt):
        return ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, prompt) == ida_kernwin.ASKBTN_YES

    def show_warning(self, message):
        ida_kernwin.warning(message)

    def open_settings(self, config):
        # registered by the ida-settings-editor plugin, which installing mcrit-ida does not bring
        if ida_expr.find_idc_func(SETTINGS_EDITOR_IDC_FUNC) == SETTINGS_EDITOR_IDC_FUNC:
            idc.eval_idc('%s("%s")' % (SETTINGS_EDITOR_IDC_FUNC, HCLI_PLUGIN_NAME))
            widget = ida_kernwin.find_widget(SETTINGS_EDITOR_CAPTION)
            if widget is None:
                return True
            return ida_kernwin.PluginForm.FormToPyQtWidget(widget)
        return None

    def save_settings(self, values):
        from mcrit_plugin.ida.config import set_setting

        for key, value in values.items():
            set_setting(key, value)

    def theme_color(self, role, default):
        from mcrit_plugin.ui_qt.QtShim import get_QtWidgets

        palette = get_QtWidgets().QApplication.palette()
        # IDA's themes are style sheets over the Qt palette, which carries their colors
        dark = palette.color(palette.ColorRole.Window).lightness() < 128
        if role == ThemeRole.TEXT_ON_TINT:
            # light themes draw black on the tints; dark themes keep their own text color
            return None if dark else default
        if not dark:
            return default
        base = palette.color(palette.ColorRole.Base)
        background = (base.red(), base.green(), base.blue())
        if role == ThemeRole.NEUTRAL:
            return background
        if role == ThemeRole.CURRENT:
            selection = palette.color(palette.ColorRole.Highlight)
            return (selection.red(), selection.green(), selection.blue())
        return tuple(int(b + TINT_STRENGTH * (t - b)) for t, b in zip(default, background))

    def show_local_match_coloring(self, smda_function, coloring):
        ranges = []
        for block in smda_function.getBlocks():
            if block.offset in coloring:
                last = list(block.getInstructions())[-1]
                end = last.offset + len(last.bytes) // 2
                ranges.append((block.offset, end, _direct_color(coloring[block.offset])))
        if self._coloring is None:
            self._coloring = _MatchColoring()
            self._coloring.hook()
        self._coloring.ranges = ranges
        ida_kernwin.refresh_idaview_anyway()

    def clear_local_match_coloring(self):
        if self._coloring is not None and self._coloring.ranges:
            self._coloring.ranges = []
            ida_kernwin.refresh_idaview_anyway()

    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        from mcrit_plugin.ida.SmdaGraphViewer import SmdaGraphViewer

        SmdaGraphViewer(parent, sample_entry, function_entry, smda_function, coloring).Show()
