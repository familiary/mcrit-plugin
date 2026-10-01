import functools
import os
import queue
import re
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_undo
import idc

from mcrit_plugin.core.Backend import Backend

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None


# bounds the threads fast cursor moves start; Block Scope parallelises its own lookups
REQUEST_WORKERS = 4
DELIVERY_INTERVAL_MS = 20


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

    IdaInterface.instance = FastIdaInterface()
    return IdaInterface()


class IdaBackend(Backend):
    name = "IDA"
    plugin_name = "MCRIT4IDA"

    def __init__(self):
        self._mutation_depth = 0
        self.closed = False
        self._executor = None
        self._deliveries = queue.SimpleQueue()
        self._pending = 0
        self._timer = None
        self._delivering = False

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
        call it; a main-thread timer hands each result to on_done."""
        if self.closed:
            return
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=REQUEST_WORKERS, thread_name_prefix="mcrit-request"
            )
        self._pending += 1
        self._executor.submit(self._run_request, title, work, on_done)
        if self._timer is None:
            self._timer = ida_kernwin.register_timer(DELIVERY_INTERVAL_MS, self._deliver)

    def _run_request(self, title, work, on_done):
        try:
            self._deliveries.put((on_done, work()))
        except Exception:
            traceback.print_exc()
            self._deliveries.put((None, title))

    def _deliver(self):
        # a dialog opened by on_done runs a nested event loop in which this timer fires again;
        # the other results wait until it closes
        if self._delivering:
            return DELIVERY_INTERVAL_MS
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
        if self.closed or not self._pending:
            self._timer = None
            return -1  # unregisters the timer
        return DELIVERY_INTERVAL_MS

    def close(self):
        """Drop the results still to come; called when the MCRIT form closes."""
        self.closed = True
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
        if self._timer is not None and not self._delivering:
            ida_kernwin.unregister_timer(self._timer)
            self._timer = None

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

    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        from mcrit_plugin.ida.SmdaGraphViewer import SmdaGraphViewer

        SmdaGraphViewer(parent, sample_entry, function_entry, smda_function, coloring).Show()
