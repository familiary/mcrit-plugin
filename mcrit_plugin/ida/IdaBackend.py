import os
import re
import traceback
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


def _address_or_none(ea):
    if ea is None or ea == ida_idaapi.BADADDR:
        return None
    return ea


class IdaBackend(Backend):
    name = "IDA"
    plugin_name = "MCRIT4IDA"

    def __init__(self):
        self._mutation_depth = 0

    def get_input_md5(self):
        md5 = ida_nalt.retrieve_input_file_md5()
        return md5.hex() if md5 is not None else None

    def get_input_sha256(self):
        sha256 = ida_nalt.retrieve_input_file_sha256()
        return sha256.hex() if sha256 is not None else None

    def get_input_filename(self):
        return os.path.basename(ida_nalt.get_root_filename())

    def get_input_size(self):
        return ida_nalt.retrieve_input_file_size()

    def export_smda_report(self):
        from smda.Disassembler import Disassembler
        from smda.ida.IdaInterface import IdaInterface

        return Disassembler(backend="IDA").disassembleBuffer(IdaInterface().getBinary(), 0)

    def get_binary_info(self):
        from smda.common.BinaryInfo import BinaryInfo
        from smda.ida.IdaInterface import IdaInterface

        ida_interface = IdaInterface()
        binary_info = BinaryInfo(ida_interface.getBinary())
        if not binary_info.architecture:
            binary_info.architecture = ida_interface.getArchitecture()
        if not binary_info.base_addr:
            binary_info.base_addr = ida_interface.getBaseAddr()
        if not binary_info.bitness:
            binary_info.bitness = ida_interface.getBitness()
        return binary_info

    def get_function_symbols(self):
        from smda.ida.IdaInterface import IdaInterface

        return IdaInterface().getFunctionSymbols()

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
        """IDA's API is main-thread only, so work runs synchronously behind a wait box."""
        ida_kernwin.show_wait_box("HIDECANCEL\n%s" % title)
        try:
            result = work()
        except Exception:
            ida_kernwin.hide_wait_box()
            traceback.print_exc()
            self.show_warning("%s failed, see the Output window for details." % title)
            return
        ida_kernwin.hide_wait_box()
        on_done(result)

    def run_on_ui_thread(self, func):
        result = []

        def wrapper():
            # execute_sync requires an int return value
            result.append(func())
            return 1

        ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_FAST)
        return result[0] if result else None

    def ask_save_file(self, default_name, prompt):
        return ida_kernwin.ask_file(1, default_name, "%s", prompt) or None

    def ask_yes_no(self, prompt):
        return ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "%s", prompt) == ida_kernwin.ASKBTN_YES

    def show_warning(self, message):
        ida_kernwin.warning(message)

    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        from mcrit_plugin.ida.SmdaGraphViewer import SmdaGraphViewer

        SmdaGraphViewer(parent, sample_entry, function_entry, smda_function, coloring).Show()
