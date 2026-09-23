"""Backend without a disassembler UI: SMDA disassembles the file itself and labels live in memory.

Needs no disassembler licence, so it exercises the shared core against a live MCRIT server in CI,
and is usable for scripted export and submission.
"""

import hashlib
import os
import re

from mcrit_plugin.core.Backend import Backend


class HeadlessBackend(Backend):
    name = "SMDA"
    plugin_name = "MCRIT4SMDA"

    def __init__(self, path):
        self.path = os.path.abspath(path)
        with open(self.path, "rb") as handle:
            self._data = handle.read()
        self._report = None
        self._loader = None
        self._names = {}
        self.cursor_offset = None

    def _disassembly(self):
        if self._report is None:
            from smda.Disassembler import Disassembler

            self._report = Disassembler().disassembleFile(self.path)
        return self._report

    def _mapped(self):
        if self._loader is None:
            from smda.utility.FileLoader import FileLoader

            self._loader = FileLoader(self.path, map_file=True)
        return self._loader

    def get_input_md5(self):
        return hashlib.md5(self._data).hexdigest()

    def get_input_sha256(self):
        return hashlib.sha256(self._data).hexdigest()

    def get_input_filename(self):
        return os.path.basename(self.path)

    def get_input_size(self):
        return len(self._data)

    def export_smda_report(self):
        report = self._disassembly()
        for function in report.getFunctions():
            if function.offset in self._names:
                function.function_name = self._names[function.offset]
        return report

    def get_binary_info(self):
        from smda.common.BinaryInfo import BinaryInfo

        loader = self._mapped()
        binary_info = BinaryInfo(loader.getData())
        binary_info.architecture = loader.getArchitecture()
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        return binary_info

    def get_function_symbols(self):
        symbols = {
            function.offset: function.function_name
            for function in self._disassembly().getFunctions()
            if function.function_name
        }
        symbols.update(self._names)
        return symbols

    def get_cursor_address(self):
        return self.cursor_offset

    def get_selection(self):
        return None, None

    def get_current_function(self, view=None):
        if view is None:
            return None
        function = self._disassembly().findFunctionByContainedAddress(view)
        return function.offset if function is not None else None

    def read_bytes(self, address, size):
        loader = self._mapped()
        start = address - loader.getBaseAddress()
        return loader.getData()[start : start + size]

    def jump_to(self, address):
        self.cursor_offset = address

    def get_function_name(self, address):
        if address in self._names:
            return self._names[address]
        function = self._disassembly().getFunction(address)
        return function.function_name if function is not None else None

    def set_function_name(self, address, name):
        if self._disassembly().getFunction(address) is None:
            return False
        self._names[address] = name
        return True

    def has_default_function_name(self, address):
        name = self.get_function_name(address)
        return bool(name) and re.match("sub_[0-9a-fA-F]+$", name) is not None

    def run_on_ui_thread(self, func):
        return func()

    def ask_save_file(self, default_name, prompt):
        return None

    def ask_yes_no(self, prompt):
        return False

    def show_warning(self, message):
        print(f"[MCRIT] {message}")

    def show_function_graph(self, parent, sample_entry, function_entry, smda_function, coloring):
        print(f"[MCRIT] CFG of 0x{smda_function.offset:x}: {smda_function.num_blocks} blocks")
