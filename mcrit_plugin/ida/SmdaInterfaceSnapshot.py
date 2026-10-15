# smda.ida.BackendInterface exists in every smda the IDA plugin supports (4.3.10 and newer)
from smda.ida.BackendInterface import BackendInterface


class SmdaInterfaceSnapshot(BackendInterface):
    """Everything smda's Exporter reads from a BackendInterface, read up front.

    IDA's API is main-thread only: the snapshot is taken there, and the export, which spends most
    of its time disassembling and hashing in Python, then runs on any thread. It reads what
    Exporter.analyzeBuffer asks for, so the report is the one the live interface yields.
    """

    def __init__(self, interface):
        super().__init__()
        self._architecture = interface.getArchitecture()
        self._bitness = interface.getBitness()
        self._base_addr = interface.getBaseAddr()
        self._binary = interface.getBinary()
        self._function_symbols = interface.getFunctionSymbols()
        self._api_map = interface.getApiMap()
        self._functions = list(interface.getFunctions())
        self._external_functions = set()
        self._blocks = {}
        self._instruction_bytes = {}
        self._code_in_refs = {}
        self._code_out_refs = {}
        for function_offset in self._functions:
            if interface.isExternalFunction(function_offset):
                self._external_functions.add(function_offset)
                continue
            blocks = interface.getBlocks(function_offset)
            self._blocks[function_offset] = blocks
            for block in blocks:
                for offset in block:
                    # functions can share code, e.g. chunks of a function with several entries
                    if offset not in self._instruction_bytes:
                        self._instruction_bytes[offset] = interface.getInstructionBytes(offset)
                        self._code_in_refs[offset] = interface.getCodeInRefs(offset)
                        self._code_out_refs[offset] = interface.getCodeOutRefs(offset)

    def getArchitecture(self):
        return self._architecture

    def getBitness(self):
        return self._bitness

    def getBaseAddr(self):
        return self._base_addr

    def getBinary(self):
        return self._binary

    def getFunctions(self):
        return self._functions

    def isExternalFunction(self, function_offset):
        return function_offset in self._external_functions

    def getBlocks(self, function_offset):
        return self._blocks[function_offset]

    def getInstructionBytes(self, offset):
        return self._instruction_bytes[offset]

    def getCodeInRefs(self, offset):
        return self._code_in_refs[offset]

    def getCodeOutRefs(self, offset):
        return self._code_out_refs[offset]

    def getFunctionSymbols(self, demangle=False):
        return self._function_symbols

    def getApiMap(self):
        return self._api_map
