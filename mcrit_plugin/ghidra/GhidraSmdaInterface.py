"""SMDA BackendInterface over a Ghidra Program, the counterpart of smda.binja.BinjaInterface.

smda.export.Exporter reads Ghidra's functions, basic blocks, instruction bytes and code references
through this interface and disassembles the instructions again with capstone, so the report has
the same instruction text as SMDA's own disassembly and as the IDA and Binary Ninja exports.

Everything here runs through JPype; the Ghidra classes are imported lazily so this module can be
imported, and unit tested with stand-ins, without a JVM.
"""

from smda.export.BackendInterface import BackendInterface
from smda.export.segment_mapping import assembleSegmentBuffer

from mcrit_plugin.ghidra.presentation import api_name, is_default_name

READ_CHUNK = 0x100000


def _signed_to_bytes(java_bytes):
    """Python bytes from a Java byte[] (JPype converts it directly)."""
    return bytes(java_bytes)


def function_display_name(function):
    """The name a Ghidra function shows, with a namespace only where it is part of the name: a
    thunk carries its target's external namespace, which would read as <EXTERNAL>::name."""
    if function.isThunk():
        return function.getName()
    namespace = function.getParentNamespace()
    if namespace is None or namespace.isGlobal() or namespace.isExternal():
        return function.getName()
    return function.getName(True)


def is_default_function_name(function):
    """True when Ghidra generated the function's name, not a loader, analyzer or the user."""
    from ghidra.program.model.symbol import SourceType

    symbol = function.getSymbol()
    if symbol is not None and symbol.getSource() == SourceType.DEFAULT:
        return True
    return is_default_name(function.getName())


class GhidraSmdaInterface(BackendInterface):
    """BackendInterface over a Ghidra Program, for smda.export.Exporter."""

    def __init__(self, program, monitor=None):
        super().__init__()
        self.program = program
        self._monitor = monitor
        self._space = program.getAddressFactory().getDefaultAddressSpace()
        self._listing = program.getListing()
        self._memory = program.getMemory()
        self._functions = program.getFunctionManager()
        self._api_map = None
        self._blocks = {}
        self._instruction_bytes = {}
        self._refs_from = {}
        self._refs_to = None

    # address helpers

    def _address(self, offset):
        return self._space.getAddress(offset)

    @staticmethod
    def _offset(address):
        return int(address.getOffset())

    def _task_monitor(self):
        if self._monitor is None:
            from ghidra.util.task import TaskMonitor

            self._monitor = TaskMonitor.DUMMY
        return self._monitor

    # architecture

    def getArchitecture(self):
        processor = str(self.program.getLanguage().getProcessor()).lower()
        bitness = self.getBitness()
        if processor == "x86":
            return "intel"
        if processor == "aarch64":
            return "aarch64"
        if processor == "arm":
            return "aarch64" if bitness == 64 else "arm"
        raise ValueError(f"Unsupported Architecture: {processor} ({bitness} bit)")

    def getBitness(self):
        return int(self.program.getLanguage().getLanguageDescription().getSize())

    def isThumb(self, offset):
        context = self.program.getProgramContext()
        register = context.getRegister("TMode")
        if register is None:
            return False
        value = context.getValue(register, self._address(offset), False)
        return value is not None and int(value.intValue()) == 1

    # memory

    def _loadedBlocks(self):
        """Initialized, loaded blocks of the default address space, the image SMDA reads from."""
        blocks = []
        for block in self._memory.getBlocks():
            if not block.isInitialized() or not block.isLoaded():
                continue
            if block.getStart().getAddressSpace() != self._space:
                continue
            blocks.append(block)
        return sorted(blocks, key=lambda block: self._offset(block.getStart()))

    def getBaseAddr(self):
        blocks = self._loadedBlocks()
        if not blocks:
            return 0
        return (self._offset(blocks[0].getStart()) // 0x10000) * 0x10000

    def _read(self, offset, size):
        from jpype import JArray, JByte

        data = bytearray()
        while size > 0:
            chunk = min(size, READ_CHUNK)
            buffer = JArray(JByte)(chunk)
            read = self._memory.getBytes(self._address(offset), buffer)
            if read <= 0:
                break
            data += _signed_to_bytes(buffer[:read])
            if read < chunk:
                break
            offset += read
            size -= read
        return bytes(data)

    def getBinary(self):
        """Image mapped at getBaseAddr(), with gaps between blocks zero-filled."""
        ranges = [
            (self._offset(block.getStart()), self._offset(block.getEnd()) + 1)
            for block in self._loadedBlocks()
        ]
        return assembleSegmentBuffer(self.getBaseAddr(), ranges, self._read)

    # functions and blocks

    def _isExternalAddress(self, offset):
        block = self._memory.getBlock(self._address(offset))
        return block is None or block.isExternalBlock() or not block.isInitialized()

    def getFunctions(self):
        return sorted(
            self._offset(function.getEntryPoint())
            for function in self._functions.getFunctions(True)
            if function.getEntryPoint().getAddressSpace() == self._space
        )

    def isExternalFunction(self, function_offset):
        function = self._functions.getFunctionAt(self._address(function_offset))
        if function is None or function.isExternal():
            return True
        # Ghidra places thunks for imports into the EXTERNAL block, which holds no code
        return self._isExternalAddress(function_offset)

    def _codeBlocks(self, function):
        from ghidra.program.model.block import BasicBlockModel

        model = BasicBlockModel(self.program)
        iterator = model.getCodeBlocksContaining(function.getBody(), self._task_monitor())
        while iterator.hasNext():
            yield iterator.next()

    def _blockInstructions(self, code_block):
        """Instruction addresses of a basic block; also caches bytes and out refs per instruction."""
        addresses = []
        instructions = self._listing.getInstructions(code_block, True)
        while instructions.hasNext():
            instruction = instructions.next()
            offset = self._offset(instruction.getAddress())
            addresses.append(offset)
            if offset not in self._instruction_bytes:
                self._instruction_bytes[offset] = _signed_to_bytes(instruction.getBytes())
                self._refs_from[offset] = self._instructionOutRefs(instruction)
        return addresses

    def getBlocks(self, function_offset):
        cached = self._blocks.get(function_offset)
        if cached is not None:
            return cached
        function = self._functions.getFunctionAt(self._address(function_offset))
        if function is None:
            return []
        blocks = [self._blockInstructions(code_block) for code_block in self._codeBlocks(function)]
        blocks = sorted(block for block in blocks if block)
        self._blocks[function_offset] = blocks
        return blocks

    def getInstructionBytes(self, offset):
        cached = self._instruction_bytes.get(offset)
        if cached is not None:
            return cached
        instruction = self._listing.getInstructionAt(self._address(offset))
        return _signed_to_bytes(instruction.getBytes()) if instruction is not None else b""

    # references

    def _instructionOutRefs(self, instruction):
        """Like IDA's CodeRefsFrom(flow=True): flow targets and the fall-through, plus the import
        slots an indirect call or jump reads, which the API map is keyed by."""
        targets = set()
        fall_through = instruction.getFallThrough()
        if fall_through is not None:
            targets.add(self._offset(fall_through))
        api_map = self.getApiMap()
        for reference in instruction.getReferencesFrom():
            to_address = reference.getToAddress()
            if to_address.getAddressSpace() != self._space:
                continue
            target = self._offset(to_address)
            reference_type = reference.getReferenceType()
            if reference_type.isFlow() or target in api_map:
                targets.add(target)
        return targets

    def _refsTo(self):
        if self._refs_to is None:
            # all functions must be walked once so every instruction's out refs are known
            for function_offset in self.getFunctions():
                if not self.isExternalFunction(function_offset):
                    self.getBlocks(function_offset)
            refs_to = {}
            for source, targets in self._refs_from.items():
                for target in targets:
                    refs_to.setdefault(target, set()).add(source)
            self._refs_to = refs_to
        return self._refs_to

    def getCodeInRefs(self, offset):
        return [(source, offset) for source in sorted(self._refsTo().get(offset, ()))]

    def getCodeOutRefs(self, offset):
        if offset not in self._refs_from:
            instruction = self._listing.getInstructionAt(self._address(offset))
            self._refs_from[offset] = (
                self._instructionOutRefs(instruction) if instruction is not None else set()
            )
        return [(offset, target) for target in sorted(self._refs_from[offset])]

    # symbols

    def getFunctionSymbols(self, demangle=False):
        # Ghidra's demangler analyzer already applied demangled names
        symbols = {}
        for function in self._functions.getFunctions(True):
            if function.getEntryPoint().getAddressSpace() != self._space:
                continue
            if is_default_function_name(function):
                continue
            symbols[self._offset(function.getEntryPoint())] = function_display_name(function)
        return symbols

    def getApiMap(self):
        """Address an import is reached through -> "dll!api": import slots (IAT/GOT entries),
        thunks to external functions, and the EXTERNAL block entries Ghidra creates."""
        if self._api_map is not None:
            return self._api_map
        api_map = {}
        reference_manager = self.program.getReferenceManager()
        # import slots: data at the slot carries an external reference
        iterator = reference_manager.getExternalReferences()
        while iterator.hasNext():
            reference = iterator.next()
            location = reference.getExternalLocation()
            from_address = reference.getFromAddress()
            if location is None or from_address.getAddressSpace() != self._space:
                continue
            api_map[self._offset(from_address)] = api_name(
                location.getLibraryName(), location.getLabel()
            )
        # thunks, including the EXTERNAL block entries calls through the PLT reach
        for function in self._functions.getFunctions(True):
            if not function.isThunk():
                continue
            target = function.getThunkedFunction(True)
            if target is None or not target.isExternal():
                continue
            entry = function.getEntryPoint()
            if entry.getAddressSpace() != self._space:
                continue
            location = target.getExternalLocation()
            library = location.getLibraryName() if location is not None else None
            api_map.setdefault(self._offset(entry), api_name(library, target.getName()))
        self._api_map = api_map
        return api_map

    def getFilePath(self):
        return self.program.getExecutablePath()
