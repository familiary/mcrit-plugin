"""The Ghidra frontend's toolkit-free helpers: function and import naming, and the remote CFG
graph's edges. None of it needs a JVM or Ghidra."""

from mcrit_plugin.ghidra import RemoteCfgGraph
from mcrit_plugin.ghidra.naming import api_name, is_default_name


def test_default_names_are_ghidras_generated_ones():
    assert is_default_name("FUN_00101129")
    assert is_default_name("thunk_FUN_00401000")
    assert is_default_name("SUB_00401000")
    assert not is_default_name("entry")
    assert not is_default_name("FUN_00101129_renamed")
    assert not is_default_name(None)


def test_api_names_follow_smda():
    assert api_name("KERNEL32.DLL", "CreateFileA") == "kernel32.dll!CreateFileA"
    # ELF imports have no library in Ghidra
    assert api_name("<EXTERNAL>", "printf") == "printf"
    assert api_name(None, "printf") == "printf"


class _Instruction:
    def __init__(self, offset, size, mnemonic="nop", operands=""):
        self.offset = offset
        self.bytes = "90" * size
        self.mnemonic = mnemonic
        self.operands = operands


class _Block:
    def __init__(self, offset, instructions):
        self.offset = offset
        self._instructions = instructions

    def getInstructions(self):
        return iter(self._instructions)


class _Function:
    def __init__(self, blocks, blockrefs, apirefs=None):
        self._blocks = blocks
        self.blockrefs = blockrefs
        self.apirefs = apirefs or {}

    def getBlocks(self):
        return iter(self._blocks)


def test_remote_cfg_edges_classify_branches():
    entry = _Block(0x10, [_Instruction(0x10, 2, "jz", "0x20")])
    fall_through = _Block(0x12, [_Instruction(0x12, 2, "jmp", "0x20")])
    target = _Block(0x20, [_Instruction(0x20, 1, "call", "0x400")])
    function = _Function(
        [entry, fall_through, target],
        # a reference to a block outside the function is dropped
        {0x10: [0x12, 0x20], 0x12: [0x20], 0x20: [0x999]},
        apirefs={0x20: "kernel32.dll!ExitProcess"},
    )
    assert sorted(RemoteCfgGraph.edges(function)) == [
        (0x10, 0x12, RemoteCfgGraph.EDGE_FALL_THROUGH),
        (0x10, 0x20, RemoteCfgGraph.EDGE_TAKEN),
        (0x12, 0x20, RemoteCfgGraph.EDGE_UNCONDITIONAL),
    ]
    # API calls show the API name, as in the IDA and Binary Ninja graphs
    assert RemoteCfgGraph.block_label(function, target) == "20  call   [kernel32.dll!ExitProcess]"
