"""SmdaInterfaceSnapshot answers smda's Exporter exactly as the interface it was taken from."""

from collections import Counter

from mcrit_plugin.ida.SmdaInterfaceSnapshot import SmdaInterfaceSnapshot


class _Interface:
    """Two functions sharing the block at 0x30, an external function, and counted calls."""

    def __init__(self):
        self.calls = Counter()
        self.blocks = {0x10: [[0x10, 0x12], [0x30]], 0x20: [[0x20], [0x30]]}

    def __getattribute__(self, name):
        if name.startswith("get") or name.startswith("is"):
            object.__getattribute__(self, "calls")[name] += 1
        return object.__getattribute__(self, name)

    def getArchitecture(self):
        return "intel"

    def getBitness(self):
        return 64

    def getBaseAddr(self):
        return 0x1000

    def getBinary(self):
        return b"\\x90" * 16

    def getFunctions(self):
        return [0x10, 0x20, 0x90]

    def isExternalFunction(self, offset):
        return offset == 0x90

    def getBlocks(self, offset):
        return self.blocks[offset]

    def getInstructionBytes(self, offset):
        return bytes([offset])

    def getCodeInRefs(self, offset):
        return [(offset - 1, offset)]

    def getCodeOutRefs(self, offset):
        return [(offset, offset + 1)]

    def getFunctionSymbols(self, demangle=False):
        return {0x10: "main"}

    def getApiMap(self):
        return {0x2000: "kernel32.dll!ExitProcess"}


def test_the_snapshot_answers_like_the_interface():
    interface = _Interface()
    snapshot = SmdaInterfaceSnapshot(interface)

    for name in ("getArchitecture", "getBitness", "getBaseAddr", "getBinary", "getFunctions"):
        assert getattr(snapshot, name)() == getattr(interface, name)()
    assert snapshot.getFunctionSymbols() == interface.getFunctionSymbols()
    assert snapshot.getApiMap() == interface.getApiMap()
    for function in (0x10, 0x20, 0x90):
        assert snapshot.isExternalFunction(function) == interface.isExternalFunction(function)
    for function in (0x10, 0x20):
        assert snapshot.getBlocks(function) == interface.getBlocks(function)
        for block in interface.getBlocks(function):
            for offset in block:
                assert snapshot.getInstructionBytes(offset) == interface.getInstructionBytes(offset)
                assert snapshot.getCodeInRefs(offset) == interface.getCodeInRefs(offset)
                assert snapshot.getCodeOutRefs(offset) == interface.getCodeOutRefs(offset)


def test_shared_code_is_read_once_and_external_functions_not_at_all():
    interface = _Interface()

    SmdaInterfaceSnapshot(interface)

    assert interface.calls["getBlocks"] == 2, "the external function's blocks are not read"
    assert interface.calls["getInstructionBytes"] == 4, "0x30 belongs to both functions"
    assert interface.calls["getCodeInRefs"] == interface.calls["getCodeOutRefs"] == 4
