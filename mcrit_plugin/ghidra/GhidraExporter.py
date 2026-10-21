"""Convert Ghidra's analysis of a Program into an SmdaReport, like smda.binja.BinjaExporter."""

from smda.Disassembler import Disassembler
from smda.export.Exporter import Exporter
from smda.SmdaConfig import SmdaConfig

from mcrit_plugin.ghidra.GhidraSmdaInterface import GhidraSmdaInterface


def exportProgram(program, config=None, monitor=None):
    """SmdaReport of *program* built from Ghidra's functions and basic blocks."""
    config = config if config is not None else SmdaConfig()
    interface = GhidraSmdaInterface(program, monitor=monitor)
    disassembler = Disassembler(config)
    disassembler.setExporter(Exporter(config, interface))
    return disassembler.disassembleBuffer(interface.getBinary(), interface.getBaseAddr())
