"""The Ghidra frontend's toolkit-free logic: naming, table aggregations, YARA text and the remote
CFG graph's edges. None of it needs a JVM, Ghidra or SMDA."""

from types import SimpleNamespace

import mcrit_plugin.core.McritTableColumn as McritTableColumn
from mcrit_plugin.ghidra import RemoteCfgGraph
from mcrit_plugin.ghidra.presentation import (
    aggregate_sample_matches,
    api_name,
    build_yara_rule,
    format_data_bytes,
    format_hex_lines,
    is_default_name,
    label_criticality,
    match_sets,
    row_cells,
    summarize_block_matches,
)


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


def test_label_criticality_levels():
    assert label_criticality([]) == 0
    assert label_criticality([(90, "a")], has_function_name=True) == 1
    assert label_criticality([(90, "a")], is_resolved=True) == 2
    assert label_criticality([(90, "a"), (80, "a")]) == 3
    assert label_criticality([(90, "a"), (80, "b")]) == 4
    # different labels share the top score
    assert label_criticality([(90, "a"), (90, "b")]) == 5


def test_match_sets_and_row_cells():
    # (score, family id, sample id, function id, is library)
    selected = [(90, 1, 10, 100, False), (80, 1, 11, 101, True), (70, 2, 12, 101, False)]
    sets, count = match_sets(0x1000, selected)
    assert count == 3
    assert sets["families"] == {1, 2}
    assert sets["functions"] == {100, 101}
    assert sets["library_matches"] == {101}
    columns = [
        McritTableColumn.OFFSET,
        McritTableColumn.FAMILIES,
        McritTableColumn.SAMPLES,
        McritTableColumn.FUNCTIONS,
        McritTableColumn.IS_LIBRARY,
        McritTableColumn.SCORE_AND_LABEL,
    ]
    texts, keys = row_cells(dict(sets), columns)
    assert texts == ["0x1000", "2", "3", "2", "YES", "-"]
    # hex offsets sort as numbers
    assert keys[0] == 0x1000


def _family(num_samples, num_library_samples):
    return SimpleNamespace(num_samples=num_samples, num_library_samples=num_library_samples)


def test_block_summary_counts_and_library_filter():
    pbh = [{"offset": 0x10, "hash": 1, "size": 5}, {"offset": 0x20, "hash": 2, "size": 6}]
    # (family id, sample id, function id, offset); family 9 holds only library samples
    matches = {1: [(1, 10, 100, 0x10), (2, 20, 200, 0x10)], 2: [(9, 90, 900, 0x20)]}
    families = {1: _family(1, 0), 2: _family(1, 0), 9: _family(2, 2)}

    by_offset, fams, samples, functions, all_functions = summarize_block_matches(
        pbh, matches, families, filter_library=False
    )
    assert set(by_offset) == {0x10, 0x20}
    assert by_offset[0x20]["has_library_matches"]
    assert by_offset[0x10]["summary"]["families"] == 2
    assert fams == {1, 2} and all_functions == {100, 200, 900}

    by_offset, fams, _, functions, all_functions = summarize_block_matches(
        pbh, matches, families, filter_library=True
    )
    # a block with library matches drops out of the summary when filtering
    assert set(by_offset) == {0x10}
    assert functions == {100, 200} and len(all_functions - functions) == 1


def test_block_summary_without_blocks():
    assert summarize_block_matches([], {}, {}, False) == ({}, None, None, None, None)


def _sample_match(sample_id, family, is_library=False, score=1):
    return SimpleNamespace(
        sample_id=sample_id,
        family=family,
        version="v",
        sha256="ab" * 32,
        is_library=is_library,
        matched_functions_minhash=1,
        matched_functions_pichash=2,
        matched_functions_combined=3,
        matched_functions_library=0,
        matched_bytes_unweighted=score,
        matched_percent_unweighted=50.0,
    )


def test_sample_aggregation_filters_libraries():
    report = SimpleNamespace(
        filtered_sample_matches=[_sample_match(1, "a"), _sample_match(2, "lib", is_library=True)]
    )
    assert set(aggregate_sample_matches(report, filter_library=False)) == {1, 2}
    assert set(aggregate_sample_matches(report, filter_library=True)) == {1}
    assert aggregate_sample_matches(None, False) == {}


def test_yara_rule_from_raw_instruction_bytes():
    instructions = [
        SimpleNamespace(offset=0x1000, bytes="55", mnemonic="push", operands="rbp"),
        SimpleNamespace(offset=0x1001, bytes="4889e5", mnemonic="mov", operands="rbp, rsp"),
    ]
    lines = format_hex_lines(instructions, report=None, use_wildcards=False)
    assert lines.splitlines() == [
        "          55     // 0x00001000: push rbp",
        "          4889e5 // 0x00001001: mov rbp, rsp",
    ]
    rule = build_yara_rule("cafebabe" * 8, "block", 0x1000, lines, date="2026-01-01")
    assert rule.startswith("rule cafebabe_0x00001000 {")
    assert 'date = "2026-01-01"' in rule
    assert "$_0x00001000 = {" in rule
    assert rule.rstrip().endswith("}")


def test_data_bytes_wrap_at_sixteen():
    text = format_data_bytes(bytes(range(20)))
    lines = text.splitlines()
    assert len(lines) == 2
    assert lines[0].strip().split() == ["%02X" % b for b in range(16)]


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
