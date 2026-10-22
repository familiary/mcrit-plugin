"""The toolkit-free logic behind the match views, shared by the Qt widgets and the Ghidra panels:
table aggregations and YARA text. None of it needs Qt, a JVM or a disassembler."""

from types import SimpleNamespace

import mcrit_plugin.core.McritTableColumn as McritTableColumn
from mcrit_plugin.core.presentation import (
    aggregate_sample_matches,
    build_yara_rule,
    format_data_bytes,
    format_hex_lines,
    label_criticality,
    match_sets,
    row_cells,
    summarize_block_matches,
)


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
        filename="sample.bin",
        is_library=is_library,
        matched_functions_minhash=1,
        matched_functions_pichash=2,
        matched_functions_combined=3,
        matched_functions_library=0,
        matched_bytes_unweighted=score,
        matched_bytes_score_weighted=score,
        matched_percent_unweighted=50.0,
        matched_percent_score_weighted=40.0,
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
