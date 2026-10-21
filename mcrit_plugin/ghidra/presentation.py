"""Toolkit-free logic of the Ghidra frontend: naming, the aggregations behind the tables, and the
YARA rule text. Nothing here imports JPype, Ghidra or Swing, so the unit tests run without a JVM.

The aggregations follow the Qt widgets (FunctionOverviewWidget, BlockMatchWidget, SampleInfoWidget,
YaraStringBuilderDialog) step by step.
"""

import datetime
import re

import mcrit_plugin.core.McritTableColumn as McritTableColumn

# Ghidra's auto-generated function names: FUN_00401000, thunk_FUN_00401000, and SUB_ for some loaders
DEFAULT_NAME = re.compile(r"(thunk_)?(FUN|SUB)_[0-9a-fA-F]+$")
# the library Ghidra files imports under when the binary does not name one (ELF)
UNKNOWN_LIBRARY = "<EXTERNAL>"
NO_LABEL = "-"


def is_default_name(name):
    return DEFAULT_NAME.match(name or "") is not None


def api_name(library, name):
    """SMDA's "dll!api" form: library names in lower case, none for an unknown library."""
    if library and library != UNKNOWN_LIBRARY:
        return f"{library.lower()}!{name}"
    return name


def match_sets(offset, selected):
    """The sets the overview shows for one local function's selected matches, and their number."""
    sets = {
        "offset": offset,
        "families": {match[1] for match in selected},
        "samples": {match[2] for match in selected},
        "functions": {match[3] for match in selected},
        "library_matches": {match[3] for match in selected if match[4]},
    }
    return sets, len(selected)


def label_criticality(label_list, has_function_name=False, is_resolved=False):
    """0 without labels, 1 named locally, 2 resolved by the user, 3 one label, 4 several labels,
    5 several labels sharing the top score."""
    if not label_list:
        return 0
    if has_function_name:
        return 1
    if is_resolved:
        return 2
    criticality = 3
    if len({entry[1] for entry in label_list}) > 1:
        criticality += 1
        top_score = max(entry[0] for entry in label_list)
        if len({entry[1] for entry in label_list if entry[0] == top_score}) > 1:
            criticality += 1
    return criticality


def row_cells(info, column_types):
    """(texts, sort keys) of an aggregated function, like OverviewTable.build_row."""
    texts, keys = [], []
    for column_type in column_types:
        if column_type == McritTableColumn.OFFSET:
            text, key = "0x%x" % info["offset"], info["offset"]
        elif column_type in (
            McritTableColumn.FAMILIES,
            McritTableColumn.SAMPLES,
            McritTableColumn.FUNCTIONS,
        ):
            field = {
                McritTableColumn.FAMILIES: "families",
                McritTableColumn.SAMPLES: "samples",
                McritTableColumn.FUNCTIONS: "functions",
            }[column_type]
            text, key = "%d" % len(info[field]), len(info[field])
        elif column_type == McritTableColumn.IS_LIBRARY:
            text = "YES" if info["library_matches"] else "NO"
            key = text
        else:
            text, key = NO_LABEL, NO_LABEL
        texts.append(text)
        keys.append(key)
    return texts, keys


def summarize_block_matches(pbh, blockhash_matches, family_infos, filter_library):
    """Per block offset its hash, matches and summary, plus the counts for the headline.

    Returns (block_matches_by_offset, families, samples, functions, all_functions); the sets are
    None without any block. Same aggregation as BlockMatchWidget._showBlockMatches."""
    by_offset = {}
    for entry in pbh:
        matches = blockhash_matches.get(entry["hash"]) or []
        by_offset[entry["offset"]] = {
            "picblockhash": entry,
            "matches": matches,
            "summary": {
                "families": len({e[0] for e in matches}),
                "samples": len({e[1] for e in matches}),
                "functions": len({e[2] for e in matches}),
                "offsets": len(matches),
            },
            "has_library_matches": False,
        }
    if not by_offset:
        return by_offset, None, None, None, None
    families, samples, functions, all_functions = set(), set(), set(), set()
    library_families = [
        family_id
        for family_id, family in (family_infos or {}).items()
        if family.num_samples and family.num_library_samples == family.num_samples
    ]
    to_drop = set()
    for offset, data in by_offset.items():
        all_functions.update(e[2] for e in data["matches"])
        filtered = [e for e in data["matches"] if e[0] not in library_families]
        if len(filtered) < len(data["matches"]):
            data["has_library_matches"] = True
            to_drop.add(offset)
        if filter_library and data["has_library_matches"]:
            data["matches"] = filtered
            continue
        data["summary"] = {
            "families": len({e[0] for e in filtered}),
            "samples": len({e[1] for e in filtered}),
            "functions": len({e[2] for e in filtered}),
            "offsets": len(filtered),
        }
        families.update(e[0] for e in filtered)
        samples.update(e[1] for e in filtered)
        functions.update(e[2] for e in filtered)
    if filter_library:
        for offset in to_drop:
            by_offset.pop(offset, None)
    return by_offset, families, samples, functions, all_functions


def aggregate_sample_matches(match_report, filter_library):
    """sample id -> the fields both tables show, from a MatchingResult."""
    if not match_report:
        return {}
    sample_matches = match_report.filtered_sample_matches
    if filter_library:
        sample_matches = [entry for entry in sample_matches if not entry.is_library]
    return {
        match.sample_id: {
            "family": match.family,
            "version": match.version,
            "sha256": match.sha256,
            "sample_id": match.sample_id,
            "minhash_matches": match.matched_functions_minhash,
            "pichash_matches": match.matched_functions_pichash,
            "combined_matches": match.matched_functions_combined,
            "library_matches": match.matched_functions_library,
            "bytescore": match.matched_bytes_unweighted,
            "percent": match.matched_percent_unweighted,
        }
        for match in sample_matches
    }


def escape_instruction(instruction, report):
    """The YARA-escaped hex of an instruction, wildcarding addresses inside the image."""
    from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

    return "".join(
        instruction.getEscapedBinary(
            IntelInstructionEscaper,
            escape_intraprocedural_jumps=True,
            lower_addr=report.base_addr,
            upper_addr=report.base_addr + report.binary_size,
        )
    )


def _disassembly(instruction):
    if getattr(instruction, "operands", None):
        return f"{instruction.mnemonic} {instruction.operands}"
    return instruction.mnemonic


def format_hex_lines(instructions, report, use_wildcards):
    """The string lines of a rule, each commented with its address and disassembly."""
    lines = []
    for instruction in instructions:
        hex_bytes = instruction.bytes
        if use_wildcards:
            try:
                hex_bytes = escape_instruction(instruction, report)
            except Exception:
                pass
        lines.append((hex_bytes, f"0x{instruction.offset:08X}: {_disassembly(instruction)}"))
    if not lines:
        return ""
    width = max(len(hex_bytes) for hex_bytes, _ in lines)
    return "".join(
        f"          {hex_bytes}{' ' * (width - len(hex_bytes))} // {comment}\n"
        for hex_bytes, comment in lines
    )


def build_yara_rule(sha256, scope_name, scope_offset, hex_content, date=None):
    date = date or datetime.datetime.now().strftime("%Y-%m-%d")
    rule_name = f"{sha256[:8]}_0x{scope_offset:08X}"
    return f"""rule {rule_name} {{
    meta:
      date = "{date}"
      info = "Rule fragment created from {scope_name} found at offset 0x{scope_offset:08X} in file {sha256}."
    strings:
      $_0x{scope_offset:08X} = {{
{hex_content}      }}
    condition:
      any of them
}}"""


def format_data_bytes(data):
    hex_bytes = " ".join(f"{byte:02X}" for byte in data)
    return "".join(f"          {hex_bytes[i : i + 47]}\n" for i in range(0, len(hex_bytes), 48))
