#!/usr/bin/env python3
"""Compare SMDA reports of the same binary produced by different exporters.

MCRIT matches on normalized instruction sequences, so reports exported from IDA, Binary Ninja and
SMDA's own disassembler must agree for the same binary to match itself across tools. For every
pair of reports this prints shared functions and how many of them have identical PicHashes and
control-flow graphs. With --min-agreement the exit code fails when any pair falls below the
threshold (share of shared functions with identical PicHashes).

Examples:
  compare_smda_reports.py --report ida=ida.smda --report binja=binja.smda --binary sample.exe
  compare_smda_reports.py --report ida=ida.smda --report binja=binja.smda --min-agreement 0.9
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path


def _load_report(path: Path):
    from smda.common.SmdaReport import SmdaReport

    return SmdaReport.fromDict(json.loads(path.read_text(encoding="utf-8")))


def _native_report(binary: Path):
    from smda.Disassembler import Disassembler

    return Disassembler().disassembleFile(str(binary))


def _functions(report):
    return {function.offset: function for function in report.getFunctions()}


def _cfg(function):
    return {source: sorted(targets) for source, targets in function.blockrefs.items()}


def compare(left, right):
    left_functions, right_functions = _functions(left), _functions(right)
    shared = sorted(set(left_functions) & set(right_functions))
    same_pichash = [o for o in shared if left_functions[o].pic_hash == right_functions[o].pic_hash]
    same_cfg = [o for o in shared if _cfg(left_functions[o]) == _cfg(right_functions[o])]
    differing = [o for o in shared if o not in set(same_pichash)]
    return {
        "left_functions": len(left_functions),
        "right_functions": len(right_functions),
        "shared": len(shared),
        "only_left": len(set(left_functions) - set(right_functions)),
        "only_right": len(set(right_functions) - set(left_functions)),
        "same_pichash": len(same_pichash),
        "same_cfg": len(same_cfg),
        "pichash_agreement": len(same_pichash) / len(shared) if shared else 0.0,
        "differing_offsets": [hex(offset) for offset in differing[:10]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--report",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="SMDA report JSON produced by an exporter (repeatable)",
    )
    parser.add_argument("--binary", type=Path, help="Also disassemble this file with SMDA itself")
    parser.add_argument("--min-agreement", type=float, help="Fail below this PicHash agreement")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    args = parser.parse_args()

    reports = {}
    for entry in args.report:
        name, _, path = entry.partition("=")
        if not path:
            parser.error(f"--report expects NAME=PATH, got {entry!r}")
        reports[name] = _load_report(Path(path))
    if args.binary:
        reports["smda"] = _native_report(args.binary)
    if len(reports) < 2:
        parser.error("need at least two reports (use --binary to add SMDA's own disassembly)")

    results = {}
    failed = False
    for left_name, right_name in itertools.combinations(reports, 2):
        result = compare(reports[left_name], reports[right_name])
        results[f"{left_name}-vs-{right_name}"] = result
        if args.min_agreement is not None and result["pichash_agreement"] < args.min_agreement:
            failed = True

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for pair, result in results.items():
            print(
                f"{pair}: functions {result['left_functions']}/{result['right_functions']}, "
                f"shared {result['shared']}, identical PicHash {result['same_pichash']} "
                f"({result['pichash_agreement']:.1%}), identical CFG {result['same_cfg']}, "
                f"only left {result['only_left']}, only right {result['only_right']}"
            )
            if result["differing_offsets"]:
                print(f"  first differing functions: {', '.join(result['differing_offsets'])}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
