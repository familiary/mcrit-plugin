#!/usr/bin/env python3
"""Build the small deterministic binary used by the IDA/MCRIT integration tests."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _find_compiler() -> tuple[str, bool]:
    configured = os.environ.get("CC")
    candidates = [configured] if configured else []
    if os.name == "nt":
        candidates.extend(["cl.exe", "clang.exe", "gcc.exe"])
    else:
        candidates.extend(["cc", "clang", "gcc"])

    for candidate in candidates:
        if candidate and shutil.which(candidate):
            return candidate, Path(candidate).stem.lower() in {"cl", "cl.exe"}
    raise RuntimeError("No C compiler found; set CC or install cc/clang/gcc/cl.")


def _build(source: Path, output: Path, variant: int, architecture: str | None) -> None:
    compiler, is_msvc = _find_compiler()
    output.parent.mkdir(parents=True, exist_ok=True)

    if is_msvc:
        command = [
            compiler,
            "/nologo",
            "/O0",
            "/GS-",
            f"/DMCRIT_VARIANT={variant}",
            f"/Fe:{output}",
            str(source),
        ]
    else:
        command = [
            compiler,
            "-O0",
            "-fno-inline",
            "-fno-omit-frame-pointer",
            "-s",
            f"-DMCRIT_VARIANT={variant}",
            "-o",
            str(output),
            str(source),
        ]
        if architecture:
            command[1:1] = ["-arch", architecture]

    print("[fixture]", " ".join(command))
    subprocess.run(command, check=True)
    if not output.exists():
        raise RuntimeError(f"Compiler did not create expected output: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variant", type=int, choices=(0, 1, 2), required=True)
    parser.add_argument(
        "--arch",
        default="x86_64" if sys.platform == "darwin" else None,
        help="Compiler architecture; macOS defaults to x86_64 because SMDA's IDA exporter is x86-based.",
    )
    args = parser.parse_args()

    output = args.output
    if os.name == "nt" and output.suffix.lower() != ".exe":
        output = output.with_suffix(".exe")
    _build(args.source.resolve(), output.resolve(), args.variant, args.arch)
    print(output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
