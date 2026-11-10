"""Run the live MCRIT integration contract through Binary Ninja's actual backend.

Requires a Commercial or Ultimate license with headless support. BN_LICENSE may supply
the license in memory; the user's normal profile is never used.
"""

import argparse
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mcrit-server", default="http://127.0.0.1:8000/")
    parser.add_argument("--reference-sha256")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument(
        "--license", type=Path, help="Read a license without using the normal profile"
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcrit-binja-headless-") as user_dir:
        if args.license:
            os.environ["BN_LICENSE"] = args.license.read_text(encoding="utf-8")
        os.environ["BN_USER_DIRECTORY"] = user_dir
        os.environ["BN_DISABLE_USER_PLUGINS"] = "1"
        os.environ["BN_DISABLE_REPOSITORY_PLUGINS"] = "1"
        import binaryninja

        from mcrit_plugin.binja.BinjaBackend import BinjaBackend
        from scripts.common.run_headless_integration import run

        with binaryninja.load(str(args.input.resolve())) as view:
            if view is None:
                raise RuntimeError("Binary Ninja failed to analyze the fixture")
            run(
                args.input.resolve(),
                args.mcrit_server,
                args.reference_sha256,
                args.timeout,
                backend=BinjaBackend(view),
            )
    print("MCRIT_BN_HEADLESS_INTEGRATION_OK")


if __name__ == "__main__":
    main()
