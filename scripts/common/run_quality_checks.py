import argparse
import subprocess
import sys
from pathlib import Path


def run(command: list[str], cwd: Path) -> int:
    print(f"[RUN] {' '.join(repr(part) for part in command)}")
    result = subprocess.run(command, cwd=cwd, check=False)
    print(f"[INFO] Exit code: {result.returncode}")
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="Path to the repository root")
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable to use when invoking Ruff",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    commands = [
        [args.python, "-m", "ruff", "format", "--check"],
        [args.python, "-m", "ruff", "check"],
    ]

    for command in commands:
        if run(command, repo) != 0:
            print("[FAIL] Quality checks failed.")
            return 1

    print("[PASS] Quality checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
