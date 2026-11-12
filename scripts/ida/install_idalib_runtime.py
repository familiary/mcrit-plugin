"""Install the IDALib bindings shipped with IDA, including older source distributions."""

import argparse
import subprocess
import sys
from pathlib import Path


def find_bindings(ida_dir: Path) -> Path:
    for root in (ida_dir, ida_dir / "Contents" / "MacOS"):
        package = root / "idalib" / "python"
        wheels = sorted(package.glob("idapro-*.whl"))
        if len(wheels) == 1:
            return wheels[0]
        if len(wheels) > 1:
            raise ValueError(f"Multiple IDALib wheels in {package}; refusing an ambiguous install")
        if (package / "setup.py").is_file() or (package / "pyproject.toml").is_file():
            return package
    raise FileNotFoundError(f"No bundled IDALib Python package below {ida_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", required=True, type=Path)
    args = parser.parse_args()
    package = find_bindings(args.ida_dir.resolve())
    subprocess.run([sys.executable, "-m", "pip", "install", str(package)], check=True)


if __name__ == "__main__":
    main()
